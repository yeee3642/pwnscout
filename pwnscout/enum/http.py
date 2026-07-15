"""Deep HTTP enumeration: fingerprint the app, then probe sensitive paths
against a soft-404 baseline so we don't drown you in false positives.
"""

from __future__ import annotations

import os
import re
from typing import List, Optional

from ..core.model import Confidence, Finding, Service, Severity
from ..core.utils import HttpResponse, base_urls, http_request
from ..kb import loader


def _tls(service: Service) -> bool:
    return service.tunnel == "ssl" or service.name == "https" or service.port in (443, 8443, 9443)


def _ctx(host: str, port: int, tls: bool):
    from . import context, render
    return context(host, port, tls), render


def enum(host: str, service: Service, opts) -> List[Finding]:
    out: List[Finding] = []
    tls = _tls(service)
    base = base_urls(host, service.port, tls)
    ctx, render = _ctx(host, service.port, tls)

    root = http_request(base + "/", timeout=getattr(opts, "http_timeout", 8.0))
    if root.status == 0 and not tls:
        # Maybe it's actually TLS on a non-standard port.
        tls = True
        base = base_urls(host, service.port, tls)
        ctx, render = _ctx(host, service.port, tls)
        root = http_request(base + "/", timeout=getattr(opts, "http_timeout", 8.0))
    if root.status == 0:
        return out

    out.extend(_fingerprint(host, service, base, root, render, ctx))
    out.extend(_root_observations(host, service, base, root, render, ctx))
    out.extend(_probe_paths(host, service, base, render, opts))
    return out


def _fingerprint(host, service, base, root: HttpResponse, render, ctx) -> List[Finding]:
    out: List[Finding] = []
    header_blob = "\n".join(f"{k}: {v}" for k, v in root.headers.items())
    hay = header_blob + "\n" + root.body
    for fp in loader.fingerprints():
        m = fp.get("match", {})
        ok = True
        for hdr, pat in (m.get("header_regex") or {}).items():
            val = root.header(hdr)
            if not (val and re.search(pat, val, re.I)):
                ok = False
                break
        if ok and m.get("body_regex"):
            if not re.search(m["body_regex"], hay, re.I):
                ok = False
        if not ok:
            continue
        version = ""
        if fp.get("version_regex"):
            vm = re.search(fp["version_regex"], hay, re.I)
            if vm:
                version = next((g for g in vm.groups() if g), "") if vm.groups() else ""
        title = fp["name"] + (f" {version}" if version else "")
        out.append(Finding(
            target=host, port=service.port, service="http",
            title=f"{title} detected",
            severity=Severity.parse(fp.get("severity", "low")),
            confidence=Confidence.LIKELY,
            category="known-cve" if "CVE" in (fp.get("note", "")) else "recon",
            evidence=(root.header("server") or fp["name"])[:120],
            why=fp.get("note", ""),
            next_step=render(fp.get("next_step", ""), ctx),
            tags=fp.get("tags", []),
        ))
    return out


def _root_observations(host, service, base, root: HttpResponse, render, ctx) -> List[Finding]:
    out: List[Finding] = []

    # Directory listing.
    if re.search(r"<title>Index of /|Directory listing for /", root.body, re.I):
        out.append(Finding(
            target=host, port=service.port, service="http",
            title="Directory listing enabled",
            severity=Severity.MEDIUM, confidence=Confidence.CONFIRMED, verified=True,
            category="misconfig", evidence="autoindex on /",
            why="The web root lists its files — browse for source, backups and secrets.",
            next_step=render("curl -s {base}/", ctx), tags=["exposure"],
        ))

    # HTTP Basic auth realm -> default-cred opportunity.
    auth = root.header("www-authenticate")
    if root.status == 401 and auth:
        out.append(Finding(
            target=host, port=service.port, service="http",
            title="HTTP Basic/Digest auth prompt",
            severity=Severity.LOW, confidence=Confidence.LIKELY,
            category="default-creds",
            evidence=auth[:120],
            why="Protected area — try default and weak credentials (run with --brute).",
            next_step=render("hydra -C defaults.txt {host} http-get /", ctx),
            tags=["default-creds"],
        ))

    # Verbose framework error / debug page.
    if re.search(r"Whitelabel Error Page|Traceback \(most recent call last\)|"
                 r"Werkzeug Debugger|DEBUG = True|Exception at", root.body):
        out.append(Finding(
            target=host, port=service.port, service="http",
            title="Debug / verbose error page exposed",
            severity=Severity.MEDIUM, confidence=Confidence.LIKELY,
            category="misconfig", evidence="stack trace / debug marker in body",
            why="Debug mode leaks paths, versions and sometimes an interactive "
                "console (Werkzeug/Ignition) that leads to RCE.",
            next_step=render("curl -s {base}/ | head -40", ctx), tags=["debug"],
        ))

    # git/svn folder mention in body or obvious server-status link — cheap hint.
    return out


def _probe_paths(host, service, base, render, opts) -> List[Finding]:
    out: List[Finding] = []
    timeout = getattr(opts, "http_timeout", 8.0)

    # Soft-404 baseline: request an unlikely path and remember what "not found"
    # looks like on this server (some return 200 for everything).
    token = os.urandom(6).hex()
    baseline = http_request(f"{base}/pwnscout_{token}_notfound", timeout=timeout)

    for entry in loader.http_paths():
        path = entry["path"]
        r = http_request(base + path, timeout=timeout)
        if not _path_hit(r, entry, baseline):
            continue
        ctx, _ = _ctx(host, service.port, base.startswith("https"))
        sev = Severity.parse(entry.get("severity", "medium"))
        # A matched positive body signal is essentially confirmed exposure.
        m = entry.get("match", {})
        strong = bool(m.get("body_contains") or m.get("body_regex"))
        conf = Confidence.CONFIRMED if strong else Confidence.LIKELY
        out.append(Finding(
            target=host, port=service.port, service="http",
            title=entry.get("title", path),
            severity=sev, confidence=conf, verified=strong,
            category=entry.get("category", "exposure"),
            evidence=f"{path} -> HTTP {r.status} ({len(r.body)}B)",
            why=entry.get("why", ""),
            next_step=render(entry.get("next_step", ""), ctx),
            tags=entry.get("tags", []),
        ))
    return out


def _path_hit(r: HttpResponse, entry: dict, baseline: Optional[HttpResponse]) -> bool:
    if r.status == 0:
        return False
    m = entry.get("match", {})
    if r.status not in m.get("status", [200]):
        return False

    ct = r.header("content-type").lower()
    ct_needles = m.get("content_type_contains")
    if ct_needles and not any(n in ct for n in ct_needles):
        return False

    body = r.body
    bc = m.get("body_contains")
    if bc and not any(s.lower() in body.lower() for s in bc):
        return False
    br = m.get("body_regex")
    if br and not re.search(br, body):
        return False

    # No positive body signal required: guard against soft-404s that echo the
    # same status and near-identical length for any path.
    if not bc and not br and baseline is not None and baseline.status == r.status:
        if abs(len(baseline.body) - len(body)) < 64:
            return False
    return True
