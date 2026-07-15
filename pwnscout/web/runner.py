"""Orchestrate a deep web assessment against one or more app URLs and return a
ScanResult that renders through the same reporter as the network scan.
"""

from __future__ import annotations

from typing import Callable, List, Optional
from urllib.parse import urlparse

from ..core.model import Host, ScanResult, Service
from ..core.utils import color, now_iso
from ..enum import http as http_enum
from ..kb import loader
from .crawler import crawl
from .discover import discover
from .probes import probe_points, probe_root
from .session import Session


def _normalize(target: str) -> str:
    if "://" not in target:
        target = "http://" + target
    p = urlparse(target)
    if not p.path:
        target = target.rstrip("/") + "/"
    return target


def _host_port_tls(url: str):
    p = urlparse(url)
    tls = p.scheme == "https"
    return (p.hostname or url), (p.port or (443 if tls else 80)), tls


def web_scan(targets: List[str], opts,
             log: Optional[Callable[[str], None]] = None) -> ScanResult:
    from ..engine import _dedup  # reuse the network scanner's dedup
    log = log or (lambda _m: None)

    session = Session.build(
        cookie=getattr(opts, "cookie", None),
        header_list=getattr(opts, "header", None),
        basic=getattr(opts, "auth_basic", None),
        timeout=getattr(opts, "timeout", 8.0),
        delay=getattr(opts, "delay", 0.0),
    )
    words = loader.wordlist(getattr(opts, "wordlist", None))
    exts = [e.strip() for e in (getattr(opts, "ext", "") or "").split(",") if e.strip()]

    result = ScanResult(started=now_iso(), args={
        "mode": "web", "targets": targets,
        "crawl": bool(getattr(opts, "crawl", True)),
        "discover": bool(getattr(opts, "discover", False)),
        "probe": bool(getattr(opts, "probe", True)),
        "authenticated": bool(session.headers.get("Cookie") or
                              session.headers.get("Authorization")),
    })

    for target in targets:
        root = _normalize(target)
        host, port, tls = _host_port_tls(root)
        log(color(f"[*] web target {root}", "cyan"))

        root_resp = session.get(root)
        if root_resp.status == 0:
            log(color(f"[!] {root} unreachable ({root_resp.error})", "red"))
            continue

        host_obj = Host(ip=host, alive=True)
        service = Service(port=port, name="https" if tls else "http",
                          tunnel="ssl" if tls else "")
        host_obj.services = [service]
        findings = []

        # fingerprint + KB sensitive-path checks (reuse the light http enum)
        try:
            findings.extend(http_enum.enum(host, service, opts))
        except Exception:
            pass

        points = []
        if getattr(opts, "crawl", True):
            cr = crawl(session, root, depth=getattr(opts, "depth", 2),
                       max_pages=getattr(opts, "max_pages", 200))
            points = cr.points
            log(color(f"    crawled {len(cr.urls)} urls · "
                      f"{len(points)} injection point(s)", "grey"))

        discovered = []
        if getattr(opts, "discover", False):
            log(color(f"    content discovery ({len(words)} words)…", "grey"))
            dfind, discovered = discover(
                session, root, words, extensions=exts,
                threads=getattr(opts, "threads", 30))
            findings.extend(dfind)
            log(color(f"    {len(discovered)} path(s) found", "grey"))

        if getattr(opts, "probe", True):
            log(color(f"    probing {len(points)} injection point(s)…", "grey"))
            findings.extend(probe_points(session, points, opts, log))
            findings.extend(probe_root(session, root, root_resp, extra_urls=discovered))

        host_obj.findings = _dedup(findings)
        result.hosts.append(host_obj)
        hot = sum(1 for f in host_obj.findings if f.score >= 50)
        log(color(f"[+] {root}: {len(host_obj.findings)} findings, {hot} high-value",
                  "green"))

    result.finished = now_iso()
    return result
