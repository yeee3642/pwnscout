"""Safe active web vulnerability probes.

Detection-only: we inject benign canaries and observe reflection, template
evaluation, DB error strings, file markers or redirect targets. Nothing
destructive, no data exfiltration, no time-based DoS. A hit means "go verify
and exploit this by hand" — the report gives you the repro command.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional
from urllib.parse import urlencode, urlparse

from ..core.model import Confidence, Finding, Severity
from ..kb import loader
from .crawler import InjectionPoint
from .session import Session


class _Budget:
    def __init__(self, cap: int):
        self.cap = cap
        self.used = 0

    def ok(self) -> bool:
        return self.used < self.cap

    def spend(self) -> None:
        self.used += 1


def _host_port(url: str):
    p = urlparse(url)
    return p.hostname or url, (p.port or (443 if p.scheme == "https" else 80))


def _send(session: Session, point: InjectionPoint, param: str, value: str):
    params = dict(point.params)
    params[param] = value
    if point.method == "POST":
        return session.request(
            point.url, "POST", data=urlencode(params).encode(),
            extra_headers={"Content-Type": "application/x-www-form-urlencoded"})
    return session.get(point.url + "?" + urlencode(params))


def _curl(point: InjectionPoint, param: str, value: str) -> str:
    params = dict(point.params)
    params[param] = value
    if point.method == "POST":
        return f"curl -s -X POST '{point.url}' -d '{urlencode(params)}'"
    return f"curl -s '{point.url}?{urlencode(params)}'"


def _mk(url, param, title, sev, conf, cat, evidence, why, next_step, tags,
        verified=False, exploit=None):
    host, port = _host_port(url)
    return Finding(
        target=host, port=port, service="http", title=title, severity=sev,
        confidence=conf, verified=verified, category=cat,
        evidence=evidence, why=why, next_step=next_step, tags=tags,
        exploit=exploit,
    )


def probe_points(session: Session, points: List[InjectionPoint], opts,
                 log: Optional[Callable[[str], None]] = None) -> List[Finding]:
    pl = loader.payloads()
    out: List[Finding] = []
    budget = _Budget(getattr(opts, "probe_budget", 1500))
    max_points = getattr(opts, "max_points", 40)
    interesting = set(pl.get("interesting_params", []))
    redir_params = set(pl.get("open_redirect", {}).get("params", []))
    truncated = False

    for point in points[:max_points]:
        # one clean baseline per point for SQLi-error diffing
        first_param = next(iter(point.params), None)
        if not first_param:
            continue
        base = _send(session, point, first_param, "pwnbase1")
        budget.spend()
        base_errors = _sql_errors(base.body, pl)

        for param in list(point.params)[:12]:
            if not budget.ok():
                truncated = True
                break
            out.extend(_xss(session, point, param, pl, budget))
            out.extend(_ssti(session, point, param, pl, budget))
            out.extend(_sqli(session, point, param, pl, budget, base_errors))
            if param.lower() in interesting or point.source == "form":
                out.extend(_traversal(session, point, param, pl, budget))
            if param.lower() in redir_params:
                out.extend(_open_redirect(session, point, param, pl, budget))
        if truncated:
            break

    if truncated and log:
        log(f"[!] probe budget ({budget.cap} reqs) reached — not all params "
            f"tested. Raise with --probe-budget or narrow the target.")
    return out


def _xss(session, point, param, pl, budget) -> List[Finding]:
    cfg = pl.get("xss", {})
    payload = (cfg.get("payloads") or [""])[0]
    marker = cfg.get("reflect_raw", ["pwnx9k1z\"'><"])[0]
    if not budget.ok():
        return []
    budget.spend()
    r = _send(session, point, param, payload)
    if marker and marker in r.body:
        return [_mk(point.url, param, f"Reflected XSS candidate (param '{param}')",
                    Severity.HIGH, Confidence.LIKELY, "injection",
                    f"payload reflected unescaped: {marker}",
                    "Special characters come back unencoded — craft a working "
                    "payload for the reflection context (attribute/JS/HTML).",
                    _curl(point, param, payload), ["xss"])]
    return []


def _ssti(session, point, param, pl, budget) -> List[Finding]:
    for probe in pl.get("ssti", []):
        if not budget.ok():
            break
        budget.spend()
        r = _send(session, point, param, probe["payload"])
        if probe["expect"] in r.body:
            return [_mk(point.url, param,
                        f"Server-Side Template Injection (param '{param}')",
                        Severity.CRITICAL, Confidence.CONFIRMED, "injection",
                        f"{probe['payload']} evaluated to {probe['expect']}",
                        f"Template expression was evaluated ({probe['engine']}) — "
                        "this is typically RCE.",
                        _curl(point, param, probe["payload"]),
                        ["ssti", "rce"], verified=True,
                        exploit={"kind": "ssti", "method": point.method,
                                 "url": point.url, "param": param,
                                 "engine": probe["engine"]})]
    return []


def _sql_errors(body: str, pl) -> List[str]:
    found = []
    for sig in pl.get("sqli_errors", []):
        if re.search(sig["regex"], body, re.I):
            found.append(sig["db"])
    return found


def _sqli(session, point, param, pl, budget, base_errors) -> List[Finding]:
    for pair in pl.get("sqli_probe_pairs", [{"break": "'"}]):
        if not budget.ok():
            break
        budget.spend()
        r = _send(session, point, param, "pwn" + pair["break"])
        errs = [e for e in _sql_errors(r.body, pl) if e not in base_errors]
        if errs:
            return [_mk(point.url, param,
                        f"SQL injection (error-based, param '{param}')",
                        Severity.HIGH, Confidence.LIKELY, "injection",
                        f"{pair['break']!r} triggered a {errs[0]} error",
                        "A single quote produced a database error the clean "
                        "request didn't — classic error-based SQLi.",
                        _curl(point, param, "pwn" + pair["break"]),
                        ["sqli"],
                        exploit={"kind": "sqli", "method": point.method,
                                 "url": point.url, "param": param})]
    return []


def _traversal(session, point, param, pl, budget) -> List[Finding]:
    cfg = pl.get("traversal", {})
    markers = cfg.get("markers", [])
    for payload in cfg.get("payloads", []):
        if not budget.ok():
            break
        budget.spend()
        r = _send(session, point, param, payload)
        for mk in markers:
            if re.search(mk, r.body):
                return [_mk(point.url, param,
                            f"Path traversal / LFI (param '{param}')",
                            Severity.HIGH, Confidence.CONFIRMED, "injection",
                            f"{payload} returned a file marker ({mk})",
                            "The parameter reads local files — pivot to LFI->RCE "
                            "(log poisoning, php filters, /proc).",
                            _curl(point, param, payload),
                            ["lfi"], verified=True,
                            exploit={"kind": "lfi", "method": point.method,
                                     "url": point.url, "param": param})]
    return []


def _open_redirect(session, point, param, pl, budget) -> List[Finding]:
    cfg = pl.get("open_redirect", {})
    host = cfg.get("marker_host", "pwnscout-oob.example")
    for payload in cfg.get("payloads", []):
        if not budget.ok():
            break
        budget.spend()
        r = _send(session, point, param, payload)
        loc = r.header("location")
        if host in loc or re.search(rf"url=.{{0,4}}{re.escape(host)}", r.body, re.I):
            return [_mk(point.url, param, f"Open redirect (param '{param}')",
                        Severity.MEDIUM, Confidence.CONFIRMED, "misconfig",
                        f"redirects to {host} (Location: {loc[:80]})",
                        "Attacker-controlled redirect — useful for phishing and "
                        "OAuth token theft.",
                        _curl(point, param, payload),
                        ["open-redirect"], verified=True)]
    return []


def probe_root(session: Session, root: str, root_resp, extra_urls=None) -> List[Finding]:
    """Header/cookie/CORS hygiene checks that don't need injection points."""
    pl = loader.payloads()
    out: List[Finding] = []
    host, port = _host_port(root)

    # Missing security headers.
    missing = []
    for hdr, note in (pl.get("security_headers") or {}).items():
        if not root_resp.header(hdr):
            missing.append(note)
    if missing:
        out.append(_mk(root, "-", "Missing security headers",
                       Severity.LOW, Confidence.CONFIRMED, "misconfig",
                       "; ".join(missing),
                       "Hardening headers absent — supports clickjacking, MIME "
                       "sniffing and downgrade attacks in a chain.",
                       f"curl -sI {root}", ["headers"], verified=True))

    # Cookie flags.
    setc = root_resp.header("set-cookie")
    if setc:
        flags = []
        low = setc.lower()
        if "httponly" not in low:
            flags.append("HttpOnly")
        if "secure" not in low and root.startswith("https"):
            flags.append("Secure")
        if "samesite" not in low:
            flags.append("SameSite")
        if flags:
            out.append(_mk(root, "-", "Weak cookie flags",
                           Severity.LOW, Confidence.CONFIRMED, "misconfig",
                           "missing: " + ", ".join(flags),
                           "Session cookies missing protective flags — eases "
                           "theft (XSS) and CSRF.",
                           f"curl -sI {root}", ["cookies"], verified=True))

    # CORS reflection.
    evil = pl.get("cors", {}).get("origin", "https://pwnscout-evil.example")
    for url in [root] + list(extra_urls or [])[:5]:
        r = session.get(url, extra_headers={"Origin": evil})
        acao = r.header("access-control-allow-origin")
        acac = r.header("access-control-allow-credentials")
        if acao == evil or (acao == "*" and acac.lower() == "true"):
            out.append(_mk(url, "-", "CORS misconfiguration",
                           Severity.MEDIUM, Confidence.LIKELY, "misconfig",
                           f"ACAO reflects {evil}; ACAC={acac or 'n/a'}",
                           "Reflected/permissive CORS with credentials lets a "
                           "malicious origin read authenticated responses.",
                           f"curl -s {url} -H 'Origin: {evil}' -i", ["cors"]))
            break
    return out
