"""Access-control / IDOR testing — the natural next step after auto-login.

Three checks, all comparison-based (a finding is a *difference* that shouldn't
exist), so they stay read-only:

1. auth-vs-unauth  — a logged-in resource still served to a cookie-less session
2. numeric neighbour — object-id +/-1 returns a different valid object (IDOR)
3. cross-user (--cookie2) — user B's session reads user A's object

All heuristic by nature, so findings are LIKELY/POSSIBLE with the evidence
spelled out for you to confirm.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse

from ..core.model import Confidence, Finding, Severity
from .crawler import CrawlResult, InjectionPoint
from .session import Session

_OBJ_PARAM = re.compile(
    r"^(id|.*_id|uid|userid|user|account|acct|order|orderno|invoice|doc|docid|"
    r"file|fileid|fileno|num|no|pid|item|itemid|record|ref|profile|member|"
    r"customer|cid|oid|gid|key)$", re.I)
_SENSITIVE_PATH = re.compile(
    r"/(account|admin|profile|user|users|order|orders|invoice|settings|"
    r"dashboard|api|me|billing|payment|document|report)(/|$|\?)", re.I)
_LOGINISH = re.compile(r'type=["\']?password|name=["\']?password|>\s*log[\s-]?in|'
                       r'sign[\s-]?in|please (log|sign)', re.I)


def _host_port(url: str):
    p = urlparse(url)
    return (p.hostname or url), (p.port or (443 if p.scheme == "https" else 80))


def _send(session: Session, point: InjectionPoint, param: str, value: str):
    params = dict(point.params)
    params[param] = value
    if point.method == "POST":
        return session.request(
            point.url, "POST", data=urlencode(params).encode(),
            extra_headers={"Content-Type": "application/x-www-form-urlencoded"})
    return session.get(point.url + "?" + urlencode(params))


def _sig(resp) -> Tuple[int, int]:
    return (resp.status, len(resp.body) // 48)


def _denied(resp) -> bool:
    """True if the response looks like 'access denied / please log in'."""
    if resp.status in (301, 302, 303, 307, 308, 401, 403):
        return True
    if resp.status != 200:
        return True
    return bool(_LOGINISH.search(resp.body))


def _mk(url, title, sev, conf, evidence, why, nxt, tags):
    host, port = _host_port(url)
    return Finding(target=host, port=port, service="http", title=title,
                   severity=sev, confidence=conf, category="misconfig",
                   evidence=evidence, why=why, next_step=nxt, tags=tags)


def _object_points(cr: CrawlResult) -> List[Tuple[InjectionPoint, str]]:
    out = []
    for p in cr.points:
        for name, val in p.params.items():
            if _OBJ_PARAM.match(name) or (val.isdigit() and len(val) <= 9):
                out.append((p, name))
    return out


def _numeric_idor(session: Session, obj_points, budget: int = 40) -> List[Finding]:
    out: List[Finding] = []
    used = 0
    for point, param in obj_points:
        if used >= budget:
            break
        val = point.params.get(param, "")
        if not val.isdigit():
            continue
        n = int(val)
        bogus = "2147480000"
        invalid = _send(session, point, param, bogus)   # unlikely-to-exist id
        orig = _send(session, point, param, val)
        used += 2
        # Reflection guard: if the id echoes back, this is a reflective param
        # (search/echo), not an object reference — leave it to the XSS probe.
        if bogus in invalid.body:
            continue
        not_found = _sig(invalid)
        # The param must actually select an object: a valid id must differ from
        # the not-found response.
        if orig.status != 200 or _sig(orig) == not_found:
            continue
        neighbours = [str(n - 1), str(n + 1)] if n >= 1 else [str(n + 1), str(n + 2)]
        for nb in neighbours:
            if used >= budget:
                break
            r = _send(session, point, param, nb)
            used += 1
            if r.status == 200 and len(r.body) > 32 and _sig(r) != not_found:
                out.append(_mk(
                    point.url, f"Possible IDOR on '{param}' (object enumeration)",
                    Severity.MEDIUM, Confidence.LIKELY,
                    f"{param}={val} and {param}={nb} both return valid objects "
                    f"(HTTP 200, {len(orig.body)}/{len(r.body)}B); "
                    f"{param}={bogus} -> HTTP {invalid.status}/{len(invalid.body)}B",
                    "Adjacent object IDs return distinct valid records while a "
                    "bogus id does not — you can enumerate other users' objects "
                    "with no authorization gate.",
                    f"for i in $(seq 1 50); do curl -s '{point.url}?{param}='$i "
                    f"-o /dev/null -w '%{{http_code}} %{{size_download}} id='$i'\\n'; done",
                    ["idor", "bac"]))
                break
    return out


def _auth_vs_unauth(session: Session, cr: CrawlResult, root: str,
                    budget: int = 25) -> List[Finding]:
    out: List[Finding] = []
    unauth = Session(timeout=session.timeout)   # clean: no jar, no auth headers
    seen = set()
    candidates: List[str] = []
    for p in cr.points:
        url = p.url + ("?" + urlencode(p.params) if p.method == "GET" and p.params else "")
        obj = any(_OBJ_PARAM.match(k) for k in p.params)
        if (obj or _SENSITIVE_PATH.search(url)) and url not in seen:
            seen.add(url)
            candidates.append(url)
    for url in list(cr.urls):
        if _SENSITIVE_PATH.search(url) and url not in seen:
            seen.add(url)
            candidates.append(url)

    for url in candidates[:budget]:
        r_auth = session.get(url)
        if r_auth.status != 200:
            continue
        r_un = unauth.get(url)
        if _denied(r_un):
            continue  # properly protected — good
        # unauth got a real 200 that isn't a login page: access control gap.
        if r_un.status == 200 and len(r_un.body) > 48:
            out.append(_mk(
                url, "Resource served without authentication",
                Severity.HIGH, Confidence.LIKELY,
                f"authed HTTP 200 ({len(r_auth.body)}B) and unauthenticated "
                f"HTTP 200 ({len(r_un.body)}B) — no redirect to login",
                "A resource reached while logged in is also served to a session "
                "with no cookies — missing authentication / broken access control.",
                f"curl -s '{url}'   # no cookies", ["bac"]))
    return out


def _cross_user_idor(cr: CrawlResult, sess1: Session, cookie2: str,
                     budget: int = 20) -> List[Finding]:
    out: List[Finding] = []
    sess2 = Session.build(cookie=cookie2, timeout=sess1.timeout)
    used = 0
    for p, param in _object_points(cr):
        if used >= budget:
            break
        val = p.params.get(param, "")
        r1 = _send(sess1, p, param, val)
        r2 = _send(sess2, p, param, val)
        used += 2
        if r1.status == 200 and r2.status == 200 and _sig(r1) == _sig(r2) \
                and len(r1.body) > 48:
            url = p.url + "?" + urlencode({**p.params, param: val})
            out.append(_mk(
                url, f"Possible cross-user IDOR on '{param}'",
                Severity.HIGH, Confidence.POSSIBLE,
                f"user1 and user2 sessions both get identical content "
                f"({len(r1.body)}B) for {param}={val}",
                "A second user's session sees the same object as the first — "
                "horizontal privilege escalation (or the resource is shared).",
                f"# compare manually: curl with cookie A vs cookie B on {url}",
                ["idor", "bac"]))
    return out


def run(session: Session, cr: CrawlResult, root: str, opts, authenticated: bool,
        log=None) -> List[Finding]:
    findings: List[Finding] = []
    obj_points = _object_points(cr)
    try:
        findings.extend(_numeric_idor(session, obj_points))
    except Exception:
        pass
    if authenticated:
        try:
            findings.extend(_auth_vs_unauth(session, cr, root))
        except Exception:
            pass
    cookie2 = getattr(opts, "cookie2", None)
    if cookie2:
        try:
            findings.extend(_cross_user_idor(cr, session, cookie2))
        except Exception:
            pass
    if log and findings:
        log(f"    access-control: {len(findings)} finding(s)")
    return findings
