"""Content discovery: wordlist-based directory/file brute forcing with a
soft-404 (wildcard) baseline, threaded.
"""

from __future__ import annotations

import os
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import List, Optional, Tuple
from urllib.parse import urlparse

from ..core.model import Confidence, Finding, Severity
from ..kb import loader
from .session import Session

_SENSITIVE = re.compile(
    r"admin|login|backup|\.git|\.env|config|dump|\.sql|phpmyadmin|actuator|"
    r"swagger|console|shell|upload|\.bak|password|secret|private|debug|"
    r"credential|\.htpasswd|web\.config|id_rsa", re.I)


@dataclass
class Hit:
    path: str
    status: int
    length: int
    url: str
    location: str = ""


def _host_port(url: str) -> Tuple[str, int]:
    p = urlparse(url)
    return p.hostname or url, (p.port or (443 if p.scheme == "https" else 80))


def discover(session: Session, root: str, words: List[str],
             extensions: Optional[List[str]] = None, threads: int = 30,
             max_words: int = 2000) -> Tuple[List[Finding], List[str]]:
    base = root.rstrip("/")
    host, port = _host_port(root)

    # Wildcard/soft-404 baseline.
    b1 = session.get(f"{base}/pwnscout_nope_{os.urandom(5).hex()}")
    baseline_status, baseline_len = b1.status, len(b1.body)

    candidates: List[str] = []
    exts = [e if e.startswith(".") else "." + e for e in (extensions or [])]
    for w in words[:max_words]:
        candidates.append(w)
        if exts and "." not in w.split("/")[-1]:
            for e in exts:
                candidates.append(w + e)

    def _probe(word: str) -> Optional[Hit]:
        url = f"{base}/{word}"
        r = session.get(url)
        if r.status == 0 or r.status == 404:
            return None
        # wildcard guard: same status + near-identical length as the baseline
        if r.status == baseline_status and abs(len(r.body) - baseline_len) < 48:
            return None
        return Hit(word, r.status, len(r.body), url, r.header("location"))

    hits: List[Hit] = []
    with ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
        for res in pool.map(_probe, candidates):
            if res:
                hits.append(res)

    findings: List[Finding] = []
    discovered_urls: List[str] = []
    for h in sorted(hits, key=lambda x: (x.status, x.path)):
        discovered_urls.append(h.url)
        sensitive = bool(_SENSITIVE.search(h.path))
        forbidden = h.status in (401, 403)
        if sensitive or forbidden:
            sev = Severity.MEDIUM if (sensitive or forbidden) else Severity.LOW
            if sensitive and h.status == 200:
                sev = Severity.HIGH
            note = ("exists but forbidden — worth an auth-bypass/verb-tamper attempt"
                    if forbidden else "sensitive path is reachable")
            findings.append(Finding(
                target=host, port=port, service="http",
                title=f"Content discovered: /{h.path}",
                severity=sev, confidence=Confidence.CONFIRMED, verified=True,
                category="exposure",
                evidence=f"/{h.path} -> HTTP {h.status} ({h.length}B)"
                         + (f" -> {h.location}" if h.location else ""),
                why=note,
                next_step=f"curl -si {h.url}",
                tags=["content-discovery"],
            ))

    # One rolled-up finding so the report isn't buried in low-value hits.
    if hits:
        sample = ", ".join(f"/{h.path}({h.status})" for h in hits[:15])
        findings.append(Finding(
            target=host, port=port, service="http",
            title=f"{len(hits)} paths found via content discovery",
            severity=Severity.INFO, confidence=Confidence.CONFIRMED, verified=True,
            category="recon",
            evidence=sample + (" …" if len(hits) > 15 else ""),
            why="Enumerated endpoints to feed manual testing and the probe stage.",
            next_step=f"# full list in the JSON report; re-run with a bigger --wordlist",
            tags=["content-discovery"],
        ))
    return findings, discovered_urls
