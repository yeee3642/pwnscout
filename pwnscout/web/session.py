"""A thin HTTP session over the stdlib helper — carries auth (cookie / header /
basic) and an optional politeness delay so authenticated red-team scans work.
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlparse

from ..core.utils import HttpResponse, http_request


@dataclass
class Session:
    headers: Dict[str, str] = field(default_factory=dict)
    timeout: float = 8.0
    delay: float = 0.0            # seconds between requests (rate limiting)
    max_body: int = 300_000

    @classmethod
    def build(cls, cookie: Optional[str] = None,
              header_list: Optional[List[str]] = None,
              basic: Optional[str] = None, timeout: float = 8.0,
              delay: float = 0.0) -> "Session":
        headers: Dict[str, str] = {}
        if cookie:
            headers["Cookie"] = cookie
        for raw in header_list or []:
            if ":" in raw:
                k, v = raw.split(":", 1)
                headers[k.strip()] = v.strip()
        if basic:
            headers["Authorization"] = "Basic " + base64.b64encode(
                basic.encode()).decode()
        return cls(headers=headers, timeout=timeout, delay=delay)

    def request(self, url: str, method: str = "GET",
                data: Optional[bytes] = None,
                extra_headers: Optional[Dict[str, str]] = None) -> HttpResponse:
        if self.delay:
            time.sleep(self.delay)
        hdrs = dict(self.headers)
        if extra_headers:
            hdrs.update(extra_headers)
        return http_request(url, method=method, headers=hdrs, data=data,
                            timeout=self.timeout, max_body=self.max_body)

    def get(self, url: str, **kw) -> HttpResponse:
        return self.request(url, "GET", **kw)


def same_scope(url: str, root: str) -> bool:
    """True when *url* is on the same host:port as *root* (default scope)."""
    a, b = urlparse(url), urlparse(root)
    return (a.hostname == b.hostname) and ((a.port or _dport(a.scheme))
                                           == (b.port or _dport(b.scheme)))


def _dport(scheme: str) -> int:
    return 443 if scheme == "https" else 80
