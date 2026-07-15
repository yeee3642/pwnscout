"""A tiny same-host crawler (stdlib regex, no bs4). It maps the app's attack
surface: reachable URLs, forms, and injectable parameters to feed the probes.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple
from urllib.parse import parse_qsl, urldefrag, urljoin, urlparse, urlunparse

from .session import Session, same_scope

_LINK_RE = re.compile(r"""(?:href|src|action)\s*=\s*['"]?([^'"\s>]+)""", re.I)
_FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.I | re.S)
_ATTR = lambda name, s: (re.search(rf"""{name}\s*=\s*['"]?([^'"\s>]+)""", s, re.I) or [None, ""])[1]
_INPUT_RE = re.compile(r"<(?:input|textarea|select)\b([^>]*)>", re.I)
_NAME_RE = re.compile(r"""name\s*=\s*['"]?([^'"\s>]+)""", re.I)
_VALUE_RE = re.compile(r"""value\s*=\s*['"]?([^'">]*)""", re.I)

_SKIP_EXT = (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
             ".woff", ".woff2", ".ttf", ".pdf", ".zip", ".tar", ".gz", ".mp4",
             ".mp3", ".webp", ".eot", ".map")
_SKIP_SCHEME = ("mailto:", "javascript:", "tel:", "data:", "#")


@dataclass
class InjectionPoint:
    method: str                       # GET | POST
    url: str                          # request target (no query for the tested set)
    params: Dict[str, str] = field(default_factory=dict)
    source: str = "url"               # url | form

    def key(self) -> Tuple:
        return (self.method, self.url, tuple(sorted(self.params)))


@dataclass
class CrawlResult:
    urls: Set[str] = field(default_factory=set)
    points: List[InjectionPoint] = field(default_factory=list)

    def add_point(self, pt: InjectionPoint, seen: Set[Tuple]) -> None:
        if pt.params and pt.key() not in seen:
            seen.add(pt.key())
            self.points.append(pt)


def _clean(url: str) -> str:
    url, _ = urldefrag(url)
    p = urlparse(url)
    # drop the query for the canonical page identity
    return urlunparse((p.scheme, p.netloc, p.path or "/", "", "", ""))


def _is_page(url: str) -> bool:
    path = urlparse(url).path.lower()
    return not path.endswith(_SKIP_EXT)


def crawl(session: Session, root: str, depth: int = 2, max_pages: int = 200,
          skip_logout: bool = True) -> CrawlResult:
    result = CrawlResult()
    seen_points: Set[Tuple] = set()
    visited: Set[str] = set()
    queue: deque = deque([(root, 0)])

    while queue and len(visited) < max_pages:
        url, d = queue.popleft()
        cu = _clean(url)
        if cu in visited:
            continue
        visited.add(cu)
        result.urls.add(url)

        # record GET params on this URL as an injection point
        q = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
        if q:
            result.add_point(InjectionPoint("GET", _clean(url), q, "url"), seen_points)

        resp = session.get(url)
        if not resp.ok or "html" not in resp.header("content-type").lower():
            continue

        # forms
        for attrs, inner in _FORM_RE.findall(resp.body):
            action = _ATTR("action", attrs) or url
            method = (_ATTR("method", attrs) or "GET").upper()
            action_url = urljoin(url, action)
            if not same_scope(action_url, root):
                continue
            inputs: Dict[str, str] = {}
            for iattr in _INPUT_RE.findall(inner):
                nm = _NAME_RE.search(iattr)
                if nm:
                    val = _VALUE_RE.search(iattr)
                    inputs[nm.group(1)] = val.group(1) if val else "pwn"
            if inputs:
                result.add_point(
                    InjectionPoint(method, _clean(action_url), inputs, "form"),
                    seen_points)

        # links
        if d < depth:
            for raw in _LINK_RE.findall(resp.body):
                if raw.lower().startswith(_SKIP_SCHEME):
                    continue
                nxt = urljoin(url, raw)
                if not nxt.lower().startswith("http"):
                    continue
                if not same_scope(nxt, root) or not _is_page(nxt):
                    continue
                if skip_logout and re.search(r"log[-_]?out|sign[-_]?out|/exit",
                                             nxt, re.I):
                    continue
                # capture GET params even on links we won't recurse into
                lq = dict(parse_qsl(urlparse(nxt).query, keep_blank_values=True))
                if lq:
                    result.add_point(InjectionPoint("GET", _clean(nxt), lq, "url"),
                                     seen_points)
                if _clean(nxt) not in visited:
                    queue.append((nxt, d + 1))

    return result
