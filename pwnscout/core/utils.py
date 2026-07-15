"""Small dependency-free helpers: target expansion, colour, socket + HTTP.

Everything here uses only the standard library so pwnscout runs on a stock
``python3`` with no ``pip install`` — the kind of box you get handed at a
competition.
"""

from __future__ import annotations

import ipaddress
import os
import re
import socket
import ssl
import sys
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from urllib import request as _urlrequest
from urllib.error import HTTPError, URLError

USER_AGENT = "pwnscout/0.1 (+offline recon; authorized testing only)"

# ---------------------------------------------------------------------------
# colour
# ---------------------------------------------------------------------------
_NO_COLOR = bool(os.environ.get("NO_COLOR")) or not sys.stdout.isatty()
_C = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[31m", "green": "\033[32m", "yellow": "\033[33m",
    "blue": "\033[34m", "magenta": "\033[35m", "cyan": "\033[36m",
    "grey": "\033[90m", "bred": "\033[91m", "bgreen": "\033[92m",
    "byellow": "\033[93m",
}


def disable_color() -> None:
    global _NO_COLOR
    _NO_COLOR = True


def color(text: str, *styles: str) -> str:
    if _NO_COLOR or not styles:
        return text
    prefix = "".join(_C.get(s, "") for s in styles)
    return f"{prefix}{text}{_C['reset']}"


# ---------------------------------------------------------------------------
# target parsing
# ---------------------------------------------------------------------------
_RANGE_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3})$")


def expand_targets(specs: List[str]) -> List[str]:
    """Turn a mix of IPs, CIDRs, ``a.b.c.d-e`` ranges, hostnames and @files
    into a de-duplicated, order-preserving list of host strings.

    Hostnames are kept as-is (resolved lazily by the scanner) so the tool
    still works when DNS is flaky — a common venue condition.
    """
    out: List[str] = []
    seen = set()

    def _add(item: str) -> None:
        item = item.strip()
        if item and item not in seen:
            seen.add(item)
            out.append(item)

    for raw in specs:
        spec = raw.strip()
        if not spec or spec.startswith("#"):
            continue
        # @file or a path to a list of targets
        if spec.startswith("@") or (os.path.sep in spec and os.path.isfile(spec)):
            path = spec[1:] if spec.startswith("@") else spec
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        for tok in re.split(r"[\s,]+", line.strip()):
                            if tok and not tok.startswith("#"):
                                for e in expand_targets([tok]):
                                    _add(e)
                continue
            except OSError:
                pass
        # CIDR
        if "/" in spec:
            try:
                net = ipaddress.ip_network(spec, strict=False)
                hosts = list(net.hosts()) or [net.network_address]
                for ip in hosts:
                    _add(str(ip))
                continue
            except ValueError:
                pass
        # a.b.c.d-e short range
        m = _RANGE_RE.match(spec)
        if m:
            base, last = m.group(1), int(m.group(2))
            octs = base.split(".")
            start = int(octs[3])
            for i in range(start, min(last, 255) + 1):
                _add(f"{octs[0]}.{octs[1]}.{octs[2]}.{i}")
            continue
        _add(spec)
    return out


def resolve(host: str) -> Optional[str]:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


# ---------------------------------------------------------------------------
# raw socket banner grab (sync — run in a thread pool)
# ---------------------------------------------------------------------------
def grab_banner(
    host: str, port: int, timeout: float = 4.0, send: Optional[bytes] = None,
    use_ssl: bool = False,
) -> str:
    data = b""
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        if use_ssl:
            ctx = ssl._create_unverified_context()
            ctx.check_hostname = False
            sock = ctx.wrap_socket(sock, server_hostname=host)
        if send:
            sock.sendall(send)
        data = sock.recv(2048)
    except (OSError, ssl.SSLError):
        return ""
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return data.decode("latin-1", "replace")


# ---------------------------------------------------------------------------
# HTTP (stdlib only, TLS verification off — we scan hostile boxes)
# ---------------------------------------------------------------------------
@dataclass
class HttpResponse:
    url: str
    status: int
    headers: Dict[str, str]
    body: str
    final_url: str
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.status != 0 and not self.error

    def header(self, name: str) -> str:
        return self.headers.get(name.lower(), "")


def http_request(
    url: str, method: str = "GET", timeout: float = 8.0,
    headers: Optional[Dict[str, str]] = None, max_body: int = 200_000,
    data: Optional[bytes] = None,
) -> HttpResponse:
    hdrs = {"User-Agent": USER_AGENT, "Accept": "*/*", "Connection": "close"}
    if headers:
        hdrs.update(headers)
    ctx = ssl._create_unverified_context()
    req = _urlrequest.Request(url, method=method, headers=hdrs, data=data)
    try:
        with _urlrequest.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(max_body)
            raw = {k.lower(): v for k, v in resp.headers.items()}
            return HttpResponse(url, resp.status, raw,
                                body.decode("utf-8", "replace"), resp.geturl())
    except HTTPError as exc:  # 4xx/5xx still carry useful info
        try:
            body = exc.read(max_body).decode("utf-8", "replace")
        except Exception:
            body = ""
        raw = {k.lower(): v for k, v in (exc.headers or {}).items()}
        return HttpResponse(url, exc.code, raw, body, url)
    except (URLError, socket.timeout, ssl.SSLError, ConnectionError, OSError) as exc:
        return HttpResponse(url, 0, {}, "", url, error=str(exc))
    except Exception as exc:  # be defensive — a scanner must never crash on one URL
        return HttpResponse(url, 0, {}, "", url, error=repr(exc))


def base_urls(host: str, port: int, tls: bool) -> str:
    scheme = "https" if tls else "http"
    default = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    netloc = host if default else f"{host}:{port}"
    return f"{scheme}://{netloc}"


def now_iso() -> str:
    # time.time() is allowed here (real CLI run, not a workflow script)
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())


def clip(text: str, length: int = 160) -> str:
    text = " ".join(text.split())
    return text if len(text) <= length else text[: length - 1] + "…"
