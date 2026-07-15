"""Loads the offline knowledge base and matches services against it.

The KB is plain JSON shipped inside the package — no network, no updates at
runtime. You can grow it by editing the JSON files or dropping extra files in
``$PWNSCOUT_KB`` (a directory of ``*.json`` merged on top of the built-ins).
"""

from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

_KB_DIR = os.path.dirname(os.path.abspath(__file__))


def _read(path: str) -> Any:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def _load(name: str) -> List[Dict[str, Any]]:
    """Load a built-in KB file, then merge any user overrides from $PWNSCOUT_KB."""
    data = _read(os.path.join(_KB_DIR, name)) or []
    extra_dir = os.environ.get("PWNSCOUT_KB")
    if extra_dir and os.path.isdir(extra_dir):
        override = _read(os.path.join(extra_dir, name))
        if isinstance(override, list):
            data = data + override
    return data if isinstance(data, list) else []


@lru_cache(maxsize=1)
def vulndb() -> List[Dict[str, Any]]:
    return _load("vulndb.json")


@lru_cache(maxsize=1)
def http_paths() -> List[Dict[str, Any]]:
    return _load("http_paths.json")


@lru_cache(maxsize=1)
def default_creds() -> List[Dict[str, Any]]:
    return _load("default_creds.json")


@lru_cache(maxsize=1)
def fingerprints() -> List[Dict[str, Any]]:
    return _load("fingerprints.json")


@lru_cache(maxsize=1)
def payloads() -> Dict[str, Any]:
    """Web probe payloads/signatures (a dict, not a list)."""
    data = _read(os.path.join(_KB_DIR, "payloads.json")) or {}
    extra_dir = os.environ.get("PWNSCOUT_KB")
    if extra_dir and os.path.isdir(extra_dir):
        override = _read(os.path.join(extra_dir, "payloads.json"))
        if isinstance(override, dict):
            data = {**data, **override}
    return data if isinstance(data, dict) else {}


def _read_lines(src: str, strip_slash: bool = False) -> List[str]:
    out: List[str] = []
    try:
        with open(src, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    out.append(line.lstrip("/") if strip_slash else line)
    except OSError:
        return []
    seen = set()
    return [w for w in out if not (w in seen or seen.add(w))]


def wordlist(path: Optional[str] = None) -> List[str]:
    """Content-discovery wordlist (built-in, or a user file via --wordlist)."""
    return _read_lines(path or os.path.join(_KB_DIR, "web_wordlist.txt"),
                       strip_slash=True)


def jwt_secrets(path: Optional[str] = None) -> List[str]:
    """Weak JWT HMAC secrets for offline cracking (built-in or --jwt-wordlist)."""
    return _read_lines(path or os.path.join(_KB_DIR, "jwt_secrets.txt"))


# ---------------------------------------------------------------------------
# version handling
# ---------------------------------------------------------------------------
_VER_RE = re.compile(r"\d+")


def version_key(value: str) -> Tuple[int, ...]:
    """Best-effort ``1.2.3p4`` -> ``(1, 2, 3, 4)`` for ordered comparison."""
    if not value:
        return ()
    return tuple(int(x) for x in _VER_RE.findall(value)[:6])


def _cmp(a: str, b: str) -> int:
    ka, kb = version_key(a), version_key(b)
    return (ka > kb) - (ka < kb)


def _version_ok(version: str, cond: Dict[str, Any]) -> bool:
    if not version:
        # No version parsed: only match rules that don't constrain version.
        return not any(k in cond for k in
                       ("version", "version_lt", "version_le", "version_ge",
                        "version_gt", "version_regex"))
    if "version" in cond and _cmp(version, str(cond["version"])) != 0:
        return False
    if "version_lt" in cond and not _cmp(version, str(cond["version_lt"])) < 0:
        return False
    if "version_le" in cond and not _cmp(version, str(cond["version_le"])) <= 0:
        return False
    if "version_ge" in cond and not _cmp(version, str(cond["version_ge"])) >= 0:
        return False
    if "version_gt" in cond and not _cmp(version, str(cond["version_gt"])) > 0:
        return False
    if "version_regex" in cond and not re.search(cond["version_regex"], version):
        return False
    return True


def match_service(product: str, version: str, banner: str, port: int) -> List[Dict[str, Any]]:
    """Return every vulndb entry whose ``match`` block fits this service."""
    hits: List[Dict[str, Any]] = []
    hay_product = (product or "").lower()
    hay_banner = banner or ""
    for entry in vulndb():
        cond = entry.get("match", {})
        if "port" in cond and cond["port"] != port:
            continue
        prod_pat = cond.get("product")
        if prod_pat:
            if not (prod_pat.lower() in hay_product
                    or re.search(prod_pat, product or "", re.I)
                    or re.search(prod_pat, hay_banner, re.I)):
                continue
        banner_pat = cond.get("banner_regex")
        if banner_pat and not re.search(banner_pat, hay_banner, re.I):
            continue
        if not _version_ok(version, cond):
            continue
        if not prod_pat and not banner_pat:
            continue  # never match an empty condition
        hits.append(entry)
    return hits
