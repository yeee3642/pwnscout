"""Detect and opportunistically use external tools if they happen to be on
the box (nmap, smbclient, searchsploit, nuclei). Everything degrades to the
pure-Python path when they are absent — pwnscout never *requires* them.
"""

from __future__ import annotations

import shutil
import subprocess
from functools import lru_cache
from typing import List, Optional


@lru_cache(maxsize=None)
def have(tool: str) -> bool:
    return shutil.which(tool) is not None


def available() -> dict:
    return {t: have(t) for t in ("nmap", "smbclient", "searchsploit", "nuclei",
                                 "redis-cli", "git-dumper")}


def run(cmd: List[str], timeout: float = 60.0) -> Optional[str]:
    """Run a command, return stdout (+stderr) or None on failure/timeout."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False,
        )
        return (proc.stdout or "") + (proc.stderr or "")
    except (OSError, subprocess.SubprocessError):
        return None


def nmap_service_scan(host: str, ports: List[int], timeout: float = 300.0) -> Optional[str]:
    """Grab nmap's -sV output if nmap exists (richer than banner parsing)."""
    if not have("nmap") or not ports:
        return None
    portspec = ",".join(str(p) for p in ports)
    return run(["nmap", "-sV", "-Pn", "-T4", "-p", portspec, "--version-light",
                host], timeout=timeout)


def smbclient_shares(host: str, timeout: float = 30.0) -> Optional[str]:
    """List SMB shares via a null session, if smbclient is present."""
    if not have("smbclient"):
        return None
    return run(["smbclient", "-N", "-L", f"//{host}/"], timeout=timeout)


def searchsploit(term: str, timeout: float = 30.0) -> Optional[str]:
    if not have("searchsploit") or not term:
        return None
    return run(["searchsploit", "--color", "never", term], timeout=timeout)
