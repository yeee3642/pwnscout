"""The scan pipeline: expand targets -> port scan -> fingerprint -> enumerate
-> (optionally) verify. Returns a ScanResult you can render any way you like.
"""

from __future__ import annotations

import re
import sys
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Dict, List, Optional, Tuple

from . import enum as enum_mod
from .core import integrations
from .core.model import Finding, Host, ScanResult, Service
from .core.utils import color, expand_targets, now_iso, resolve
from .scan import banner as banner_mod
from .scan import ports as port_mod
from .verify import verify_host


def _noop(*_a, **_k):
    pass


def _stderr_log(msg: str) -> None:
    sys.stderr.write(msg + "\n")
    sys.stderr.flush()


_NMAP_LINE = re.compile(r"^(\d+)/tcp\s+open\s+(\S+)\s*(.*)$", re.M)


def _nmap_enrich(host: str, services: List[Service]) -> None:
    ports = [s.port for s in services]
    out = integrations.nmap_service_scan(host, ports)
    if not out:
        return
    by_port = {s.port: s for s in services}
    for m in _NMAP_LINE.finditer(out):
        port = int(m.group(1))
        svc = by_port.get(port)
        if not svc:
            continue
        name, detail = m.group(2), m.group(3).strip()
        if name and name != "unknown":
            svc.name = name
        if detail:
            # detail like "Apache httpd 2.4.49 ((Ubuntu))"
            vm = re.search(r"([A-Za-z][\w .+-]*?)\s+([0-9]+\.[0-9][\w.+-]*)", detail)
            if vm and not svc.version:
                svc.product = svc.product or vm.group(1).strip()
                svc.version = vm.group(2).strip()
            if not svc.banner:
                svc.banner = detail[:200]


def run_scan(opts, log: Optional[Callable[[str], None]] = None) -> ScanResult:
    log = log or (_noop if getattr(opts, "quiet", False) else _stderr_log)

    targets = expand_targets(list(opts.targets))
    ports = port_mod.parse_ports(getattr(opts, "ports", None),
                                 getattr(opts, "profile", "top"))
    result = ScanResult(
        started=now_iso(),
        args={"targets": targets[:50], "ports": len(ports),
              "profile": getattr(opts, "profile", "top"),
              "verify": bool(getattr(opts, "verify", False))},
    )
    if not targets:
        result.finished = now_iso()
        return result

    log(color(f"[*] {len(targets)} target(s), {len(ports)} port(s) — scanning…", "cyan"))

    def _progress(done: int, total: int) -> None:
        if total and (done == total or done % (max(total // 20, 1)) < 1):
            pct = int(done * 100 / total)
            log(color(f"    port scan {pct:>3}%  ({done}/{total})", "grey"))

    open_map = port_mod.scan(
        targets, ports,
        concurrency=getattr(opts, "concurrency", 400),
        timeout=getattr(opts, "timeout", 2.0),
        progress=_progress,
    )

    alive = [ip for ip, o in open_map.items() if o]
    real_pairs: List[Tuple[str, int]] = [
        (ip, p) for ip in alive for p in open_map[ip]
    ]
    log(color(f"[*] {len(alive)} host(s) with open ports, "
              f"{sum(len(o) for o in open_map.values())} open port(s)", "cyan"))

    # ---- fingerprint every open port (threaded) ----
    detect_timeout = getattr(opts, "timeout", 2.0) + 3.0
    services_by_host: Dict[str, List[Service]] = {ip: [] for ip in alive}

    def _detect(pair: Tuple[str, int]) -> Tuple[str, Service]:
        ip, port = pair
        return ip, banner_mod.detect(ip, port, timeout=detect_timeout)

    workers = getattr(opts, "enum_workers", 40)
    if real_pairs:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for ip, svc in pool.map(_detect, real_pairs):
                services_by_host[ip].append(svc)
    log(color("[*] services fingerprinted", "grey"))

    # optional nmap enrichment
    if getattr(opts, "use_nmap", False) and integrations.have("nmap"):
        log(color("[*] enriching with nmap -sV…", "grey"))
        for ip in alive:
            _nmap_enrich(ip, services_by_host[ip])

    # ---- build hosts, enumerate, verify ----
    hostname_cache: Dict[str, str] = {}
    for ip in alive:
        host = Host(ip=ip, alive=True, hostname=hostname_cache.get(ip, ""))
        host.services = sorted(services_by_host[ip], key=lambda s: s.port)

        findings: List[Finding] = []

        def _enum_one(svc: Service) -> List[Finding]:
            try:
                return enum_mod.run(ip, svc, opts)
            except Exception:
                return []

        with ThreadPoolExecutor(max_workers=workers) as pool:
            for res in pool.map(_enum_one, host.services):
                findings.extend(res)

        if getattr(opts, "verify", False):
            try:
                findings.extend(verify_host(host, opts))
            except Exception:
                pass

        host.findings = _dedup(findings)
        result.hosts.append(host)
        _log_host(log, host)

    result.hosts.sort(key=lambda h: h.ip)
    result.finished = now_iso()
    return result


def _dedup(findings: List[Finding]) -> List[Finding]:
    best: Dict[Tuple, Finding] = {}
    for f in findings:
        key = (f.target, f.port, f.title)
        cur = best.get(key)
        if cur is None or f.score > cur.score:
            best[key] = f
    return sorted(best.values(), key=lambda f: -f.score)


def _log_host(log, host: Host) -> None:
    hot = [f for f in host.findings if f.score >= 50]
    if hot:
        log(color(f"[+] {host.ip}: {len(host.findings)} findings, "
                  f"{len(hot)} high-value", "green"))
    elif host.findings:
        log(color(f"[+] {host.ip}: {len(host.findings)} findings", "grey"))
