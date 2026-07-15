"""Port scanning: a pure-asyncio TCP connect scanner, plus an optional nmap
front-end when nmap is on PATH.

The async scanner needs nothing but the standard library, so it runs on any
``python3`` — the whole reason pwnscout is portable to a competition box.
"""

from __future__ import annotations

import asyncio
from typing import Dict, Iterable, List, Optional, Tuple

# A curated "top ports" list — the services that actually matter in an
# engagement, not a raw frequency dump. Kept short so a /24 scans fast.
TOP_PORTS: List[int] = [
    21, 22, 23, 25, 53, 69, 79, 80, 81, 88, 110, 111, 123, 135, 137, 139, 143,
    161, 389, 443, 445, 465, 500, 512, 513, 514, 515, 543, 548, 587, 623, 631,
    636, 873, 902, 990, 993, 995, 1025, 1080, 1099, 1194, 1352, 1433, 1434,
    1521, 1723, 1883, 2049, 2181, 2222, 2375, 2376, 2379, 3000, 3128, 3268,
    3306, 3389, 3690, 4369, 4444, 4505, 4506, 4786, 5000, 5060, 5432, 5555,
    5601, 5672, 5900, 5901, 5984, 5985, 5986, 6000, 6379, 6443, 6667, 7001,
    7002, 7070, 7199, 7474, 7687, 8000, 8008, 8009, 8080, 8081, 8086, 8088,
    8090, 8161, 8443, 8500, 8686, 8888, 9000, 9042, 9092, 9200, 9300, 9443,
    9990, 10000, 11211, 15672, 25565, 27017, 27018, 50000, 61616,
]

WEB_PORTS: List[int] = [
    80, 81, 443, 591, 2082, 2087, 2095, 3000, 5000, 7001, 8000, 8008, 8080,
    8081, 8088, 8090, 8443, 8888, 9000, 9090, 9443,
]


def parse_ports(spec: Optional[str], profile: str = "top") -> List[int]:
    """Turn ``80,443,8000-8100`` / ``top`` / ``web`` / ``full`` into a port list."""
    if spec:
        ports: List[int] = []
        for chunk in spec.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            if "-" in chunk:
                lo, hi = chunk.split("-", 1)
                ports.extend(range(int(lo), int(hi) + 1))
            else:
                ports.append(int(chunk))
        return sorted({p for p in ports if 0 < p <= 65535})
    if profile == "full":
        return list(range(1, 65536))
    if profile == "web":
        return WEB_PORTS
    return TOP_PORTS


async def _probe(host: str, port: int, timeout: float, sem: asyncio.Semaphore) -> Optional[int]:
    async with sem:
        try:
            fut = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(fut, timeout=timeout)
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            except (asyncio.TimeoutError, OSError):
                pass
            return port
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None
        except Exception:
            return None


async def _scan_async(
    hosts: List[str], ports: List[int], concurrency: int, timeout: float,
    progress=None,
) -> Dict[str, List[int]]:
    sem = asyncio.Semaphore(concurrency)
    results: Dict[str, List[int]] = {h: [] for h in hosts}
    pairs: List[Tuple[str, int]] = [(h, p) for h in hosts for p in ports]
    done = 0
    total = len(pairs)
    # Chunk so we never materialise millions of coroutine objects at once.
    chunk = max(concurrency * 4, 1000)
    for i in range(0, total, chunk):
        batch = pairs[i : i + chunk]
        tasks = [asyncio.ensure_future(_probe(h, p, timeout, sem)) for h, p in batch]
        for (h, _p), fut in zip(batch, tasks):
            port = await fut
            if port is not None:
                results[h].append(port)
        done += len(batch)
        if progress:
            progress(done, total)
    for h in results:
        results[h].sort()
    return results


def scan(
    hosts: List[str], ports: List[int], concurrency: int = 400,
    timeout: float = 2.0, progress=None,
) -> Dict[str, List[int]]:
    """Synchronous entry point. Returns ``{host: [open_ports]}``."""
    if not hosts or not ports:
        return {h: [] for h in hosts}
    try:
        return asyncio.run(_scan_async(hosts, ports, concurrency, timeout, progress))
    except RuntimeError:
        # An event loop is already running (e.g. embedded use) — fall back.
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(
                _scan_async(hosts, ports, concurrency, timeout, progress)
            )
        finally:
            loop.close()
