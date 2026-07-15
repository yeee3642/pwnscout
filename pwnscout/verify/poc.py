"""Safe proof-of-concept checks.

Every check here is read-only: an anonymous login, an unauthenticated status
query, a version handshake. Nothing writes to or damages the target. Optional
credential guessing is gated behind ``--brute`` and kept intentionally small
to avoid lockouts.
"""

from __future__ import annotations

import base64
import ftplib
import socket
import struct
from typing import List

from ..core.integrations import smbclient_shares
from ..core.model import Confidence, Finding, Host, Service, Severity
from ..core.utils import http_request


def _ctx(host: str, port: int, tls: bool = False):
    from ..enum import context, render
    return context(host, port, tls), render


def verify_host(host: Host, opts) -> List[Finding]:
    """Run every applicable safe PoC for a host's services."""
    out: List[Finding] = []
    brute = getattr(opts, "brute", False)
    for svc in host.services:
        try:
            name, port = svc.name, svc.port
            if name == "ftp" or port == 21:
                out.extend(_ftp_anon(host.ip, port))
            if name == "redis" or port == 6379:
                out.extend(_redis(host.ip, port))
            if name == "memcached" or port == 11211:
                out.extend(_memcached(host.ip, port))
            if name in ("docker",) or port == 2375:
                out.extend(_docker(host.ip, port))
            if name == "elasticsearch" or port in (9200,):
                out.extend(_elasticsearch(host.ip, port))
            if name == "mongodb" or port in (27017, 27018):
                out.extend(_mongodb(host.ip, port))
            if name == "smb" or port == 445:
                out.extend(_smb_null(host.ip, port))
            if brute and svc.is_web:
                out.extend(_http_basic_brute(host.ip, svc))
        except Exception:
            # A scanner must never die on one probe.
            continue
    return out


def _mk(host, port, service, title, sev, why, next_step, tags, evidence):
    ctx, render = _ctx(host, port)
    return Finding(
        target=host, port=port, service=service, title=title,
        severity=sev, confidence=Confidence.CONFIRMED, verified=True,
        category="unauth", evidence=evidence, why=why,
        next_step=render(next_step, ctx), tags=tags,
    )


def _ftp_anon(host: str, port: int) -> List[Finding]:
    out: List[Finding] = []
    ftp = ftplib.FTP()
    try:
        ftp.connect(host, port, timeout=8)
        ftp.login("anonymous", "anonymous@example.com")
        listing = []
        try:
            listing = ftp.nlst()[:10]
        except ftplib.error_perm:
            pass
        out.append(_mk(
            host, port, "ftp", "Anonymous FTP login allowed",
            Severity.MEDIUM,
            "Anonymous access confirmed — read exposed files and, if the "
            "directory is writable, drop a payload.",
            "ftp {ip} {port}  # user: anonymous",
            ["unauth", "exposure"],
            "230 login OK; entries: " + ", ".join(listing) if listing else "230 login OK",
        ))
    except (ftplib.all_errors, OSError):
        pass
    finally:
        try:
            ftp.close()
        except Exception:
            pass
    return out


def _redis(host: str, port: int) -> List[Finding]:
    out: List[Finding] = []
    try:
        with socket.create_connection((host, port), timeout=6) as s:
            s.settimeout(6)
            s.sendall(b"PING\r\n")
            resp = s.recv(256).decode("latin-1", "replace")
            if "PONG" in resp:
                s.sendall(b"CONFIG GET dir\r\n")
                cfg = s.recv(512).decode("latin-1", "replace")
                writable = "NOAUTH" not in cfg and "dir" in cfg
                out.append(_mk(
                    host, port, "redis", "Redis reachable without authentication",
                    Severity.HIGH,
                    "No AUTH required. Abuse CONFIG SET dir/dbfilename to write an "
                    "SSH key, cron job or webshell for RCE." if writable else
                    "No AUTH required — read/modify all cached data.",
                    "redis-cli -h {ip} -p {port} config get dir",
                    ["unauth", "rce"],
                    "PING -> +PONG (no auth)",
                ))
            elif "NOAUTH" in resp:
                pass  # protected — good for them, nothing to confirm
    except OSError:
        pass
    return out


def _memcached(host: str, port: int) -> List[Finding]:
    out: List[Finding] = []
    try:
        with socket.create_connection((host, port), timeout=6) as s:
            s.settimeout(6)
            s.sendall(b"stats\r\n")
            resp = s.recv(2048).decode("latin-1", "replace")
            if "STAT " in resp:
                out.append(_mk(
                    host, port, "memcached", "Memcached exposed without auth",
                    Severity.MEDIUM,
                    "Unauthenticated — dump cached keys (sessions/tokens) and note "
                    "UDP amplification risk.",
                    "echo -e 'stats items\\nquit' | nc {ip} {port}",
                    ["unauth"],
                    "stats -> " + resp.strip().splitlines()[0][:80],
                ))
    except OSError:
        pass
    return out


def _docker(host: str, port: int) -> List[Finding]:
    out: List[Finding] = []
    r = http_request(f"http://{host}:{port}/version", timeout=6)
    if r.ok and ("ApiVersion" in r.body or "Version" in r.body):
        out.append(_mk(
            host, port, "docker", "Docker Engine API exposed without auth",
            Severity.CRITICAL,
            "Unauthenticated Docker API = full host takeover: run a container that "
            "mounts the host filesystem.",
            "docker -H tcp://{ip}:{port} run -v /:/mnt --rm -it alpine chroot /mnt sh",
            ["unauth", "rce"],
            "GET /version -> " + r.body[:80],
        ))
    return out


def _elasticsearch(host: str, port: int) -> List[Finding]:
    out: List[Finding] = []
    r = http_request(f"http://{host}:{port}/", timeout=6)
    if r.ok and '"cluster_name"' in r.body:
        idx = http_request(f"http://{host}:{port}/_cat/indices?format=json", timeout=6)
        confirmed = idx.status == 200
        out.append(_mk(
            host, port, "elasticsearch",
            "Elasticsearch reachable without authentication",
            Severity.HIGH if confirmed else Severity.MEDIUM,
            "Unauthenticated REST API — dump every index (often full app data).",
            "curl -s http://{ip}:{port}/_cat/indices?v",
            ["unauth", "data"],
            "GET / -> cluster_name present",
        ))
    return out


def _mongodb(host: str, port: int) -> List[Finding]:
    """Legacy isMaster handshake to confirm a MongoDB is actually there."""
    out: List[Finding] = []
    try:
        # BSON for {isMaster: 1}
        doc = struct.pack("<i", 19) + b"\x10isMaster\x00" + struct.pack("<i", 1) + b"\x00"
        body = (struct.pack("<i", 0) + b"admin.$cmd\x00"
                + struct.pack("<ii", 0, -1) + doc)
        header = struct.pack("<iiii", 16 + len(body), 1, 0, 2004)
        with socket.create_connection((host, port), timeout=6) as s:
            s.settimeout(6)
            s.sendall(header + body)
            resp = s.recv(2048)
        if b"ismaster" in resp.lower() or b"maxWireVersion" in resp:
            out.append(Finding(
                target=host, port=port, service="mongodb",
                title="MongoDB reachable", severity=Severity.MEDIUM,
                confidence=Confidence.LIKELY, category="recon",
                evidence="isMaster handshake answered",
                why="MongoDB is exposed. If auth is off you can list and dump "
                    "databases directly.",
                next_step=f"mongosh 'mongodb://{host}:{port}' --eval 'db.adminCommand({{listDatabases:1}})'",
                tags=["recon"],
            ))
    except OSError:
        pass
    return out


def _smb_null(host: str, port: int) -> List[Finding]:
    out: List[Finding] = []
    result = smbclient_shares(host)
    if result and ("Sharename" in result or "Disk" in result):
        shares = [ln.split()[0] for ln in result.splitlines()
                  if ln.strip() and ("Disk" in ln or "IPC" in ln)][:12]
        out.append(_mk(
            host, port, "smb", "SMB null-session share listing",
            Severity.MEDIUM,
            "Anonymous share enumeration works — hunt readable shares for files "
            "and credentials.",
            "smbclient -N //{ip}/SHARE",
            ["unauth", "recon"],
            "shares: " + ", ".join(shares) if shares else "null session OK",
        ))
    return out


def _http_basic_brute(host: str, svc: Service) -> List[Finding]:
    """Tiny HTTP Basic-auth default-cred check (only with --brute)."""
    from ..kb import loader
    out: List[Finding] = []
    tls = svc.tunnel == "ssl" or svc.port in (443, 8443, 9443)
    scheme = "https" if tls else "http"
    base = f"{scheme}://{host}:{svc.port}"
    # Only try if the root actually challenges for Basic auth.
    root = http_request(base + "/", timeout=6)
    targets = [("/", root)]
    # Tomcat manager is a classic.
    mgr = http_request(base + "/manager/html", timeout=6)
    if mgr.status in (401, 403):
        targets.append(("/manager/html", mgr))

    creds = []
    for group in loader.default_creds():
        if group.get("service") in ("basic-auth", "web-app", "tomcat-manager"):
            creds.extend(tuple(c) for c in group.get("creds", []))
    seen = set()
    creds = [c for c in creds if not (tuple(c) in seen or seen.add(tuple(c)))][:8]

    for path, resp in targets:
        if resp.status != 401 or "basic" not in resp.header("www-authenticate").lower():
            continue
        for user, pw in creds:
            token = base64.b64encode(f"{user}:{pw}".encode()).decode()
            r = http_request(base + path, headers={"Authorization": f"Basic {token}"},
                             timeout=6)
            if r.status not in (401, 403, 0):
                out.append(_mk(
                    host, svc.port, "http",
                    f"Default HTTP Basic creds: {user}:{pw or '<blank>'}",
                    Severity.HIGH,
                    "Authenticated with default credentials — you have access to "
                    "the protected area.",
                    f"curl -su {user}:{pw} {base}{path}",
                    ["default-creds", "auth-bypass"],
                    f"{path} -> HTTP {r.status} with {user}:{pw or '<blank>'}",
                ))
                break
    return out
