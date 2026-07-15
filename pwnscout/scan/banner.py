"""Service + version fingerprinting from banners (standard library only).

For each open port we guess the service, send the right probe, read the
banner and parse product/version. That version is what the KB matches against
to say "this exact build has a known hole".
"""

from __future__ import annotations

import re
import socket
import ssl
from typing import Dict, Optional, Tuple

from ..core.model import Service

# Default service name by port (fallback when the banner is silent/binary).
PORT_SERVICE: Dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 79: "finger",
    80: "http", 81: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 161: "snmp", 389: "ldap", 443: "https",
    445: "smb", 465: "smtps", 512: "exec", 513: "login", 514: "shell",
    587: "smtp", 636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s",
    1080: "socks", 1099: "java-rmi", 1433: "mssql", 1521: "oracle",
    1723: "pptp", 2049: "nfs", 2181: "zookeeper", 2222: "ssh", 2375: "docker",
    2376: "docker-tls", 3000: "http", 3128: "http-proxy", 3306: "mysql",
    3389: "rdp", 5000: "http", 5432: "postgres", 5601: "kibana", 5672: "amqp",
    5900: "vnc", 5901: "vnc", 5984: "couchdb", 5985: "winrm", 5986: "winrm-tls",
    6379: "redis", 6443: "kube-api", 6667: "irc", 7001: "weblogic",
    8000: "http", 8008: "http", 8009: "ajp", 8080: "http", 8081: "http",
    8086: "influxdb", 8090: "http", 8161: "activemq", 8443: "https",
    8888: "http", 9000: "http", 9042: "cassandra", 9092: "kafka",
    9200: "elasticsearch", 9300: "elasticsearch", 11211: "memcached",
    15672: "rabbitmq-mgmt", 27017: "mongodb", 27018: "mongodb", 61616: "activemq",
}

TLS_PORTS = {443, 465, 636, 993, 995, 8443, 9443, 2376, 5986, 6443}
HTTP_PORTS = {80, 81, 591, 3000, 5000, 8000, 8008, 8080, 8081, 8088, 8090, 8888, 9000, 9090}

# Probe to send after connecting, keyed by (best-guess) service.
_PROBES: Dict[str, bytes] = {
    "http": b"GET / HTTP/1.0\r\nHost: x\r\nUser-Agent: pwnscout\r\n\r\n",
    "redis": b"INFO server\r\n",
    "memcached": b"version\r\n",
    "mongodb": b"",  # binary; skip probe
}

# product/version extraction. Order matters — first match wins.
_VERSION_RULES = [
    ("OpenSSH", re.compile(r"OpenSSH[_/]([0-9][0-9.p]*)"), "ssh"),
    ("Dropbear", re.compile(r"dropbear_([0-9][0-9.]*)"), "ssh"),
    ("vsftpd", re.compile(r"vsFTPd (\d[\d.]*)", re.I), "ftp"),
    ("ProFTPD", re.compile(r"ProFTPD (\d[\d.]*)", re.I), "ftp"),
    ("Pure-FTPd", re.compile(r"Pure-FTPd", re.I), "ftp"),
    ("FileZilla", re.compile(r"FileZilla Server[^0-9]*([\d.]+)?", re.I), "ftp"),
    ("Exim", re.compile(r"Exim (\d[\d.]*)", re.I), "smtp"),
    ("Postfix", re.compile(r"Postfix", re.I), "smtp"),
    ("Sendmail", re.compile(r"Sendmail[^\d]*(\d[\d./]*)?", re.I), "smtp"),
    ("Apache", re.compile(r"Apache/(\d[\d.]*)", re.I), "http"),
    ("nginx", re.compile(r"nginx/(\d[\d.]*)", re.I), "http"),
    ("Microsoft-IIS", re.compile(r"Microsoft-IIS/(\d[\d.]*)", re.I), "http"),
    ("lighttpd", re.compile(r"lighttpd/(\d[\d.]*)", re.I), "http"),
    ("redis", re.compile(r"redis_version:(\d[\d.]*)", re.I), "redis"),
    ("MySQL", re.compile(r"(\d+\.\d+\.\d+)[-_]?(MariaDB|log|Ubuntu|Debian)?", re.I), "mysql"),
    ("memcached", re.compile(r"VERSION (\d[\d.]*)", re.I), "memcached"),
    ("VNC", re.compile(r"RFB (\d{3}\.\d{3})", re.I), "vnc"),
]

_SERVER_HDR = re.compile(r"(?im)^Server:\s*(.+?)\r?$")
_XPOWERED = re.compile(r"(?im)^X-Powered-By:\s*(.+?)\r?$")


def _raw_connect(host: str, port: int, timeout: float, use_ssl: bool,
                 probe: bytes) -> str:
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        if use_ssl:
            ctx = ssl._create_unverified_context()
            ctx.check_hostname = False
            sock = ctx.wrap_socket(sock, server_hostname=host)
        # Give banner-first services (FTP/SSH/SMTP) a moment before probing.
        data = b""
        if probe:
            try:
                sock.settimeout(1.5)
                data = sock.recv(1024)  # grab any greeting first
            except (socket.timeout, OSError):
                data = b""
            try:
                sock.sendall(probe)
            except OSError:
                pass
            sock.settimeout(timeout)
        try:
            more = sock.recv(4096)
            data += more
        except (socket.timeout, OSError):
            pass
        return data.decode("latin-1", "replace")
    except (OSError, ssl.SSLError):
        return ""
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _parse(banner: str) -> Tuple[str, str]:
    """Return (product, version) from a banner using the rule table."""
    # HTTP: prefer the Server header.
    m = _SERVER_HDR.search(banner)
    if m:
        server = m.group(1).strip()
        for product, rx, _svc in _VERSION_RULES:
            vm = rx.search(server)
            if vm:
                ver = vm.group(1) if vm.groups() and vm.group(1) else ""
                return product, ver or ""
        return server.split()[0] if server else "", ""
    for product, rx, _svc in _VERSION_RULES:
        vm = rx.search(banner)
        if vm:
            ver = ""
            if vm.groups():
                ver = next((g for g in vm.groups() if g and re.match(r"\d", g)), "")
            return product, ver
    return "", ""


def detect(host: str, port: int, timeout: float = 5.0) -> Service:
    name = PORT_SERVICE.get(port, "unknown")
    use_ssl = port in TLS_PORTS
    probe_key = "http" if (port in HTTP_PORTS or name in ("http", "https")) else name
    probe = _PROBES.get(probe_key, b"")
    banner = _raw_connect(host, port, timeout, use_ssl, probe)

    # If a plaintext HTTP probe on a maybe-TLS port failed, retry with TLS.
    if not banner and not use_ssl and port in (443, 8443, 9443):
        banner = _raw_connect(host, port, timeout, True, probe)
        use_ssl = True

    # Web apps love odd ports. If we don't recognise the port, try HTTP.
    if name == "unknown" and "HTTP/" not in banner.upper():
        alt = _raw_connect(host, port, timeout, use_ssl, _PROBES["http"])
        if "HTTP/" in alt.upper():
            banner = alt
        elif not use_ssl:
            alt = _raw_connect(host, port, timeout, True, _PROBES["http"])
            if "HTTP/" in alt.upper():
                banner, use_ssl = alt, True

    product, version = _parse(banner)

    # Normalise a couple of names for cleaner KB matching.
    if "HTTP/" in banner.upper() and name in ("unknown", ""):
        name = "https" if use_ssl else "http"
    if name == "unknown" and product:
        if "ssh" in banner.lower():
            name = "ssh"
        elif "ftp" in banner.lower():
            name = "ftp"
        elif "http" in banner.lower() or _SERVER_HDR.search(banner):
            name = "http"

    svc = Service(
        port=port, proto="tcp", name=name, product=product, version=version,
        banner=banner[:600].strip(), tunnel=("ssl" if use_ssl else ""),
    )
    xp = _XPOWERED.search(banner)
    if xp:
        svc.extra["x_powered_by"] = xp.group(1).strip()
    return svc
