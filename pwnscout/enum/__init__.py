"""Enumeration dispatch: turn a detected service into concrete findings."""

from __future__ import annotations

from typing import Dict, List

from ..core.model import Finding, Host, Service
from ..core.utils import base_urls
from . import http as http_enum
from . import services as svc_enum


def context(host: str, port: int, tls: bool) -> Dict[str, str]:
    scheme = "https" if tls else "http"
    return {
        "ip": host, "host": host, "port": str(port),
        "scheme": scheme, "base": base_urls(host, port, tls),
    }


def render(template: str, ctx: Dict[str, str]) -> str:
    """Substitute {ip}/{host}/{port}/{scheme}/{base} without touching other
    braces (payloads often contain literal { } and must survive verbatim)."""
    if not template:
        return template
    out = template
    for key, val in ctx.items():
        out = out.replace("{" + key + "}", val)
    return out


def is_tls(service: Service) -> bool:
    return service.tunnel == "ssl" or service.name in ("https", "smtps", "imaps",
                                                        "pop3s", "ldaps")


def run(host_ip: str, service: Service, opts) -> List[Finding]:
    findings: List[Finding] = []
    findings.extend(svc_enum.match_versions(host_ip, service))
    findings.extend(svc_enum.service_notes(host_ip, service))
    if service.is_web:
        findings.extend(http_enum.enum(host_ip, service, opts))
    return findings
