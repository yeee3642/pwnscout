"""Non-web enumeration: match banners/versions against the KB and emit the
port-based "you should look at this" notes.
"""

from __future__ import annotations

from typing import List

from ..core.model import Confidence, Finding, Service, Severity
from ..kb import loader


def _ctx(host: str, port: int):
    # local import to avoid a cycle with the package __init__
    from . import context, render
    return context(host, port, False), render


def match_versions(host: str, service: Service) -> List[Finding]:
    """version/banner -> known-CVE findings straight from vulndb."""
    out: List[Finding] = []
    ctx, render = _ctx(host, service.port)
    entries = loader.match_service(
        service.product, service.version, service.banner, service.port
    )
    for e in entries:
        # Port-only rules (e.g. "445 open -> check MS17-010") are hints, not
        # version-confirmed bugs, so they stay POSSIBLE. A product+version hit
        # is a much stronger signal.
        has_version = bool(service.version) and "product" in e.get("match", {})
        conf = Confidence.LIKELY if has_version else Confidence.POSSIBLE
        out.append(Finding(
            target=host, port=service.port, service=service.name or "tcp",
            title=e.get("title", e.get("id", "known issue")),
            severity=Severity.parse(e.get("severity", "medium")),
            confidence=conf,
            category="known-cve" if e.get("cve") else "misconfig",
            evidence=(f"{service.product} {service.version}".strip()
                      or service.banner[:120]),
            why=e.get("why", ""),
            next_step=render(e.get("next_step", ""), ctx),
            refs=e.get("refs", []),
            tags=e.get("tags", []),
            cve=e.get("cve"),
        ))
    return out


def service_notes(host: str, service: Service) -> List[Finding]:
    """A couple of always-useful observations that aren't in vulndb."""
    out: List[Finding] = []
    ctx, render = _ctx(host, service.port)
    b = service.banner.lower()

    # Cleartext protocols worth flagging for the report.
    cleartext = {"ftp": 21, "telnet": 23, "http": 80, "pop3": 110, "imap": 143,
                 "smtp": 25}
    if service.name in cleartext and service.tunnel != "ssl":
        # Only note it once, at low severity — it matters for the writeup.
        if service.name in ("telnet", "ftp"):
            out.append(Finding(
                target=host, port=service.port, service=service.name,
                title=f"Cleartext {service.name.upper()} service",
                severity=Severity.LOW, confidence=Confidence.LIKELY,
                category="misconfig", evidence=service.banner[:120],
                why="Credentials and data traverse the network in cleartext; "
                    "sniff them on a shared segment or MITM position.",
                next_step=render("nc {ip} {port}", ctx),
                tags=["cleartext"],
            ))

    # WinRM is a prime lateral-movement target once you have creds.
    if service.name in ("winrm", "winrm-tls"):
        out.append(Finding(
            target=host, port=service.port, service=service.name,
            title="WinRM management endpoint",
            severity=Severity.LOW, confidence=Confidence.LIKELY,
            category="recon", evidence=service.banner[:120],
            why="With valid Windows creds this is instant remote code execution.",
            next_step=render("evil-winrm -i {ip} -u USER -p PASS", ctx),
            tags=["lateral"],
        ))

    return out
