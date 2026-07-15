"""Core data model: hosts, services, findings and the attack-score.

The whole point of pwnscout is the ``Finding`` and its ``score``. A finding
answers three questions at once:

* **what** is wrong (``title`` / ``category``)
* **why it is attackable** (``why``)
* **what to do next** (``next_step`` — a concrete command you can paste)

``score`` (0-100) is a deterministic ranking so that after a run you read the
report top-down and start hitting things in order. No AI, no fuzzy magic —
just severity x confidence with small, explainable bumps.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: Any) -> "Severity":
        if isinstance(value, cls):
            return value
        if isinstance(value, int):
            return cls(max(0, min(4, value)))
        key = str(value).strip().upper()
        return cls.__members__.get(key, cls.INFO)


class Confidence(enum.IntEnum):
    """How sure we are the finding is real and hittable."""

    POSSIBLE = 0   # inferred from a version/banner only — could be a false positive
    LIKELY = 1     # a strong, specific signal was observed
    CONFIRMED = 2  # a safe PoC actually proved it

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: Any) -> "Confidence":
        if isinstance(value, cls):
            return value
        if isinstance(value, int):
            return cls(max(0, min(2, value)))
        key = str(value).strip().upper()
        return cls.__members__.get(key, cls.POSSIBLE)


# Deterministic scoring tables. Tuned so a CONFIRMED critical pins to ~100 and
# a POSSIBLE info stays near the floor, with everything else spread between.
_SEV_WEIGHT = {0: 5, 1: 22, 2: 48, 3: 76, 4: 94}
_CONF_MULT = {0: 0.6, 1: 0.82, 2: 1.0}

# Tags that mean "there is a known way to pop this" — small score bump so
# exploitable things float above merely-severe things.
_HOT_TAGS = frozenset(
    {"rce", "exploit-available", "default-creds", "unauth", "auth-bypass", "sqli"}
)


@dataclass
class Finding:
    target: str
    service: str
    title: str
    port: Optional[int] = None
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.POSSIBLE
    category: str = "misc"          # exposure | default-creds | known-cve | misconfig | injection | recon
    evidence: str = ""              # raw proof (banner slice, path + status, etc.)
    why: str = ""                   # plain-language: why this is attackable
    next_step: str = ""             # a command you can paste to go further
    refs: List[str] = field(default_factory=list)
    verified: bool = False          # a safe PoC confirmed it this run
    tags: List[str] = field(default_factory=list)
    cve: Optional[str] = None
    exploit: Optional[Dict[str, Any]] = None   # structured hook for exploit-gen

    @property
    def score(self) -> int:
        base = _SEV_WEIGHT[int(self.severity)]
        mult = _CONF_MULT[int(self.confidence)]
        value = base * mult
        if self.verified:
            value = min(100.0, value + 10)
        if _HOT_TAGS.intersection(self.tags):
            value = min(100.0, value + 5)
        return int(round(value))

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.label
        data["confidence"] = self.confidence.label
        data["score"] = self.score
        return data


@dataclass
class Service:
    port: int
    proto: str = "tcp"
    name: str = ""                  # guessed service name, e.g. "http", "ssh"
    product: str = ""               # e.g. "Apache httpd", "OpenSSH"
    version: str = ""               # e.g. "2.4.49"
    banner: str = ""
    tunnel: str = ""                # "ssl" when wrapped in TLS
    extra: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_web(self) -> bool:
        if self.name in ("http", "https"):
            return True
        return self.port in (80, 443, 8000, 8008, 8080, 8443, 8888, 9000, 5000, 3000)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Host:
    ip: str
    hostname: str = ""
    alive: bool = True
    services: List[Service] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "alive": self.alive,
            "services": [s.to_dict() for s in self.services],
            "findings": [f.to_dict() for f in sorted(self.findings, key=lambda x: -x.score)],
        }


@dataclass
class ScanResult:
    hosts: List[Host] = field(default_factory=list)
    started: str = ""
    finished: str = ""
    args: Dict[str, Any] = field(default_factory=dict)

    @property
    def findings(self) -> List[Finding]:
        out: List[Finding] = []
        for host in self.hosts:
            out.extend(host.findings)
        return out

    def ranked(self, min_score: int = 0) -> List[Finding]:
        return sorted(
            (f for f in self.findings if f.score >= min_score),
            key=lambda f: (-f.score, f.target, f.port or 0),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": "pwnscout",
            "started": self.started,
            "finished": self.finished,
            "args": self.args,
            "summary": self.summary(),
            "hosts": [h.to_dict() for h in self.hosts],
        }

    def summary(self) -> Dict[str, Any]:
        counts = {s.label: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.label] += 1
        return {
            "hosts_scanned": len(self.hosts),
            "hosts_alive": sum(1 for h in self.hosts if h.alive),
            "services": sum(len(h.services) for h in self.hosts),
            "findings": len(self.findings),
            "verified": sum(1 for f in self.findings if f.verified),
            "by_severity": counts,
        }
