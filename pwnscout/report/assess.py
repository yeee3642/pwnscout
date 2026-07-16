"""Risk scoring (CVSS 3.1), submittability, and remediation for findings.

Turns each finding into something you can actually put in a report or a bug
bounty submission: a real CVSS v3.1 vector + base score, a risk label, whether
it's worth submitting (vs recon noise), and concrete remediation advice.

CVSS vectors are *estimated* from the finding class — deterministic and
defensible, but always eyeball them before you submit.
"""

from __future__ import annotations

import math
from typing import Dict, Optional

from ..core.model import Confidence, Finding, Severity

# ---- CVSS 3.1 base-score metric weights ----
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}


def _roundup(x: float) -> float:
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def base_score(vector: str) -> float:
    """Compute the CVSS 3.1 base score from a vector string (metrics only)."""
    m = {}
    for part in vector.split("/"):
        if ":" in part:
            k, v = part.split(":", 1)
            m[k] = v
    try:
        scope_changed = m["S"] == "C"
        pr = (_PR_C if scope_changed else _PR_U)[m["PR"]]
        exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]
        iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        else:
            impact = 6.42 * iss
        if impact <= 0:
            return 0.0
        raw = (1.08 if scope_changed else 1.0) * (impact + exploitability)
        return _roundup(min(raw, 10.0))
    except (KeyError, ValueError):
        return 0.0


def risk_label(score: float) -> str:
    if score == 0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


# ---- finding class -> CVSS vector ----
_SEV_FALLBACK = {
    Severity.INFO: None,
    Severity.LOW: "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
    Severity.MEDIUM: "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    Severity.HIGH: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    Severity.CRITICAL: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
}


def _vector(f: Finding) -> Optional[str]:
    t = set(f.tags)
    title = f.title.lower()

    def has(*x):
        return any(k in t for k in x)

    if has("ssti") or (has("rce") and has("unauth")):
        return "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"        # 9.8
    if has("rce"):
        return "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"        # 8.8
    if has("sqli"):
        return "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"        # 8.6
    if has("lfi"):
        return "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"        # 7.5
    if has("default-creds", "auth-bypass"):
        return "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"        # 9.8
    if has("bac", "idor"):
        if "without auth" in title or "missing auth" in title:
            return "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"    # 7.5
        return "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"        # 6.5
    if has("secrets", "source-leak"):
        return "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"        # 7.5
    if has("xss"):
        return "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"        # 6.1
    if has("open-redirect"):
        return "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N"        # 4.7
    if has("cors"):
        return "AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N"        # 6.8
    if has("data") and has("unauth"):
        return "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"        # 7.5
    if has("jwt"):
        # weak-secret / alg=none are tagged auth-bypass and handled above;
        # what's left (no-exp, sensitive-claims) is genuinely Low, not submittable.
        return "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"        # 3.7
    if has("headers", "cookies", "cleartext"):
        return "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"        # 3.1
    if f.category == "recon":
        return None
    return _SEV_FALLBACK[f.severity]


_REMEDIATION = [
    (("ssti",), "Never render user input as a template. Use logic-less, sandboxed "
                "templates and strict input validation."),
    (("sqli",), "Use parameterised queries / prepared statements everywhere and a "
                "least-privilege database account."),
    (("lfi",), "Never build filesystem paths from user input. Allow-list filenames, "
               "canonicalise, and disable remote/URL includes."),
    (("rce",), "Remove the code-execution sink and upgrade to a patched release; "
               "run the service sandboxed with least privilege."),
    (("default-creds",), "Change all default credentials, enforce strong unique "
                         "passwords, and require MFA on admin interfaces."),
    (("auth-bypass", "jwt"), "Rotate the signing secret to a long random value; "
                             "verify the algorithm server-side, reject alg=none, "
                             "and enforce exp."),
    (("bac", "idor"), "Enforce object-level authorization on every request "
                      "server-side; never trust client-supplied identifiers."),
    (("open-redirect",), "Allow-list redirect destinations or map them to server-side "
                        "identifiers; never redirect to a raw user-supplied URL."),
    (("cors",), "Do not reflect the Origin header with credentials; use a strict "
                "server-side allow-list of trusted origins."),
    (("secrets", "source-leak"), "Remove the exposed file from the web root, block "
                                 "dotfiles/backup extensions, and rotate any leaked "
                                 "secret immediately."),
    (("xss",), "Apply context-aware output encoding, a strong Content-Security-Policy, "
               "and HttpOnly session cookies."),
    (("unauth",), "Require authentication and bind the service to localhost or behind "
                  "a firewall / allow-list."),
    (("headers",), "Add Content-Security-Policy, Strict-Transport-Security, "
                   "X-Content-Type-Options and X-Frame-Options."),
    (("cookies",), "Set HttpOnly, Secure and SameSite on all session cookies."),
    (("cleartext",), "Disable the cleartext protocol; use its TLS variant."),
]


def _remediation(f: Finding) -> str:
    tags = set(f.tags)
    for keys, text in _REMEDIATION:
        if tags.intersection(keys):
            return text
    if f.cve:
        return "Upgrade to a fixed release as described in the referenced CVE."
    return "Validate and encode all input, apply least privilege, and keep the "\
           "component patched."


def assess(f: Finding) -> Dict:
    vector = _vector(f)
    score = base_score(vector) if vector else 0.0
    risk = risk_label(score)
    strong = f.verified or f.confidence >= Confidence.LIKELY or bool(f.cve)
    submittable = bool(vector) and score >= 4.0 and f.category != "recon" and strong
    return {
        "cvss_vector": ("CVSS:3.1/" + vector) if vector else "",
        "cvss_score": score,
        "risk": risk,
        "submittable": submittable,
        "remediation": _remediation(f),
    }
