"""JWT discovery and weakness analysis (offline).

Finds JWTs in responses, cookies and headers, decodes them, and flags:
  * alg=none acceptance risk
  * weak HMAC secret (cracked against a bundled wordlist -> token forgery)
  * RS/ES -> HS algorithm-confusion opportunity
  * missing/expired exp, and sensitive claims worth tampering
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from typing import Dict, List, Optional
from urllib.parse import urlparse

from ..core.model import Confidence, Finding, Severity
from ..kb import loader
from .session import Session

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*")
_SENSITIVE_CLAIM = re.compile(r"admin|role|is_?admin|priv|scope|group|superuser|"
                              r"is_?staff|permission", re.I)
_HASH = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


def _b64d(seg: str) -> bytes:
    seg += "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg)


def _host_port(url: str):
    p = urlparse(url)
    return (p.hostname or url), (p.port or (443 if p.scheme == "https" else 80))


def decode(token: str) -> Optional[Dict]:
    try:
        h, p, _sig = token.split(".")
        header = json.loads(_b64d(h))
        payload = json.loads(_b64d(p))
        return {"header": header, "payload": payload}
    except Exception:
        return None


def crack_hmac(token: str, secrets: List[str]) -> Optional[str]:
    try:
        h, p, sig = token.split(".")
        header = json.loads(_b64d(h))
    except Exception:
        return None
    alg = header.get("alg", "")
    fn = _HASH.get(alg)
    if not fn:
        return None
    signing_input = f"{h}.{p}".encode()
    for secret in secrets:
        mac = hmac.new(secret.encode(), signing_input, fn).digest()
        want = base64.urlsafe_b64encode(mac).rstrip(b"=").decode()
        if hmac.compare_digest(want, sig):
            return secret
    return None


def analyze(token: str, source: str, host: str, port: int,
            secrets: Optional[List[str]] = None) -> List[Finding]:
    dec = decode(token)
    if not dec:
        return []
    header, payload = dec["header"], dec["payload"]
    alg = str(header.get("alg", "")).upper()
    out: List[Finding] = []
    short = token[:24] + "…"
    if secrets is None:
        secrets = loader.jwt_secrets()

    def mk(title, sev, conf, why, nxt, tags, verified=False):
        return Finding(target=host, port=port, service="http", title=title,
                       severity=sev, confidence=conf, verified=verified,
                       category="known-cve" if "forg" in why else "misconfig",
                       evidence=f"{source}: alg={alg} {short}", why=why,
                       next_step=nxt, tags=tags)

    if alg == "NONE":
        out.append(mk("JWT alg=none", Severity.HIGH, Confidence.LIKELY,
                      "Token uses alg=none — if the server accepts it you forge "
                      "any identity with no signature.",
                      "Re-sign with alg=none and empty signature; replay to a "
                      "protected endpoint.", ["jwt", "auth-bypass"]))

    if alg in _HASH:
        secret = crack_hmac(token, secrets)
        if secret:
            out.append(mk(f"JWT weak HMAC secret: '{secret}'",
                          Severity.CRITICAL, Confidence.CONFIRMED,
                          f"Signing secret cracked ('{secret}') — forge tokens "
                          "for any user/role (full auth bypass).",
                          f"# forge with the recovered secret '{secret}' (jwt_tool / pyjwt)",
                          ["jwt", "auth-bypass"], verified=True))

    if alg.startswith(("RS", "ES", "PS")):
        out.append(mk("JWT RS/ES — algorithm-confusion candidate",
                      Severity.MEDIUM, Confidence.POSSIBLE,
                      "Asymmetric alg: if the public key is obtainable, an RS256->"
                      "HS256 confusion may let you sign tokens with it.",
                      "Fetch the public key (JWKS/cert) and try HS256 signing "
                      "with it as the secret (jwt_tool -X k).", ["jwt"]))

    if "exp" not in payload:
        out.append(mk("JWT has no exp claim", Severity.LOW, Confidence.LIKELY,
                      "No expiry — a stolen token is valid forever.",
                      "# note for report; combine with any forgery finding",
                      ["jwt"]))

    hits = [k for k in payload if _SENSITIVE_CLAIM.search(str(k))]
    if hits:
        out.append(mk(f"JWT sensitive claims: {', '.join(hits[:4])}",
                      Severity.INFO, Confidence.LIKELY,
                      "Authorization data lives in the token — a prime tamper "
                      "target if signing is ever bypassed.",
                      "# if you crack/forge, flip these claims to escalate",
                      ["jwt"]))
    return out


def collect_and_scan(session: Session, root: str, root_resp,
                     extra_urls: Optional[List[str]] = None,
                     secrets: Optional[List[str]] = None) -> List[Finding]:
    host, port = _host_port(root)
    if secrets is None:
        secrets = loader.jwt_secrets()
    tokens: Dict[str, str] = {}   # token -> source

    def harvest(text: str, source: str):
        for m in _JWT_RE.findall(text or ""):
            tokens.setdefault(m, source)

    harvest(root_resp.body, "response body")
    for c in root_resp.set_cookies or []:
        harvest(c, "Set-Cookie")
    for k, v in session.jar.items():
        harvest(v, f"cookie {k}")
    harvest(session.headers.get("Authorization", ""), "Authorization header")

    for url in (extra_urls or [])[:8]:
        r = session.get(url)
        harvest(r.body, f"body {url}")
        for c in r.set_cookies or []:
            harvest(c, "Set-Cookie")

    out: List[Finding] = []
    for token, source in tokens.items():
        out.extend(analyze(token, source, host, port, secrets))
    return out
