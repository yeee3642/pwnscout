"""Form-based auto-login for authenticated scans.

Give it a login URL and credentials; it finds the login form (carrying any
hidden CSRF token), submits, and leaves the Session holding the authenticated
cookies so the crawler and probes run as a logged-in user.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin

from .crawler import _FORM_RE, _INPUT_RE, _NAME_RE, _VALUE_RE
from .session import Session

_TYPE_RE = re.compile(r"""type\s*=\s*['"]?(\w+)""", re.I)
_USER_HINT = re.compile(r"user|email|login|name|account|uid", re.I)


@dataclass
class LoginForm:
    action: str
    method: str
    fields: Dict[str, str]
    user_field: Optional[str]
    pass_field: Optional[str]


def find_login_form(html: str, page_url: str) -> Optional[LoginForm]:
    for attrs, inner in _FORM_RE.findall(html):
        fields: Dict[str, str] = {}
        pass_field = None
        user_candidates = []
        for iattr in _INPUT_RE.findall(inner):
            nm = _NAME_RE.search(iattr)
            if not nm:
                continue
            name = nm.group(1)
            val = _VALUE_RE.search(iattr)
            fields[name] = val.group(1) if val else ""
            itype = (_TYPE_RE.search(iattr) or [None, "text"])[1].lower()
            if itype == "password":
                pass_field = name
            elif itype in ("text", "email", ""):
                user_candidates.append(name)
        if not pass_field:
            continue  # not a login form
        user_field = next((n for n in user_candidates if _USER_HINT.search(n)),
                          user_candidates[0] if user_candidates else None)
        action = _attr("action", attrs) or page_url
        method = (_attr("method", attrs) or "POST").upper()
        return LoginForm(urljoin(page_url, action), method, fields,
                         user_field, pass_field)
    return None


def _attr(name: str, s: str) -> str:
    m = re.search(rf"""{name}\s*=\s*['"]?([^'"\s>]+)""", s, re.I)
    return m.group(1) if m else ""


def login(session: Session, login_url: str, user: Optional[str] = None,
          password: Optional[str] = None, login_data: Optional[str] = None,
          check: Optional[str] = None) -> Tuple[bool, str]:
    """Perform the login. Returns (success, evidence)."""
    page = session.get(login_url)
    if page.status == 0:
        return False, f"login page unreachable: {page.error}"

    form = find_login_form(page.body, login_url)
    data: Dict[str, str] = {}
    action = login_url
    method = "POST"
    if form:
        data.update(form.fields)                 # keep hidden/CSRF fields
        action, method = form.action, form.method

    # Overlay caller-supplied credentials.
    if login_data:
        data.update(dict(parse_qsl(login_data, keep_blank_values=True)))
    else:
        if form and form.user_field and user is not None:
            data[form.user_field] = user
        if form and form.pass_field and password is not None:
            data[form.pass_field] = password
        if not form and user is not None:
            # blind guess when no form was parseable
            data.setdefault("username", user)
            data.setdefault("password", password or "")

    if not data:
        return False, "no login form or --login-data given"

    if method == "POST":
        resp = session.request(
            action, "POST", data=urlencode(data).encode(),
            extra_headers={"Content-Type": "application/x-www-form-urlencoded"})
    else:
        resp = session.get(action + "?" + urlencode(data))

    # Success determination.
    if check:
        ok = bool(re.search(check, resp.body))
        return ok, f"check '{check}' {'matched' if ok else 'not found'} (HTTP {resp.status})"

    # Heuristics: got a session cookie, redirected, or the login form is gone.
    got_cookie = bool(session.jar)
    redirected = resp.status in (301, 302, 303, 307)
    form_gone = "password" not in resp.body.lower() and resp.status == 200
    ok = got_cookie or redirected or form_gone
    ev = (f"HTTP {resp.status}"
          + (f", cookies: {','.join(session.jar)}" if got_cookie else "")
          + (", redirected" if redirected else "")
          + (", login form gone" if form_gone and not redirected else ""))
    return ok, ev
