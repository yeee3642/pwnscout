"""Offline unit tests — no network, no external tools required."""

from __future__ import annotations

from pwnscout.core.model import (Confidence, Finding, Host, ScanResult, Service,
                                 Severity)
from pwnscout.core.utils import expand_targets
from pwnscout.enum.http import _path_hit
from pwnscout.core.utils import HttpResponse
from pwnscout.exploit.runner import Exploit
from pwnscout.kb import loader
from pwnscout.scan.ports import parse_ports
from pwnscout import report


def test_expand_targets_cidr_range_dedup():
    out = expand_targets(["10.0.0.0/30", "192.168.1.5-7", "10.0.0.1"])
    assert out == ["10.0.0.1", "10.0.0.2", "192.168.1.5", "192.168.1.6", "192.168.1.7"]


def test_parse_ports():
    assert parse_ports("80,443,8000-8002") == [80, 443, 8000, 8001, 8002]
    assert len(parse_ports(None, "full")) == 65535
    assert 80 in parse_ports(None, "web")


def test_version_key_and_compare():
    assert loader.version_key("2.4.49") == (2, 4, 49)
    assert loader.version_key("7.6p1") == (7, 6, 1)


def test_match_service_exact_and_range():
    hits = loader.match_service("vsftpd", "2.3.4", "220 (vsFTPd 2.3.4)", 21)
    assert any(h.get("cve") == "CVE-2011-2523" for h in hits)
    # OpenSSH 7.4 is < 7.7 -> user-enum rule fires
    ssh = loader.match_service("OpenSSH", "7.4", "SSH-2.0-OpenSSH_7.4", 22)
    assert any(h.get("cve") == "CVE-2018-15473" for h in ssh)
    # OpenSSH 8.0 is not < 7.7 -> rule does not fire
    ssh2 = loader.match_service("OpenSSH", "8.0", "SSH-2.0-OpenSSH_8.0", 22)
    assert not any(h.get("cve") == "CVE-2018-15473" for h in ssh2)


def test_finding_score_ordering():
    crit_conf = Finding("h", "s", "t", severity=Severity.CRITICAL,
                        confidence=Confidence.CONFIRMED, verified=True, tags=["rce"])
    low_poss = Finding("h", "s", "t2", severity=Severity.LOW,
                       confidence=Confidence.POSSIBLE)
    assert crit_conf.score == 100
    assert crit_conf.score > low_poss.score
    assert low_poss.score < 30


def _resp(status, body, headers=None):
    return HttpResponse("u", status, headers or {}, body, "u")


def test_path_hit_positive_signal():
    entry = {"path": "/.git/HEAD", "match": {"status": [200], "body_contains": ["ref:"]}}
    assert _path_hit(_resp(200, "ref: refs/heads/main"), entry, _resp(404, "nope"))
    assert not _path_hit(_resp(200, "totally unrelated"), entry, _resp(404, "nope"))


def test_path_hit_soft404_guard():
    # No body signal required, and the response mirrors the baseline -> reject.
    entry = {"path": "/whatever", "match": {"status": [200]}}
    baseline = _resp(200, "X" * 500)
    assert not _path_hit(_resp(200, "X" * 505), entry, baseline)
    # A clearly different length passes.
    assert _path_hit(_resp(200, "Y" * 50), entry, baseline)


def test_exploit_find_flag():
    ctx = {"flag_regex": None}
    assert Exploit.find_flag("junk FLAG{abc_123} junk", ctx) == "FLAG{abc_123}"
    assert Exploit.find_flag("no flag here", ctx) is None


def test_payloads_and_wordlist_load():
    pl = loader.payloads()
    assert pl["ssti"] and pl["sqli_errors"] and pl["xss"]
    assert len(loader.wordlist()) > 100


class _FakeSession:
    """In-process vulnerable app: reflects input (XSS), evals {{7*7}} (SSTI),
    and errors on a quote (SQLi). Lets us test probes with no network."""
    headers: dict = {}

    def _render(self, value: str) -> str:
        body = f"page echo: {value}".replace("{{7*7}}", "49")
        if "'" in value or '"' in value:
            body += " -- SQL syntax error near your MySQL server"
        return body

    def _val(self, url_or_data):
        from urllib.parse import parse_qs, urlparse
        qs = parse_qs(urlparse(url_or_data).query or url_or_data)
        return next(iter(qs.values()), [""])[0]

    def get(self, url, extra_headers=None):
        return HttpResponse(url, 200, {}, self._render(self._val(url)), url)

    def request(self, url, method="GET", data=None, extra_headers=None):
        if data:
            return HttpResponse(url, 200, {}, self._render(self._val(data.decode())), url)
        return self.get(url, extra_headers)


def test_crawler_extracts_points():
    from pwnscout.web.crawler import crawl

    html = ("<a href='/search?q=x'>s</a>"
            "<form action='/login' method='post'>"
            "<input name='user'><input name='pass'></form>")

    class S:
        headers = {}
        def get(self, url, extra_headers=None):
            body = html if url.rstrip("/").endswith("8903") else ""
            return HttpResponse(url, 200, {"content-type": "text/html"}, body, url)
        def request(self, *a, **k):
            return self.get(a[0])

    res = crawl(S(), "http://127.0.0.1:8903/", depth=1, max_pages=10)
    names = {p.source for p in res.points}
    params = {k for p in res.points for k in p.params}
    assert "form" in names and "q" in params and "user" in params


def test_probes_detect_xss_ssti_sqli():
    from types import SimpleNamespace
    from pwnscout.web.crawler import InjectionPoint
    from pwnscout.web.probes import probe_points

    point = InjectionPoint("GET", "http://t/search", {"q": "x"}, "url")
    opts = SimpleNamespace(probe_budget=1500, max_points=40)
    findings = probe_points(_FakeSession(), [point], opts)
    tags = {t for f in findings for t in f.tags}
    assert "ssti" in tags and "xss" in tags and "sqli" in tags


def test_login_form_detection():
    from pwnscout.web.auth import find_login_form

    html = ("<form action='/login' method='post'>"
            "<input type='hidden' name='csrf' value='t0k'>"
            "<input type='text' name='username'>"
            "<input type='password' name='pw'></form>")
    form = find_login_form(html, "http://x/login")
    assert form and form.pass_field == "pw" and form.user_field == "username"
    assert form.fields.get("csrf") == "t0k"   # hidden CSRF carried through


def test_jwt_crack_and_analyze():
    import base64, hashlib, hmac, json
    from pwnscout.web import jwt as jwtmod

    def seg(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

    h, p = seg({"alg": "HS256", "typ": "JWT"}), seg({"user": "admin", "role": "admin"})
    sig = base64.urlsafe_b64encode(
        hmac.new(b"secret", f"{h}.{p}".encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    token = f"{h}.{p}.{sig}"
    assert jwtmod.crack_hmac(token, ["nope", "secret"]) == "secret"
    titles = " ".join(f.title for f in jwtmod.analyze(token, "src", "h", 80, ["secret"]))
    assert "weak HMAC secret" in titles and "no exp" in titles


def test_exploit_gen_writes_runnable_modules(tmp_path):
    import py_compile
    from pwnscout.web import exploit_gen

    h = Host(ip="10.0.0.9")
    h.add(Finding("10.0.0.9", "http", "SSTI", port=80, severity=Severity.CRITICAL,
                  confidence=Confidence.CONFIRMED, verified=True, tags=["ssti"],
                  exploit={"kind": "ssti", "method": "GET",
                           "url": "http://10.0.0.9/s", "param": "q",
                           "engine": "Jinja2"}))
    h.add(Finding("10.0.0.9", "http", "LFI", port=80, severity=Severity.HIGH,
                  confidence=Confidence.CONFIRMED, verified=True, tags=["lfi"],
                  exploit={"kind": "lfi", "method": "GET",
                           "url": "http://10.0.0.9/p", "param": "file"}))
    res = ScanResult(hosts=[h])
    files = exploit_gen.generate(res, str(tmp_path))
    py = [f for f in files if f.endswith(".py")]
    assert len(py) == 2
    for f in py:
        py_compile.compile(f, doraise=True)       # generated code is valid python
        assert "class Module" in open(f, encoding="utf-8").read()
    assert any(f.endswith("EXPLOIT_PLAN.md") for f in files)


def test_numeric_idor_detects_and_ignores_reflection():
    from urllib.parse import parse_qs, urlparse
    from pwnscout.web.authz import _numeric_idor
    from pwnscout.web.crawler import InjectionPoint

    def _id(url):
        return (parse_qs(urlparse(url).query).get("id") or ["0"])[0]

    class OrderSession:      # object lookup: distinct record per id, 404 for bogus
        timeout = 8
        def get(self, url, extra_headers=None):
            v = _id(url)
            n = int(v) if v.isdigit() else -1
            if 1 <= n <= 100000:
                return HttpResponse(
                    url, 200, {},
                    f"<html><body>Order #{n} — customer {n}, total ${n*7}</body></html>",
                    url)
            return HttpResponse(url, 404, {}, "<html><body>no such order</body></html>", url)
        def request(self, url, method="GET", data=None, extra_headers=None):
            return self.get(url)

    class EchoSession:       # reflective param — must NOT be flagged as IDOR
        timeout = 8
        def get(self, url, extra_headers=None):
            return HttpResponse(url, 200, {}, f"you searched for {_id(url)}", url)
        def request(self, url, method="GET", data=None, extra_headers=None):
            return self.get(url)

    pt = InjectionPoint("GET", "http://t/api/order", {"id": "1000"}, "url")
    hits = _numeric_idor(OrderSession(), [(pt, "id")])
    assert any("IDOR" in f.title for f in hits)

    pt2 = InjectionPoint("GET", "http://t/search", {"id": "1000"}, "url")
    assert _numeric_idor(EchoSession(), [(pt2, "id")]) == []


def test_cvss_and_submittability():
    from pwnscout.report.assess import assess, base_score

    # CVSS 3.1 base score matches the reference for a canonical RCE vector.
    assert base_score("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8

    ssti = Finding("h", "http", "SSTI", port=80, severity=Severity.CRITICAL,
                   confidence=Confidence.CONFIRMED, verified=True, tags=["ssti", "rce"])
    a = assess(ssti)
    assert a["cvss_score"] == 9.8 and a["risk"] == "Critical" and a["submittable"]
    assert a["remediation"]

    # A recon lead (content discovery) is NOT submittable.
    lead = Finding("h", "http", "Content discovered: /admin", port=80,
                   severity=Severity.LOW, confidence=Confidence.CONFIRMED,
                   verified=True, category="recon", tags=["content-discovery"])
    assert assess(lead)["submittable"] is False

    # A low-value JWT informational finding is NOT submittable.
    jwt_info = Finding("h", "http", "JWT has no exp claim", port=80,
                       severity=Severity.LOW, confidence=Confidence.LIKELY, tags=["jwt"])
    assert assess(jwt_info)["cvss_score"] < 4.0
    assert assess(jwt_info)["submittable"] is False


def test_oob_listener_records_callback():
    import time
    import urllib.request
    from pwnscout.web.ssrf import OOBListener, _local_ip

    lst = OOBListener(port=0)
    lst.start()
    try:
        try:
            urllib.request.urlopen(
                f"http://127.0.0.1:{lst.port}/tok_abc123", timeout=3).read()
        except Exception:
            pass
        time.sleep(0.3)
        hits = lst.hits()
    finally:
        lst.stop()
    assert any("tok_abc123" in (path or "") for _peer, path, _raw in hits)
    assert _local_ip("127.0.0.1")  # returns some address string


def test_report_renders():
    h = Host(ip="10.0.0.5", services=[Service(port=80, name="http")])
    h.add(Finding("10.0.0.5", "http", "Exposed .env", port=80,
                  severity=Severity.CRITICAL, confidence=Confidence.CONFIRMED,
                  verified=True, why="secrets", next_step="curl x"))
    res = ScanResult(hosts=[h], started="a", finished="b")
    assert "Exposed .env" in report.to_terminal(res)
    assert '"findings"' in report.to_json(res)
    assert "Exposed .env" in report.to_markdown(res)
    assert "<table>" in report.to_html(res)
