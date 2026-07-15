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
