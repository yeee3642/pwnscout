"""Command-line interface.

    pwnscout scan 10.10.10.0/24 --verify -o loot/run1
    pwnscout scan target.txt --profile full --nmap
    pwnscout exploit ./acme.py --targets enemies.txt --port 8080 --loop 30
    pwnscout kb
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from typing import List, Optional

from . import __version__
from .core import integrations
from .core.utils import color, disable_color, expand_targets, http_request


def _add_scan(sub) -> None:
    p = sub.add_parser("scan", help="recon + enumerate + list what you can hit")
    p.add_argument("targets", nargs="+",
                   help="IP / CIDR / host / a.b.c.d-e range / @file / file path")
    p.add_argument("-p", "--ports", help="e.g. 80,443,8000-8100 (overrides --profile)")
    p.add_argument("--profile", choices=["top", "web", "full"], default="top",
                   help="port set when -p is not given (default: top)")
    p.add_argument("--concurrency", type=int, default=400, help="port-scan sockets")
    p.add_argument("--timeout", type=float, default=2.0, help="port connect timeout (s)")
    p.add_argument("--http-timeout", type=float, default=8.0, dest="http_timeout")
    p.add_argument("--enum-workers", type=int, default=40, dest="enum_workers")
    p.add_argument("--verify", action="store_true",
                   help="run safe active PoCs (anon FTP, unauth Redis/Docker/ES…)")
    p.add_argument("--brute", action="store_true",
                   help="also try a tiny set of default creds (HTTP Basic/Tomcat)")
    p.add_argument("--nmap", action="store_true", dest="use_nmap",
                   help="enrich versions with nmap -sV if nmap is installed")
    p.add_argument("-o", "--out", help="write report to OUT.json/.md/.html")
    p.add_argument("--min-score", type=int, default=0, dest="min_score",
                   help="hide findings below this attack score (0-100)")
    p.add_argument("--top", type=int, default=0, help="show only the top N findings")
    p.add_argument("--no-color", action="store_true", dest="no_color")
    p.add_argument("--quiet", action="store_true", help="suppress progress on stderr")


def _add_exploit(sub) -> None:
    p = sub.add_parser("exploit", help="fire an exploit module across many targets (A/D)")
    p.add_argument("module", help="path to your exploit .py (defines Module(Exploit))")
    p.add_argument("--targets", nargs="+", required=True, help="IPs / @file")
    p.add_argument("--port", type=int, help="override module default_port")
    p.add_argument("--threads", type=int, default=16)
    p.add_argument("--flag-regex", dest="flag_regex", help="regex to extract the flag")
    p.add_argument("--submit-url", dest="submit_url",
                   help="POST captured flags here as form field 'flag'")
    p.add_argument("--loop", type=int, default=0,
                   help="repeat every N seconds (A/D tick); 0 = run once")
    p.add_argument("--no-color", action="store_true", dest="no_color")


def _add_web(sub) -> None:
    p = sub.add_parser("web",
                       help="deep web assessment: crawl + discover + safe active probes")
    p.add_argument("targets", nargs="+", help="app URL(s) or host (http:// assumed)")
    p.add_argument("--no-crawl", action="store_false", dest="crawl",
                   help="skip crawling (probe only the URLs given)")
    p.add_argument("--depth", type=int, default=2, help="crawl depth (default 2)")
    p.add_argument("--max-pages", type=int, default=200, dest="max_pages")
    p.add_argument("--discover", action="store_true",
                   help="run wordlist content discovery")
    p.add_argument("--wordlist", help="content-discovery wordlist (default: bundled)")
    p.add_argument("--ext", default="",
                   help="extensions to append in discovery, e.g. php,bak,txt,zip")
    p.add_argument("--no-probe", action="store_false", dest="probe",
                   help="skip active vuln probes (crawl/discover only)")
    p.add_argument("--probe-budget", type=int, default=1500, dest="probe_budget",
                   help="max probe requests (guards against huge apps)")
    p.add_argument("--max-points", type=int, default=40, dest="max_points",
                   help="max injection points to probe")
    p.add_argument("--cookie", help="Cookie header for authenticated scans")
    p.add_argument("--header", action="append", metavar="'K: V'",
                   help="extra request header (repeatable)")
    p.add_argument("--auth-basic", dest="auth_basic", help="user:pass for HTTP Basic")
    # auto-login (form based)
    p.add_argument("--login-url", dest="login_url",
                   help="login page URL — auto-detect the form and log in first")
    p.add_argument("--login-user", dest="login_user", help="username for auto-login")
    p.add_argument("--login-pass", dest="login_pass", help="password for auto-login")
    p.add_argument("--login-data", dest="login_data",
                   help="raw login body, e.g. 'user=admin&pass=secret' (overrides fields)")
    p.add_argument("--login-check", dest="login_check",
                   help="regex that, if present after login, means success")
    # JWT
    p.add_argument("--no-jwt", action="store_false", dest="jwt",
                   help="skip JWT discovery/analysis")
    p.add_argument("--jwt-wordlist", dest="jwt_wordlist",
                   help="secret wordlist for JWT HMAC cracking (default: bundled)")
    # access control / IDOR
    p.add_argument("--no-idor", action="store_false", dest="idor",
                   help="skip access-control / IDOR checks")
    p.add_argument("--cookie2", dest="cookie2",
                   help="a second user's Cookie — enables cross-user IDOR comparison")
    # exploit generation
    p.add_argument("--gen-exploits", dest="gen_exploits", metavar="DIR",
                   help="write runnable exploit modules for confirmed SSTI/LFI/SQLi")
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--http-timeout", type=float, default=8.0, dest="http_timeout")
    p.add_argument("--delay", type=float, default=0.0,
                   help="seconds between requests (be polite / evade rate limits)")
    p.add_argument("--threads", type=int, default=30, help="content-discovery threads")
    p.add_argument("-o", "--out", help="write report to OUT.json/.md/.html")
    p.add_argument("--min-score", type=int, default=0, dest="min_score")
    p.add_argument("--top", type=int, default=0)
    p.add_argument("--no-color", action="store_true", dest="no_color")
    p.add_argument("--quiet", action="store_true")
    p.set_defaults(crawl=True, probe=True, jwt=True, idor=True)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="pwnscout",
        description="Offline attack-surface & exploitability scanner. No AI, no cloud.",
    )
    ap.add_argument("--version", action="version", version=f"pwnscout {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    _add_scan(sub)
    _add_web(sub)
    _add_exploit(sub)
    sub.add_parser("kb", help="show knowledge-base stats and detected tools")
    return ap


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------
def cmd_scan(opts) -> int:
    from .engine import run_scan
    from . import report

    if opts.no_color:
        disable_color()
        os.environ["NO_COLOR"] = "1"

    result = run_scan(opts)
    sys.stdout.write(report.to_terminal(result, min_score=opts.min_score, top=opts.top))
    sys.stdout.write("\n")

    if opts.out:
        base = opts.out
        _write(base + ".json", report.to_json(result))
        _write(base + ".md", report.to_markdown(result))
        _write(base + ".html", report.to_html(result))
        sys.stderr.write(color(f"[*] reports written: {base}.json/.md/.html\n", "cyan"))

    crit_high = sum(1 for f in result.findings
                    if f.severity.label in ("critical", "high"))
    return 0 if crit_high == 0 else 2  # non-zero exit if hot findings (CI-friendly)


def cmd_web(opts) -> int:
    from .web import web_scan
    from . import report

    if opts.no_color:
        disable_color()
        os.environ["NO_COLOR"] = "1"

    log = None if opts.quiet else (lambda m: sys.stderr.write(m + "\n"))
    result = web_scan(opts.targets, opts, log=log)

    sys.stdout.write(report.to_terminal(result, min_score=opts.min_score, top=opts.top))
    sys.stdout.write("\n")

    if opts.out:
        base = opts.out
        _write(base + ".json", report.to_json(result))
        _write(base + ".md", report.to_markdown(result))
        _write(base + ".html", report.to_html(result))
        sys.stderr.write(color(f"[*] reports written: {base}.json/.md/.html\n", "cyan"))

    crit_high = sum(1 for f in result.findings
                    if f.severity.label in ("critical", "high"))
    return 0 if crit_high == 0 else 2


def cmd_exploit(opts) -> int:
    from .exploit import load_module, run_campaign
    from .exploit.runner import ExploitResult

    if opts.no_color:
        disable_color()

    try:
        module = load_module(opts.module)
    except Exception as exc:
        sys.stderr.write(color(f"[!] cannot load module: {exc}\n", "red"))
        return 1

    targets = expand_targets(opts.targets)
    submit = _make_submitter(opts.submit_url) if opts.submit_url else None

    def _on(res: ExploitResult) -> None:
        if res.ok:
            tag = color("FLAG", "bgreen")
            sent = color(" [submitted]", "cyan") if res.submitted else ""
            sys.stdout.write(f"  {tag} {res.target} -> {res.flag}{sent}\n")
        elif res.error:
            sys.stderr.write(color(f"  err  {res.target}: {res.error}\n", "grey"))

    sys.stderr.write(color(
        f"[*] module '{module.name}' vs {len(targets)} target(s)"
        f"{' (looping every %ds)' % opts.loop if opts.loop else ''}\n", "cyan"))

    tick = 0
    while True:
        tick += 1
        if opts.loop:
            sys.stderr.write(color(f"[*] tick {tick} — {time.strftime('%H:%M:%S')}\n", "grey"))
        camp = run_campaign(module, targets, port=opts.port, threads=opts.threads,
                            flag_regex=opts.flag_regex, submit=submit, on_result=_on)
        sys.stderr.write(color(
            f"[*] {camp.wins}/{camp.total} flags this run\n", "green"))
        if not opts.loop:
            break
        try:
            time.sleep(opts.loop)
        except KeyboardInterrupt:
            break
    return 0


def cmd_kb(_opts) -> int:
    from .kb import loader
    pl = loader.payloads()
    print(color("pwnscout knowledge base", "bold"))
    print(f"  vulndb entries    : {len(loader.vulndb())}")
    print(f"  http path checks  : {len(loader.http_paths())}")
    print(f"  web fingerprints  : {len(loader.fingerprints())}")
    print(f"  default-cred sets : {len(loader.default_creds())}")
    print(f"  web wordlist      : {len(loader.wordlist())}")
    print(f"  jwt secrets       : {len(loader.jwt_secrets())}")
    print(f"  probe payloads    : ssti {len(pl.get('ssti', []))}, "
          f"sqli-sigs {len(pl.get('sqli_errors', []))}, "
          f"traversal {len(pl.get('traversal', {}).get('payloads', []))}")
    print(color("\nexternal tools detected:", "bold"))
    for tool, ok in integrations.available().items():
        mark = color("yes", "green") if ok else color("no", "grey")
        print(f"  {tool:<12}: {mark}")
    if os.environ.get("PWNSCOUT_KB"):
        print(color(f"\nextra KB dir: {os.environ['PWNSCOUT_KB']}", "cyan"))
    return 0


# ---------------------------------------------------------------------------
def _write(path: str, text: str) -> None:
    d = os.path.dirname(os.path.abspath(path))
    if d and not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _make_submitter(url: str):
    from urllib.parse import urlencode

    def submit(target: str, flag: str) -> bool:
        r = http_request(url, method="POST",
                         headers={"Content-Type": "application/x-www-form-urlencoded"},
                         data=urlencode({"flag": flag}).encode())
        body = (r.body or "").lower()
        return r.status == 200 and not any(w in body for w in ("wrong", "invalid", "incorrect"))
    return submit


def _force_utf8() -> None:
    # Windows consoles default to legacy code pages (cp950/cp1252) that choke on
    # the report's box glyphs. UTF-8 with replace keeps output readable anywhere.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def main(argv: Optional[List[str]] = None) -> int:
    _force_utf8()
    ap = build_parser()
    opts = ap.parse_args(argv)
    try:
        if opts.cmd == "scan":
            return cmd_scan(opts)
        if opts.cmd == "web":
            return cmd_web(opts)
        if opts.cmd == "exploit":
            return cmd_exploit(opts)
        if opts.cmd == "kb":
            return cmd_kb(opts)
    except KeyboardInterrupt:
        sys.stderr.write("\n[!] interrupted\n")
        return 130
    ap.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
