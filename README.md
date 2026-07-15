# pwnscout

**Offline attack-surface & exploitability scanner. No AI. No cloud. No telemetry.**

Point it at targets, run it, and get a **ranked list of what you can actually hit** —
each finding tells you *what* is wrong, *why it's exploitable*, and *the exact command to run next*.

Built to be thrown on a competition laptop (CTF Attack/Defense, red-team lab, boot2root
range) and just work: it runs on a stock `python3` with **zero pip dependencies**, and it
never phones home. If Kali tools like `nmap`, `smbclient` or `searchsploit` happen to be on
the box, it uses them; if not, it falls back to its own pure-Python implementations.

```
  pwnscout — attack surface report
  hosts 1/1 up · 1 services · 4 findings (3 verified)
  CRIT:1  HIGH:1  LOW:1  INFO:1

  WHAT YOU CAN HIT  (ranked by exploitability)
  ────────────────────────────────────────────────────────────────────
  100 ██████████ [CRIT] 10.0.0.5:8080  Exposed .env file ✓verified
       why: Framework .env files hold DB credentials, API keys and app secrets…
       run: curl -s http://10.0.0.5:8080/.env

   86 █████████· [HIGH] 10.0.0.5:8080  Exposed .git repository ✓verified
       why: The .git directory is web-reachable — dump it to recover full source…
       run: git-dumper http://10.0.0.5:8080/.git/ loot_git && …
```

---

## ⚖️ Authorized use only

pwnscout is for **systems you own or have explicit written permission to test** (CTF
competition, lab range, sanctioned engagement, bug-bounty scope). Unauthorized scanning or
exploitation is illegal in most jurisdictions. You are responsible for staying inside scope.

---

## Why it exists

At a competition you often can't rely on internet access or AI assistants, and you need to
go from "here are some IPs" to "here's what I can pop, in priority order" in minutes.
pwnscout is that first pass:

- **No AI, fully deterministic** — same input, same output. Nothing to configure, no keys.
- **Offline knowledge base** — CVE/version signatures, sensitive paths, web-app
  fingerprints and default creds ship as JSON inside the package.
- **Actionable, not just noisy** — every finding carries a *why* and a *next command*.
- **Ranked** — a single 0-100 attack score (severity × confidence, with small bumps for
  known-exploit and verified findings) so you read top-down and start hitting things.
- **Confirms, doesn't just guess** — the `--verify` stage runs *safe, read-only* PoCs
  (anonymous FTP, unauth Redis/Docker/Elasticsearch/Memcached, exposed `.git`/`.env`, …)
  to turn "possible" into "✓verified".
- **A/D ready** — a batch exploit runner fires your own exploit module at every enemy IP
  in parallel and collects flags on a loop.

## Install

Nothing to install — clone and run:

```bash
git clone https://github.com/ericchen913900/pwnscout.git
cd pwnscout
python3 pwnscout.py --version
```

Or install it as a command:

```bash
pip install .        # provides the `pwnscout` entry point
pwnscout --version
```

Requires Python 3.8+. No third-party packages.

## Quickstart

```bash
# Recon a subnet, top ports, and list what you can hit
python3 pwnscout.py scan 10.10.10.0/24

# Full port range + confirm findings with safe PoCs + save reports
python3 pwnscout.py scan 10.10.10.5 --profile full --verify -o loot/box5

# A single web app on an odd port, with default-cred checks
python3 pwnscout.py scan 10.10.10.7 -p 8080,8443 --verify --brute

# Use nmap for version detection if it's installed
python3 pwnscout.py scan targets.txt --nmap --verify

# Show only the juicy stuff
python3 pwnscout.py scan 10.10.10.0/24 --min-score 50
```

Targets can be IPs, hostnames, CIDR (`10.0.0.0/24`), short ranges (`10.0.0.5-40`),
a file path, or `@file`.

Reports are written to `OUT.json` (machine-readable), `OUT.md` (paste into your notes),
and `OUT.html` (standalone, dark-mode).

### Exit codes (CI-friendly)

`0` = no high/critical findings · `2` = at least one high/critical · `1` = usage error.

## How scoring works

```
score = severity_weight × confidence_multiplier  (+10 verified, +5 known-exploit)
```

- **severity**: info → critical
- **confidence**: `possible` (version/banner only) → `likely` (specific signal) →
  `confirmed` (a safe PoC proved it)

Deterministic, explainable, no magic. Sort descending = your to-do list.

## The A/D exploit runner

Write one module per vulnerable service, then sweep every enemy box:

```python
# acme.py
from pwnscout.exploit import Exploit

class Module(Exploit):
    name = "acme-rce"
    default_port = 8080
    def run(self, target, ctx):
        # ... your exploit; return the flag string or None ...
        return self.find_flag(loot, ctx)
```

```bash
# Fire once
python3 pwnscout.py exploit acme.py --targets enemies.txt --port 8080

# Loop every 30s (A/D tick) and auto-submit flags
python3 pwnscout.py exploit acme.py --targets enemies.txt --loop 30 \
    --submit-url https://scoreboard/flag
```

See [`examples/example_exploit.py`](examples/example_exploit.py) for a working template.

## Extending the knowledge base

The KB is plain JSON in [`pwnscout/kb/`](pwnscout/kb):

| file | what it drives |
|------|----------------|
| `vulndb.json` | banner/version → known CVE, with exploit pointer |
| `http_paths.json` | sensitive paths to probe (`.git`, `.env`, actuator, swagger…) |
| `fingerprints.json` | web-app fingerprints (Tomcat, Jenkins, GitLab, Confluence…) |
| `default_creds.json` | small default-cred sets for the `--brute` stage |

Add your own without touching the built-ins — point `PWNSCOUT_KB` at a directory of JSON
files with the same names and they're merged on top:

```bash
PWNSCOUT_KB=~/my-kb python3 pwnscout.py scan 10.0.0.0/24
```

Check what's loaded and which external tools were detected:

```bash
python3 pwnscout.py kb
```

## What it checks (today)

- **Port scan** — pure-asyncio TCP connect scan (curated top-114 / web / full 1-65535),
  or nmap if you pass `--nmap`.
- **Service & version fingerprinting** — SSH, FTP, SMTP, HTTP(S), MySQL, Redis, Memcached,
  VNC and more, with product/version parsing for CVE matching.
- **Version → CVE** — vsftpd 2.3.4 backdoor, ProFTPD mod_copy, Apache 2.4.49/2.4.50
  traversal, SambaCry, IIS 6 WebDAV, Exim, Elasticsearch Groovy, and port-based hints for
  MS17-010 / BlueKeep / Ghostcat / exposed Docker/NFS/SNMP/LDAP/… .
- **Deep HTTP enum** — app fingerprints, sensitive-path probing with a soft-404 baseline,
  directory listing, debug pages, and Basic-auth prompts.
- **Safe verification** (`--verify`) — anonymous FTP, unauth Redis/Docker/Elasticsearch/
  Memcached/MongoDB, SMB null session, exposed `.git`/`.env`, and (with `--brute`) a tiny
  HTTP Basic / Tomcat default-cred check.

## Design notes

- **Never crashes on one bad probe** — every check is wrapped; one dead host or weird banner
  can't take down the run.
- **Standard library only** — the whole reason it survives a locked-down venue box.
- **Read-only verification** — the verify stage proves holes without changing target state.
  Actual exploitation is your call, via the suggested commands or the A/D runner.

## Development

```bash
pip install -e ".[dev]"
pytest -q
```

## License

MIT — see [LICENSE](LICENSE).
