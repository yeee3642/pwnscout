# Changelog

All notable changes to pwnscout are documented here.

## [0.2.0] — 2026-07-16

Web red-team release. The `web` subcommand goes from a light path-checker to a
full authenticated web assessment with auto-exploitation hand-off.

### Added
- **`pwnscout web`** — deep web assessment: same-host crawler → injectable point
  discovery, wordlist content discovery (soft-404 baselined), and safe active
  probes.
- **Active probes** (detection-only): reflected XSS, SSTI (with engine ID),
  error-based SQLi, path traversal / LFI, open redirect, CORS, security headers,
  cookie flags. Bounded by `--probe-budget` with an explicit truncation notice.
- **Authenticated scanning** — form-based auto-login (`--login-url` + creds or
  `--login-data`) with CSRF-token carry-through, plus a cookie jar so the crawler
  and probes run logged-in. Also `--cookie` / `--header` / `--auth-basic`.
- **JWT analysis** — discovers tokens in bodies/cookies/headers and flags
  `alg=none`, weak HMAC secret (cracked offline against a bundled wordlist →
  token forgery), RS/ES→HS confusion, missing `exp`, and sensitive claims.
- **Exploit generation** (`--gen-exploits DIR`) — turns confirmed SSTI / LFI /
  SQLi findings into runnable files: `Module(Exploit)` python modules you can
  fire with `pwnscout exploit` across A/D targets, plus a sqlmap hand-off script
  and an `EXPLOIT_PLAN.md`.
- KB: `payloads.json`, `web_wordlist.txt` (254), `jwt_secrets.txt` (67); all
  overridable via `$PWNSCOUT_KB` / `--wordlist` / `--jwt-wordlist`.
- GitHub Actions CI (py3.8/3.10/3.12), CHANGELOG.

### Changed
- `HttpResponse` now captures all `Set-Cookie` headers; `Session` gained a
  cookie jar that absorbs and replays them.
- `Finding` carries optional structured `exploit` metadata for exploit-gen.
- `kb` command reports wordlist / JWT-secret / probe-payload counts.

## [0.1.0] — 2026-07-15

Initial release: offline, no-AI, zero-dependency attack-surface scanner.

### Added
- Async TCP port scanner (pure Python) with optional nmap enrichment.
- Service/version fingerprinting and offline vulndb (version → CVE) matching.
- Light HTTP enum: web-app fingerprints and sensitive-path checks (soft-404).
- Safe verification stage: anon FTP, unauth Redis/Docker/Elasticsearch/
  Memcached/MongoDB, SMB null session, exposed `.git`/`.env`.
- Ranked "what you can hit" report (terminal / JSON / Markdown / HTML).
- A/D batch exploit runner with flag submission and loop mode.
