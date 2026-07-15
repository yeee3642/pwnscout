"""Render a ScanResult four ways: terminal, JSON, Markdown, standalone HTML.

The terminal view is the payoff: a ranked "what to hit" list, highest attack
score first, each with the reason and a paste-ready next command.
"""

from __future__ import annotations

import html
import json
from typing import List

from ..core.model import Finding, ScanResult, Severity
from ..core.utils import clip, color

_SEV_COLOR = {
    "critical": ("bred", "bold"), "high": ("red",), "medium": ("yellow",),
    "low": ("cyan",), "info": ("grey",),
}
_SEV_BADGE = {"critical": "CRIT", "high": "HIGH", "medium": "MED ",
              "low": "LOW ", "info": "INFO"}


def _score_bar(score: int) -> str:
    filled = round(score / 10)
    return "█" * filled + "·" * (10 - filled)


def to_terminal(result: ScanResult, min_score: int = 0, top: int = 0) -> str:
    lines: List[str] = []
    s = result.summary()
    lines.append("")
    lines.append(color("  pwnscout — attack surface report", "bold", "cyan"))
    lines.append(color(f"  {result.started}  →  {result.finished}", "grey"))
    bysev = s["by_severity"]
    head = (f"  hosts {s['hosts_alive']}/{s['hosts_scanned']} up · "
            f"{s['services']} services · {s['findings']} findings "
            f"({s['verified']} verified)")
    lines.append(color(head, "dim"))
    sevline = "  " + "  ".join(
        color(f"{_SEV_BADGE[k].strip()}:{bysev[k]}", *_SEV_COLOR[k])
        for k in ("critical", "high", "medium", "low", "info") if bysev[k]
    )
    if sevline.strip():
        lines.append(sevline)
    lines.append("")

    ranked = result.ranked(min_score)
    if top:
        ranked = ranked[:top]
    if not ranked:
        lines.append(color("  No findings at or above the score threshold.", "grey"))
        return "\n".join(lines)

    lines.append(color("  WHAT YOU CAN HIT  (ranked by exploitability)", "bold"))
    lines.append(color("  " + "─" * 68, "grey"))
    for i, f in enumerate(ranked, 1):
        sev = f.severity.label
        badge = color(f"[{_SEV_BADGE[sev]}]", *_SEV_COLOR[sev])
        vflag = color(" ✓verified", "bgreen") if f.verified else ""
        loc = f"{f.target}:{f.port}" if f.port else f.target
        bar = color(_score_bar(f.score), "green" if f.score >= 60 else "yellow")
        lines.append(f"  {color(f'{f.score:>3}', 'bold')} {bar} {badge} "
                     f"{color(loc, 'cyan')}  {f.title}{vflag}")
        if f.cve:
            lines.append(color(f"       {f.cve}", "magenta"))
        if f.why:
            lines.append(color("       why: ", "dim") + clip(f.why, 150))
        if f.next_step:
            lines.append(color("       run: ", "dim") + color(clip(f.next_step, 150), "green"))
        lines.append("")
    return "\n".join(lines)


def to_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2, ensure_ascii=False)


def to_markdown(result: ScanResult) -> str:
    s = result.summary()
    out: List[str] = []
    out.append("# pwnscout report\n")
    out.append(f"*{result.started} → {result.finished}*\n")
    out.append(f"- Hosts up: **{s['hosts_alive']}/{s['hosts_scanned']}**")
    out.append(f"- Services: **{s['services']}**")
    out.append(f"- Findings: **{s['findings']}** ({s['verified']} verified)")
    bs = s["by_severity"]
    out.append(f"- Severity: "
               f"critical {bs['critical']}, high {bs['high']}, "
               f"medium {bs['medium']}, low {bs['low']}, info {bs['info']}\n")

    out.append("## What you can hit (ranked)\n")
    out.append("| # | Score | Sev | Target | Finding | Verified |")
    out.append("|---|------:|-----|--------|---------|:--------:|")
    for i, f in enumerate(result.ranked(), 1):
        loc = f"{f.target}:{f.port}" if f.port else f.target
        out.append(f"| {i} | {f.score} | {f.severity.label} | `{loc}` | "
                   f"{f.title}{(' — ' + f.cve) if f.cve else ''} | "
                   f"{'✓' if f.verified else ''} |")
    out.append("")

    out.append("## Details\n")
    for f in result.ranked():
        loc = f"{f.target}:{f.port}" if f.port else f.target
        out.append(f"### [{f.score}] {f.title} — `{loc}`\n")
        out.append(f"- **Severity:** {f.severity.label}  "
                   f"**Confidence:** {f.confidence.label}"
                   f"{'  **Verified**' if f.verified else ''}")
        if f.cve:
            out.append(f"- **CVE:** {f.cve}")
        if f.evidence:
            out.append(f"- **Evidence:** `{f.evidence}`")
        if f.why:
            out.append(f"- **Why it's hittable:** {f.why}")
        if f.next_step:
            out.append(f"- **Next step:**\n\n  ```bash\n  {f.next_step}\n  ```")
        if f.refs:
            out.append("- **Refs:** " + ", ".join(f.refs))
        out.append("")
    return "\n".join(out)


def to_html(result: ScanResult) -> str:
    s = result.summary()
    rows = []
    for i, f in enumerate(result.ranked(), 1):
        loc = f"{f.target}:{f.port}" if f.port else f.target
        rows.append(
            f"<tr class='sev-{f.severity.label}'>"
            f"<td class='sc'>{f.score}</td>"
            f"<td><span class='badge {f.severity.label}'>{f.severity.label}</span></td>"
            f"<td class='tgt'>{html.escape(loc)}</td>"
            f"<td><b>{html.escape(f.title)}</b>"
            f"{'  <span class=v>verified</span>' if f.verified else ''}"
            f"{('<div class=cve>' + html.escape(f.cve) + '</div>') if f.cve else ''}"
            f"<div class=why>{html.escape(f.why)}</div>"
            f"{('<pre>' + html.escape(f.next_step) + '</pre>') if f.next_step else ''}"
            f"</td></tr>"
        )
    body = "\n".join(rows)
    return f"""<!doctype html><html><head><meta charset=utf-8>
<title>pwnscout report</title><style>
:root{{color-scheme:dark light}}
body{{font:14px/1.5 ui-monospace,Consolas,monospace;margin:0;background:#0d1117;color:#c9d1d9}}
header{{padding:18px 24px;border-bottom:1px solid #21262d;background:#161b22}}
h1{{margin:0;font-size:18px;color:#58a6ff}}
.meta{{color:#8b949e;margin-top:6px}}
table{{border-collapse:collapse;width:100%}}
td,th{{padding:8px 12px;border-bottom:1px solid #21262d;vertical-align:top}}
.sc{{font-weight:700;font-size:16px;text-align:right;width:44px}}
.tgt{{color:#58a6ff;white-space:nowrap}}
.badge{{padding:1px 7px;border-radius:4px;font-size:11px;text-transform:uppercase;color:#fff}}
.badge.critical{{background:#b62324}}.badge.high{{background:#da3633}}
.badge.medium{{background:#9e6a03}}.badge.low{{background:#1f6feb}}.badge.info{{background:#484f58}}
.why{{color:#8b949e;margin:4px 0}}.cve{{color:#bc8cff;font-size:12px}}
.v{{color:#3fb950;font-size:11px}}
pre{{background:#010409;border:1px solid #21262d;padding:8px;border-radius:6px;overflow:auto;color:#7ee787;margin:6px 0 0}}
tr.sev-critical .sc{{color:#ff7b72}}tr.sev-high .sc{{color:#ffa198}}
</style></head><body>
<header><h1>pwnscout — attack surface report</h1>
<div class=meta>{html.escape(result.started)} → {html.escape(result.finished)} &nbsp;·&nbsp;
hosts {s['hosts_alive']}/{s['hosts_scanned']} up · {s['services']} services ·
{s['findings']} findings ({s['verified']} verified)</div></header>
<table><thead><tr><th>Score</th><th>Sev</th><th>Target</th><th>Finding · why · next step</th></tr></thead>
<tbody>{body}</tbody></table></body></html>"""
