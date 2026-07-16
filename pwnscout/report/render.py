"""Render a ScanResult four ways: terminal, JSON, Markdown, standalone HTML.

The Markdown/HTML are submission-ready vulnerability reports: every finding
carries an estimated CVSS 3.1 vector + score, a risk label, reproduction steps,
a PoC pointer, impact and remediation. Findings worth reporting are marked
"submittable"; recon noise is separated out.
"""

from __future__ import annotations

import html
import json
from typing import Dict, List

from ..core.model import Finding, ScanResult, Severity
from ..core.utils import clip, color
from . import assess as _assess

_SEV_COLOR = {
    "critical": ("bred", "bold"), "high": ("red",), "medium": ("yellow",),
    "low": ("cyan",), "info": ("grey",),
}
_SEV_BADGE = {"critical": "CRIT", "high": "HIGH", "medium": "MED ",
              "low": "LOW ", "info": "INFO"}

_IMPACT = {
    "Critical": "Critical impact — likely full compromise (RCE, credential theft "
                "or bulk data exposure).",
    "High": "High impact — significant data exposure or account/authorization "
            "compromise.",
    "Medium": "Medium impact — partial exposure, or requires user interaction / "
              "specific conditions.",
    "Low": "Low impact — hardening / defence-in-depth; useful in a chain.",
    "None": "Informational.",
}


def _score_bar(score: int) -> str:
    filled = round(score / 10)
    return "█" * filled + "·" * (10 - filled)


def _submittable_count(result: ScanResult) -> int:
    return sum(1 for f in result.findings if _assess.assess(f)["submittable"])


# ---------------------------------------------------------------------------
# terminal
# ---------------------------------------------------------------------------
def to_terminal(result: ScanResult, min_score: int = 0, top: int = 0) -> str:
    lines: List[str] = []
    s = result.summary()
    subs = _submittable_count(result)
    lines.append("")
    lines.append(color("  pwnscout — attack surface report", "bold", "cyan"))
    lines.append(color(f"  {result.started}  →  {result.finished}", "grey"))
    head = (f"  hosts {s['hosts_alive']}/{s['hosts_scanned']} up · "
            f"{s['services']} services · {s['findings']} findings "
            f"({s['verified']} verified · {color(str(subs) + ' submittable', 'bgreen')})")
    lines.append(color(head, "dim"))
    bysev = s["by_severity"]
    sevline = "  " + "  ".join(
        color(f"{_SEV_BADGE[k].strip()}:{bysev[k]}", *_SEV_COLOR[k])
        for k in ("critical", "high", "medium", "low", "info") if bysev[k])
    if sevline.strip():
        lines.append(sevline)
    lines.append("")

    ranked = result.ranked(min_score)
    if top:
        ranked = ranked[:top]
    if not ranked:
        lines.append(color("  No findings at or above the score threshold.", "grey"))
        return "\n".join(lines)

    lines.append(color("  WHAT YOU CAN HIT  (ranked; ★ = submittable)", "bold"))
    lines.append(color("  " + "─" * 70, "grey"))
    for f in ranked:
        a = _assess.assess(f)
        sev = f.severity.label
        badge = color(f"[{_SEV_BADGE[sev]}]", *_SEV_COLOR[sev])
        vflag = color(" ✓", "bgreen") if f.verified else ""
        star = color("★", "byellow") if a["submittable"] else " "
        loc = f"{f.target}:{f.port}" if f.port else f.target
        bar = color(_score_bar(f.score), "green" if f.score >= 60 else "yellow")
        cvss = color(f"CVSS {a['cvss_score']}", "magenta") if a["cvss_score"] else ""
        lines.append(f"  {star} {color(f'{f.score:>3}', 'bold')} {bar} {badge} "
                     f"{color(loc, 'cyan')}  {f.title}{vflag}  {cvss}")
        if f.why:
            lines.append(color("       why: ", "dim") + clip(f.why, 150))
        if f.next_step:
            lines.append(color("       run: ", "dim") + color(clip(f.next_step, 150), "green"))
        lines.append("")
    lines.append(color(f"  → {subs} submittable finding(s). "
                       f"Use -o <name> for a full report + PoCs.", "cyan"))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# JSON (enriched with CVSS / risk / submittable / remediation)
# ---------------------------------------------------------------------------
def _enrich(f: Finding) -> Dict:
    d = f.to_dict()
    d.update(_assess.assess(f))
    return d


def to_json(result: ScanResult) -> str:
    data = {
        "tool": "pwnscout",
        "started": result.started,
        "finished": result.finished,
        "args": result.args,
        "summary": {**result.summary(), "submittable": _submittable_count(result)},
        "findings": [_enrich(f) for f in result.ranked()],
        "hosts": [h.to_dict() for h in result.hosts],
    }
    return json.dumps(data, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Markdown vulnerability report
# ---------------------------------------------------------------------------
def to_markdown(result: ScanResult) -> str:
    s = result.summary()
    ranked = result.ranked()
    enriched = [(f, _assess.assess(f)) for f in ranked]
    submit = [(f, a) for f, a in enriched if a["submittable"]]
    other = [(f, a) for f, a in enriched if not a["submittable"]]

    out: List[str] = []
    out.append("# pwnscout vulnerability report\n")
    out.append(f"*{result.started} → {result.finished}*\n")
    out.append(f"- Hosts up: **{s['hosts_alive']}/{s['hosts_scanned']}** · "
               f"Services: **{s['services']}**")
    out.append(f"- Findings: **{s['findings']}** ({s['verified']} verified)")
    out.append(f"- **Submittable: {len(submit)}** "
               f"(CVSS ≥ 4.0, confirmed or high-confidence)")
    bs = s["by_severity"]
    out.append(f"- Severity: critical {bs['critical']}, high {bs['high']}, "
               f"medium {bs['medium']}, low {bs['low']}, info {bs['info']}\n")
    out.append("> CVSS vectors are estimated from the finding class — review "
               "before submitting.\n")

    out.append("## Submittable findings\n")
    if not submit:
        out.append("_None met the submission bar this run._\n")
    for i, (f, a) in enumerate(submit, 1):
        loc = f"{f.target}:{f.port}" if f.port else f.target
        out.append(f"### {i}. [{a['risk']} · CVSS {a['cvss_score']}] "
                   f"{f.title} — `{loc}`\n")
        out.append(f"- **Risk:** {a['risk']} · **CVSS:** {a['cvss_score']} "
                   f"(`{a['cvss_vector']}`)")
        out.append(f"- **Confidence:** {f.confidence.label}"
                   f"{' · **Verified PoC**' if f.verified else ''}")
        if f.cve:
            out.append(f"- **CVE:** {f.cve}")
        out.append(f"- **Affected:** `{loc}`"
                   f"{(' service ' + f.service) if f.service else ''}")
        if f.why:
            out.append(f"- **Description:** {f.why}")
        if f.evidence:
            out.append(f"- **Evidence:** `{f.evidence}`")
        if f.next_step:
            out.append(f"- **Steps to reproduce:**\n\n  ```bash\n  {f.next_step}\n  ```")
        poc = ("runnable module in the PoC bundle (see `POC_INDEX.md`)"
               if getattr(f, "exploit", None) else "see reproduction steps above")
        out.append(f"- **Proof of concept:** {poc}")
        out.append(f"- **Impact:** {_IMPACT.get(a['risk'], '')}")
        out.append(f"- **Remediation:** {a['remediation']}")
        if f.refs:
            out.append(f"- **References:** {', '.join(f.refs)}")
        out.append("")

    out.append("## Other / informational findings\n")
    out.append("| Score | Sev | Target | Finding | Verified |")
    out.append("|------:|-----|--------|---------|:--------:|")
    for f, a in other:
        loc = f"{f.target}:{f.port}" if f.port else f.target
        out.append(f"| {f.score} | {f.severity.label} | `{loc}` | "
                   f"{f.title} | {'✓' if f.verified else ''} |")
    out.append("")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# HTML vulnerability report
# ---------------------------------------------------------------------------
def to_html(result: ScanResult) -> str:
    s = result.summary()
    enriched = [(f, _assess.assess(f)) for f in result.ranked()]
    subs = sum(1 for _f, a in enriched if a["submittable"])

    rows = []
    for f, a in enriched:
        loc = f"{f.target}:{f.port}" if f.port else f.target
        star = "★" if a["submittable"] else ""
        poc = ("<div class=poc>PoC: runnable module (POC_INDEX.md)</div>"
               if getattr(f, "exploit", None) else "")
        rows.append(
            f"<tr class='sev-{f.severity.label}'>"
            f"<td class='sc'>{star}<br>{a['cvss_score'] or ''}</td>"
            f"<td><span class='badge {f.severity.label}'>{a['risk']}</span></td>"
            f"<td class='tgt'>{html.escape(loc)}</td>"
            f"<td><b>{html.escape(f.title)}</b>"
            f"{'  <span class=v>verified</span>' if f.verified else ''}"
            f"{('<div class=cve>' + html.escape(f.cve) + '</div>') if f.cve else ''}"
            f"<div class=vec>{html.escape(a['cvss_vector'])}</div>"
            f"<div class=why>{html.escape(f.why)}</div>"
            f"{('<pre>' + html.escape(f.next_step) + '</pre>') if f.next_step else ''}"
            f"<div class=rem><b>Fix:</b> {html.escape(a['remediation'])}</div>"
            f"{poc}</td></tr>")
    body = "\n".join(rows)
    return f"""<!doctype html><html><head><meta charset=utf-8>
<title>pwnscout vulnerability report</title><style>
:root{{color-scheme:dark light}}
body{{font:14px/1.5 ui-monospace,Consolas,monospace;margin:0;background:#0d1117;color:#c9d1d9}}
header{{padding:18px 24px;border-bottom:1px solid #21262d;background:#161b22}}
h1{{margin:0;font-size:18px;color:#58a6ff}}
.meta{{color:#8b949e;margin-top:6px}}
.sub{{color:#3fb950;font-weight:700}}
table{{border-collapse:collapse;width:100%}}
td,th{{padding:8px 12px;border-bottom:1px solid #21262d;vertical-align:top}}
.sc{{font-weight:700;text-align:center;width:52px;color:#ffa657}}
.tgt{{color:#58a6ff;white-space:nowrap}}
.badge{{padding:1px 7px;border-radius:4px;font-size:11px;text-transform:uppercase;color:#fff}}
.badge.critical{{background:#b62324}}.badge.high{{background:#da3633}}
.badge.medium{{background:#9e6a03}}.badge.low{{background:#1f6feb}}.badge.info{{background:#484f58}}
.why{{color:#8b949e;margin:4px 0}}.cve{{color:#bc8cff;font-size:12px}}
.vec{{color:#6e7681;font-size:11px}}.rem{{color:#7ee787;margin-top:4px;font-size:12px}}
.poc{{color:#d29922;font-size:12px;margin-top:2px}}.v{{color:#3fb950;font-size:11px}}
pre{{background:#010409;border:1px solid #21262d;padding:8px;border-radius:6px;overflow:auto;color:#7ee787;margin:6px 0 0}}
</style></head><body>
<header><h1>pwnscout — vulnerability report</h1>
<div class=meta>{html.escape(result.started)} → {html.escape(result.finished)} &nbsp;·&nbsp;
hosts {s['hosts_alive']}/{s['hosts_scanned']} up · {s['services']} services ·
{s['findings']} findings ({s['verified']} verified) ·
<span class=sub>{subs} submittable ★</span></div></header>
<table><thead><tr><th>★<br>CVSS</th><th>Risk</th><th>Target</th>
<th>Finding · vector · fix</th></tr></thead>
<tbody>{body}</tbody></table></body></html>"""
