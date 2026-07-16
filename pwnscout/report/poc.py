"""Generate a PoC bundle from a scan/web result.

- Injection findings (SSTI/LFI/SQLi) that carry exploit metadata become runnable
  modules via the exploit generator.
- Every other submittable finding gets a small reproduction script carrying the
  exact command and the expected evidence.
- POC_INDEX.md ties it together with CVSS / risk / submittable status.
"""

from __future__ import annotations

import os
import re
from typing import List

from . import assess as _assess


def _slug(s: str) -> str:
    return (re.sub(r"[^A-Za-z0-9]+", "_", s or "").strip("_") or "poc")[:40]


_REPRO_TPL = """#!/bin/sh
# pwnscout PoC — {title}
# target : {loc}
# risk   : {risk}  (CVSS {score}  {vector})
# proof  : {evidence}
# Expected: the command below reproduces the finding described above.
{cmd}
"""


def generate(result, outdir: str) -> List[str]:
    os.makedirs(outdir, exist_ok=True)
    written: List[str] = []

    # 1) runnable exploit modules for structured injection findings
    has_exploit = any(getattr(f, "exploit", None) for f in result.findings)
    if has_exploit:
        try:
            from ..web import exploit_gen
            written.extend(exploit_gen.generate(result, outdir))
        except Exception:
            pass

    # 2) reproduction scripts for the remaining submittable findings
    idx = 0
    index = ["# pwnscout — PoC index", "",
             "| # | Risk | CVSS | Target | Finding | Submittable | Artifact |",
             "|---|------|-----:|--------|---------|:-----------:|----------|"]
    for f in result.ranked():
        a = _assess.assess(f)
        if not a["submittable"]:
            continue
        idx += 1
        loc = f"{f.target}:{f.port}" if f.port else f.target
        meta = getattr(f, "exploit", None)
        if meta:
            artifact = "runnable module (see above / EXPLOIT_PLAN.md)"
        else:
            idx_name = f"{idx:02d}_{_slug(f.title)}.sh"
            path = os.path.join(outdir, idx_name)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(_REPRO_TPL.format(
                    title=f.title, loc=loc, risk=a["risk"],
                    score=a["cvss_score"], vector=a["cvss_vector"],
                    evidence=f.evidence or "-", cmd=f.next_step or "# (manual)"))
            try:
                os.chmod(path, 0o755)
            except OSError:
                pass
            written.append(path)
            artifact = f"`{idx_name}`"
        index.append(f"| {idx} | {a['risk']} | {a['cvss_score']} | `{loc}` | "
                     f"{f.title}{(' — ' + f.cve) if f.cve else ''} | "
                     f"{'yes' if a['submittable'] else 'no'} | {artifact} |")

    index_path = os.path.join(outdir, "POC_INDEX.md")
    with open(index_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(index) + "\n")
    written.append(index_path)
    return written
