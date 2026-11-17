"""Turn RUN/steps.tsv into RUN/results.json and RUN/summary.md (stdlib only)."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> None:
    run = Path(sys.argv[1])
    meta = {}
    if (run / "meta.env").exists():
        for line in (run / "meta.env").read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                meta[k] = v
    steps = []
    for line in (run / "steps.tsv").read_text(encoding="utf-8", errors="replace").splitlines():
        parts = (line.split("\t") + [""] * 6)[:6]
        n, status, secs, name, logf, msg = parts
        steps.append({"n": int(n), "status": status, "seconds": float(secs or 0), "name": name, "log": logf, "message": msg})
    counts = {s: sum(1 for x in steps if x["status"] == s) for s in ("OK", "FAIL", "WARN", "SKIP")}
    (run / "results.json").write_text(json.dumps({"meta": meta, "counts": counts, "steps": steps}, indent=2), encoding="utf-8")
    lines = [
        f"# Acceptance run: {meta.get('TOOL', '?')} ({meta.get('MODE', '?')})",
        "",
        f"- source: `{meta.get('SOURCE', '?')}`",
        f"- started: {meta.get('STARTED', '?')}; run folder: `{run}`",
        f"- result: **{'FAIL' if counts['FAIL'] else 'PASS'}**: {counts['OK']} ok, {counts['FAIL']} failed, "
        f"{counts['WARN']} warnings, {counts['SKIP']} skipped; {sum(x['seconds'] for x in steps):.0f}s in steps",
        "",
        "| # | status | s | step | message |",
        "|---|---|---|---|---|",
    ]
    for s in steps:
        msg = s["message"].replace("|", "\\|")[:300]
        lines.append(f"| {s['n']} | {s['status']} | {s['seconds']:.1f} | {s['name']} | {msg} |")
    (run / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
