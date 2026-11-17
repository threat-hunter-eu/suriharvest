"""Update runs: corpus counts, before/after snapshots, gates and reports.

A gate compares this run with the last run that passed (or was accepted by hand). A failed run never becomes the
baseline, so a slow leak cannot ratchet the numbers down one update at a time.
"""

from __future__ import annotations

import json
import os
import re
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from suriharvest.config import Workspace
from suriharvest.db import in_list
from suriharvest.models import LogicGroup, Occurrence, Quarantine, RuleKey, RuleVersion, Source, UpdateRun
from suriharvest.ruleopts import option_int

KEEP_REPORTS = 60


@dataclass
class Thresholds:
    max_logic_drop: float = 5.0  # % of unique logic
    max_quarantine_growth: float = 20.0  # %
    quarantine_min_growth: int = 50  # rows; below this a growth never fails
    max_failed_sources: float = 10.0  # % of enabled sources
    failed_sources_floor: int = 1  # this many failures always pass
    max_load_error_growth: float = 20.0  # %
    load_error_min_growth: int = 50


@dataclass
class Gate:
    name: str
    status: str  # pass | fail | warn | skipped
    detail: str


def _pct(a: float, b: float) -> float:
    return 100.0 * a / b if b else 0.0


# ---------------------------------------------------------------------------------------------------------------
# counts and snapshots


def snapshot(s: Session) -> set[tuple[str, str]]:
    """(source, logic hash) of every present occurrence in an enabled source."""
    q = (
        select(Source.name, RuleVersion.logic_hash)
        .join(Occurrence, Occurrence.source_id == Source.id)
        .join(RuleVersion, RuleVersion.id == Occurrence.version_id)
        .where(Occurrence.present.is_(True), Source.enabled.is_(True))
        .distinct()
    )
    return {(a, b) for a, b in s.execute(q)}


def corpus_counts(s: Session, snap: set[tuple[str, str]], sources_enabled: int, sources_failed: list[str]) -> dict[str, Any]:
    live_logic = {lh for _, lh in snap}
    indexed = set(s.scalars(select(LogicGroup.logic_hash)))
    load_errors: dict[str, int] = defaultdict(int)
    for fails, loads in s.execute(select(LogicGroup.fails_in, LogicGroup.loads_in)):
        for engine in fails or []:
            load_errors[engine] += 1
        for engine in loads or []:
            load_errors.setdefault(engine, 0)
    return {
        "unique_logic": len(live_logic),
        "index_groups": len(indexed),
        "index_missing": len(live_logic - indexed),
        "families": s.scalar(select(func.count(func.distinct(LogicGroup.family_id)))) or 0,
        "ioc": s.scalar(select(func.count()).select_from(LogicGroup).where(LogicGroup.is_ioc.is_(True))) or 0,
        "junk": s.scalar(select(func.count()).select_from(LogicGroup).where(LogicGroup.junk.is_(True))) or 0,
        "ambiguous_keys": s.scalar(select(func.count()).select_from(RuleKey).where(RuleKey.ambiguous.is_(True))) or 0,
        # only enabled sources: a disabled (or migrated) source keeps its rows but is not part of the corpus
        "quarantine": s.scalar(
            select(func.count())
            .select_from(Quarantine)
            .join(Source, Source.id == Quarantine.source_id)
            .where(Quarantine.present.is_(True), Source.enabled.is_(True))
        )
        or 0,
        "sources_enabled": sources_enabled,
        "sources_failed": len(sources_failed),
        "failed_source_names": sorted(sources_failed),
        "load_errors": dict(load_errors),
    }


def changes(s: Session, before: set[tuple[str, str]], after: set[tuple[str, str]], sample: int = 25) -> dict[str, Any]:
    """What the sync changed: logic that is new to the corpus, logic that left it, and per-source movements."""
    logic_before = {lh for _, lh in before}
    logic_after = {lh for _, lh in after}
    new, gone = logic_after - logic_before, logic_before - logic_after
    per_source: dict[str, dict[str, int]] = defaultdict(lambda: {"added": 0, "removed": 0})
    for src, _ in after - before:
        per_source[src]["added"] += 1
    for src, _ in before - after:
        per_source[src]["removed"] += 1

    def rows(hashes: set[str]) -> list[dict[str, Any]]:
        picked = sorted(hashes)[:sample]
        if not picked:
            return []
        q = select(RuleVersion.logic_hash, RuleVersion.sid, RuleVersion.rev, RuleVersion.msg).where(in_list(RuleVersion.logic_hash, picked))
        seen: dict[str, dict[str, Any]] = {}
        for lh, sid, rev, msg in s.execute(q):
            seen.setdefault(lh, {"logic_hash": lh, "sid": sid, "rev": rev, "msg": msg})
        return list(seen.values())

    return {
        "new_logic": len(new),
        "gone_logic": len(gone),
        "per_source": dict(sorted(per_source.items())),
        "new_sample": rows(new),
        "gone_sample": rows(gone),
    }


# ---------------------------------------------------------------------------------------------------------------
# gates


def evaluate(cur: dict[str, Any], prev: dict[str, Any] | None, th: Thresholds) -> list[Gate]:
    gates: list[Gate] = []
    if prev and prev.get("unique_logic"):
        drop = _pct(prev["unique_logic"] - cur["unique_logic"], prev["unique_logic"])
        ok = drop <= th.max_logic_drop
        gates.append(
            Gate(
                "unique logic",
                "pass" if ok else "fail",
                f"{prev['unique_logic']:,} -> {cur['unique_logic']:,} ({-drop:+.1f}%, limit -{th.max_logic_drop:g}%)"
                + ("" if ok else ": a source was emptied or rewritten, or parsing/identity regressed; see removed rules"),
            )
        )
    else:
        gates.append(Gate("unique logic", "skipped", "no previous passed run to compare with"))
    if prev is not None and "quarantine" in prev:
        grown = cur["quarantine"] - prev["quarantine"]
        growth = _pct(grown, prev["quarantine"]) if prev["quarantine"] else (100.0 if grown else 0.0)
        ok = growth <= th.max_quarantine_growth or grown < th.quarantine_min_growth
        gates.append(
            Gate(
                "quarantine",
                "pass" if ok else "fail",
                f"{prev['quarantine']:,} -> {cur['quarantine']:,} ({growth:+.1f}%, limit +{th.max_quarantine_growth:g}% and {th.quarantine_min_growth} lines)"
                + ("" if ok else ": a parser regression or a source full of broken lines; see `suriharvest quarantine`"),
            )
        )
    else:
        gates.append(Gate("quarantine", "skipped", "no previous passed run to compare with"))
    enabled = cur.get("sources_enabled") or 0
    failed = cur.get("sources_failed", 0)
    share = _pct(failed, enabled)
    every = bool(enabled) and failed >= enabled  # the floor is for large workspaces, never for "all of them failed"
    ok = (share <= th.max_failed_sources or failed <= th.failed_sources_floor) and not every
    names = ", ".join(cur.get("failed_source_names", [])[:10])
    gates.append(
        Gate(
            "failed sources",
            "pass" if ok else "fail",
            f"{failed}/{enabled} failed ({share:.1f}%, limit {th.max_failed_sources:g}%, always allowed {th.failed_sources_floor})"
            + (f": {names}" if failed else "")
            + ("; every enabled source failed: nothing was updated" if every else ""),
        )
    )
    if not cur.get("unique_logic"):
        gates.append(
            Gate("rules", "fail", "the corpus has no rules: nothing to build or publish; check the sources (`suriharvest sources list`)")
        )
    missing = cur.get("index_missing", 0)
    gates.append(
        Gate(
            "index complete",
            "pass" if not missing else "fail",
            f"{cur.get('index_groups', 0):,} groups for {cur['unique_logic']:,} live logic"
            + (f", {missing} missing: run `suriharvest index`" if missing else ""),
        )
    )
    prev_err = (prev or {}).get("load_errors") or {}
    for engine, n in sorted((cur.get("load_errors") or {}).items()):
        if engine not in prev_err:
            gates.append(Gate(f"loads in {engine}", "skipped", f"{n} rules fail; no previous count for this engine"))
            continue
        p = prev_err[engine]
        grown = n - p
        growth = _pct(grown, p) if p else (100.0 if grown else 0.0)
        ok = growth <= th.max_load_error_growth or grown < th.load_error_min_growth
        gates.append(
            Gate(
                f"loads in {engine}",
                "pass" if ok else "fail",
                f"{p:,} -> {n:,} rules that do not load ({growth:+.1f}%)"
                + (
                    ""
                    if ok
                    else ": an engine/config change or a source shipping rules for another Suricata version; `suriharvest search fails:"
                    + engine
                    + "`"
                ),
            )
        )
    return gates


# ---------------------------------------------------------------------------------------------------------------
# runs and reports


def previous_baseline(s: Session, before_id: int | None = None) -> UpdateRun | None:
    q = select(UpdateRun).where((UpdateRun.status == "passed") | UpdateRun.accepted.is_(True))
    if before_id is not None:
        q = q.where(UpdateRun.id < before_id)
    return s.scalars(q.order_by(UpdateRun.id.desc()).limit(1)).first()


def get_run(s: Session, key: str) -> UpdateRun | None:
    if key == "latest":
        return s.scalars(select(UpdateRun).order_by(UpdateRun.id.desc()).limit(1)).first()
    return s.get(UpdateRun, option_int(key)) if option_int(key) is not None else None


def render_markdown(run: UpdateRun, prev: UpdateRun | None) -> str:
    c, ch = run.counts, run.changes
    lines = [
        f"# suriharvest update {run.id}: {run.status.upper()}",
        "",
        f"Started {run.started_at:%Y-%m-%d %H:%M:%S} UTC, finished {run.finished_at:%H:%M:%S} UTC."
        if run.finished_at
        else f"Started {run.started_at:%Y-%m-%d %H:%M:%S} UTC.",
        f"Compared with run {prev.id} ({prev.started_at:%Y-%m-%d})." if prev else "No earlier passed run: this run sets the baseline.",
        "",
        "## Gates",
        "",
        "| gate | result | detail |",
        "|---|---|---|",
    ]
    for g in run.gates:
        lines.append(f"| {g['name']} | {g['status']} | {g['detail'].replace('|', '/')} |")
    if run.error:
        lines += ["", f"**Error:** {run.error}"]
    lines += ["", "## Steps", "", "| step | result |", "|---|---|"]
    for k, v in run.steps.items():
        lines.append(f"| {k} | {v} |")
    lines += ["", "## Corpus", "", "| measure | value |", "|---|---|"]
    for k, v in c.items():
        lines.append(f"| {k} | {v} |")
    if ch:
        lines += [
            "",
            "## What changed",
            "",
            f"{ch.get('new_logic', 0):,} logic new to the corpus, {ch.get('gone_logic', 0):,} gone from it.",
            "",
        ]
        if ch.get("per_source"):
            lines += ["| source | logic added | logic removed |", "|---|---|---|"]
            for src, d in ch["per_source"].items():
                lines.append(f"| {src} | {d['added']} | {d['removed']} |")
        for title, key in (("New rules (sample)", "new_sample"), ("Rules that left the corpus (sample)", "gone_sample")):
            if ch.get(key):
                lines += ["", f"### {title}", ""]
                lines += [
                    f"- `{r['logic_hash'][:12]}` sid {r['sid']} rev {r['rev']}: {(r['msg'] or '').replace('|', '/')}" for r in ch[key]
                ]
    return "\n".join(lines) + "\n"


def runs_dir(ws: Workspace) -> Path:
    """Run reports live in reports/runs/<stamp>.md and .json (docs/conventions.md, as in sigharvest)."""
    return ws.reports / "runs"


def report_stamp(when: datetime) -> str:
    """UTC timestamp used as the report file name, e.g. 20261026T043000Z (started_at is stored in UTC)."""
    return when.strftime("%Y%m%dT%H%M%SZ")


LEGACY_REPORT = re.compile(r"update-(\d{8})-(\d{6})-(\d+)")  # the old place: reports/update-<time>-<id>.md


def legacy_report_name(path: Path) -> str | None:
    """reports/update-20261026-043000-7.md -> 20261026T043000Z-7.md (its name in reports/runs); None if not legacy."""
    m = LEGACY_REPORT.fullmatch(path.stem)
    return f"{m[1]}T{m[2]}Z-{m[3]}{path.suffix}" if m else None


def report_file(ws: Workspace, stored: str | None) -> Path | None:
    """The report a run row points at; a row still naming the old place finds the file once it has moved."""
    if not stored:
        return None
    path = Path(stored)
    if not path.exists() and (name := legacy_report_name(path)):
        moved = runs_dir(ws) / name
        if moved.exists():
            return moved
    return path


def migrate_legacy_reports(ws: Workspace, s: Session | None = None) -> int:
    """Move reports/update-*.md and .json into reports/runs (the first update after the move does it); the run rows
    are pointed at the new files. Links are left alone. Returns the number of reports moved."""
    folder = runs_dir(ws)
    moved = 0
    if not ws.reports.is_dir() or folder.is_symlink():
        return 0
    for md in sorted(ws.reports.glob("update-*.md")):
        name = legacy_report_name(md)
        if name is None or md.is_symlink() or not md.is_file():
            continue
        folder.mkdir(parents=True, exist_ok=True)
        target = folder / name
        if target.exists():
            continue
        os.replace(md, target)
        js = md.with_suffix(".json")
        if js.is_file() and not js.is_symlink() and not target.with_suffix(".json").exists():
            os.replace(js, target.with_suffix(".json"))
        if s is not None:
            s.execute(update(UpdateRun).where(UpdateRun.report_path == str(md)).values(report_path=str(target)))
        moved += 1
    return moved


def write_report(ws: Workspace, run: UpdateRun, prev: UpdateRun | None, s: Session | None = None) -> Path:
    """Write reports/runs/<stamp>.md and .json (older reports at reports/update-*.md are moved there first)."""
    migrate_legacy_reports(ws, s)
    folder = runs_dir(ws)
    folder.mkdir(parents=True, exist_ok=True)
    md = folder / f"{report_stamp(run.started_at)}.md"
    if md.exists():  # two runs that started in the same second must not share (and overwrite) one report
        md = folder / f"{report_stamp(run.started_at)}-{run.id}.md"
    md.write_text(render_markdown(run, prev), encoding="utf-8", newline="\n")
    data = {
        "id": run.id,
        "status": run.status,
        "started_at": run.started_at.isoformat(),
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "steps": run.steps,
        "counts": run.counts,
        "gates": run.gates,
        "changes": run.changes,
        "error": run.error,
        "baseline": prev.id if prev else None,
    }
    md.with_suffix(".json").write_text(json.dumps(data, indent=2, default=str), encoding="utf-8", newline="\n")
    reports = sorted(p for p in folder.glob("*.md") if p.is_file() and not p.is_symlink())
    for old in reports[:-KEEP_REPORTS]:
        old.unlink(missing_ok=True)
        old.with_suffix(".json").unlink(missing_ok=True)
    return md


def gates_as_json(gates: list[Gate]) -> list[dict[str, str]]:
    return [asdict(g) for g in gates]


def stamp_now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M")
