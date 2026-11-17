"""Sync and update pipelines shared by the CLI and the scheduler.

update = sync -> validate (new rules only) -> index -> counts + gates -> report.
A failed step is recorded and the run continues where that is safe: a failed source keeps its previous rules,
a failed engine keeps its previous results. The exit status says whether a source or a gate failed; an engine
that cannot validate fails the run (its results would be stale, and a release built from them wrong).
"""

from __future__ import annotations

import errno
import time
import traceback
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.markup import escape
from sqlalchemy import select
from sqlalchemy.orm import Session

from suriharvest.config import ConfigError, SourceConfig, Workspace, load_sources
from suriharvest.models import Source, SyncLog, UpdateRun, utcnow

Say = Callable[[str], None]


@dataclass
class SourceOutcome:
    name: str
    ok: bool
    message: str


@dataclass
class SyncOutcome:
    sources: list[SourceOutcome] = field(default_factory=list)

    @property
    def failed(self) -> list[str]:
        return [o.name for o in self.sources if not o.ok]


def reconcile_sources(s: Session, configs: list[SourceConfig]) -> None:
    """Make the sources table follow sources.yaml: settings copied, sources removed from the file disabled.
    (Their rules stay in the corpus; disabled sources are left out of the index.)"""
    from suriharvest.ingest import ensure_source

    names = {c.name for c in configs}
    for c in configs:
        ensure_source(s, c)
    for row in s.scalars(select(Source)):
        if row.name not in names:
            row.enabled = False
    s.commit()


def apply_source_settings(s: Session, w: Workspace, say: Say) -> None:
    """Before anything is built or exported: copy the current sources.yaml settings (enabled, redistribute,
    licence, priority) into the database and re-index when they changed, so a source turned to
    `redistribute: no`, disabled or removed is honoured without waiting for the next sync."""
    reconcile_sources(s, load_sources(w))
    index_step(s, say, if_changed=True)


def sync_sources(s: Session, w: Workspace, srcs: list[SourceConfig], say: Say) -> SyncOutcome:
    from suriharvest.ingest import ensure_source, ingest, load_manifest, save_manifest
    from suriharvest.majors import source_rulesets
    from suriharvest.sync import SyncError, fetch, save_validators

    settings = w.settings()
    reconcile_sources(s, load_sources(w))
    out = SyncOutcome()
    for src in srcs:
        row = ensure_source(s, src)
        log = SyncLog(source_id=row.id, old_commit=row.last_commit)
        s.add(log)
        s.commit()
        t0 = time.monotonic()
        try:
            per_major = source_rulesets(src, settings)
            res = fetch(src, w, row.last_commit, load_manifest(w, src.name), settings.ruleset_version, per_major)
            st = ingest(s, w, src, row, res)
            save_manifest(w, src.name, res.root)
            row.last_commit, row.last_sync_at = res.new_commit, utcnow()
            log.new_commit, log.files_added, log.files_changed, log.files_removed = (
                res.new_commit,
                len(res.added),
                len(res.changed),
                len(res.removed),
            )
            log.rules_seen, log.versions_new, log.quarantined, log.status = st.rules, st.versions_new, st.quarantined, "ok"
            log.finished_at = utcnow()
            s.commit()
            save_validators(res)  # only now: a failed extraction or ingest must be retried, not answered by a 304
            what = (
                "unchanged"
                if not (res.added or res.changed or res.removed)
                else f"+{len(res.added)} ~{len(res.changed)} -{len(res.removed)} files"
            )
            msg = f"{what}; {st.rules} rules read, {st.versions_new} new versions, {st.quarantined} quarantined ({time.monotonic() - t0:.1f}s)"
            if per_major:
                msg += f"; one copy per Suricata major ({', '.join(per_major)})"
            if res.too_large:
                msg += f"; [yellow]{len(res.too_large)} file(s) over the size limit skipped: {escape(', '.join(res.too_large[:3]))}[/]"
            out.sources.append(SourceOutcome(src.name, True, msg))
            say(f"[green]ok[/] {src.name}: {msg}")
        except Exception as e:  # noqa: BLE001 - one bad source (corrupt archive, git timeout, bug) must not stop the others
            s.rollback()
            msg = str(e) if isinstance(e, (SyncError, ConfigError, OSError)) else f"{type(e).__name__}: {e}"
            log = s.merge(log)
            log.status, log.error, log.finished_at = "error", msg[:1000], utcnow()
            s.commit()
            out.sources.append(SourceOutcome(src.name, False, msg))
            say(f"[red]failed[/] {src.name}: {escape(msg)}")  # msg can quote archive member names or git output
    return out


def corpus_fingerprint(s: Session) -> str:
    """Changes whenever anything the index is built from changes."""
    from sqlalchemy import func

    from suriharvest.identity import FACTS_VERSION, sha256_hex
    from suriharvest.models import Occurrence, RuleVersion, ValidationResult, Verdict

    parts = [
        FACTS_VERSION,
        s.execute(select(func.count(), func.max(RuleVersion.id)).select_from(RuleVersion)).one(),
        s.execute(select(func.count(), func.max(Occurrence.id)).where(Occurrence.present.is_(True))).one(),
        # a rule the publisher only enabled or commented out changes no count above (enabled_anywhere)
        s.execute(select(func.count(), func.sum(Occurrence.id)).where(Occurrence.present.is_(True), Occurrence.enabled.is_(True))).one(),
        s.execute(select(func.count(), func.max(ValidationResult.checked_at)).select_from(ValidationResult)).one(),
        s.execute(select(func.count(), func.max(Verdict.updated_at)).select_from(Verdict)).one(),
        s.execute(
            select(Source.name, Source.priority, Source.enabled, Source.redistribute, Source.sid_namespace).order_by(Source.name)
        ).all(),
    ]
    return sha256_hex(repr(parts))


def index_step(s: Session, say: Say, *, if_changed: bool = False) -> bool:
    """Rebuild the index. With if_changed, skip it when the corpus fingerprint is the one indexed last.
    Returns True when it rebuilt."""
    from suriharvest.db import get_meta, set_meta

    fp = corpus_fingerprint(s)
    if if_changed and get_meta(s, "index_fingerprint") == fp and get_meta(s, "indexed_at"):
        say("index: up to date (nothing changed since the last index)")
        return False
    _rebuild(s, say)
    set_meta(s, "index_fingerprint", corpus_fingerprint(s))
    s.commit()
    return True


def _rebuild(s: Session, say: Say) -> None:
    from suriharvest.index import rebuild
    from suriharvest.ingest import refresh_facts

    t0 = time.monotonic()
    n = refresh_facts(s)
    if n:
        say(f"identity code changed: recomputed facts of {n} versions from their text")
    rep = rebuild(s)
    say(
        f"index: {rep.live_versions:,} live versions -> {rep.logic_groups:,} unique logics -> {rep.semantic_groups:,} semantic -> "
        f"{rep.families:,} families ({rep.ioc_groups:,} IOC, {rep.behaviour_groups:,} behaviour; {rep.ambiguous_keys:,} ambiguous sids; "
        f"{rep.junk:,} junk; {rep.unique_indicators:,} unique indicators, {rep.near_duplicates:,} similar pairs) in {time.monotonic() - t0:.1f}s"
    )


def build_profiles(s: Session, w: Workspace, say: Say) -> int:
    """Rebuild every profile with auto_build (default on) through its exclusions."""
    from suriharvest.models import Profile
    from suriharvest.profiles import load_files, make_build

    fs = load_files(s, w)
    if fs.added or fs.removed:
        say(f"exclusion files edited by hand: +{fs.added} -{fs.removed} applied")
    for e in fs.errors:
        say(f"[yellow]exclusion file not applied[/]: {escape(str(e))}")
    n = 0
    from suriharvest.profiles import ProfileError, build_fingerprint, last_build

    for t in s.scalars(select(Profile).order_by(Profile.name)):
        if (t.options or {}).get("auto_build", True):
            prev = last_build(s, t)
            if prev is not None and prev.summary.get("fingerprint") == build_fingerprint(s, t) and Path(prev.path).exists():
                say(f"build {t.name}: up to date (#{prev.id}, {prev.rules:,} rules)")
                continue
            try:
                b = make_build(s, w, t)
            except ProfileError as e:
                say(f"[yellow]build {t.name} skipped[/]: {escape(str(e))}")
                continue
            say(
                f"build {t.name} #{b.id}: {b.rules:,} rules, {b.excluded:,} excluded; "
                + (
                    f"+{b.summary['added']} -{b.summary['removed']} ~{b.summary.get('changed', 0)} since the previous build"
                    if b.summary.get("previous_build")
                    else f"first build of profile {t.name}"
                )
            )
            n += 1
    return n


def progress_lines(say: Say, label: str, every: float = 30.0) -> Callable[[int, int], None]:
    """A progress callback that prints a plain line (fine in cron logs and pipes, no TTY needed) at most every
    `every` seconds and at each 25%: "validate local: 4,000/22,901 rules (17%), about 3 min left"."""
    start = time.monotonic()
    state = {"last": start, "quarter": 0}

    def cb(done: int, total: int) -> None:
        now = time.monotonic()
        quarter = done * 4 // total if total else 4
        if done >= total or (now - state["last"] < every and quarter <= state["quarter"]):
            return
        state["last"], state["quarter"] = now, quarter
        left = (now - start) / done * (total - done) if done else 0
        eta = f", about {left / 60:.0f} min left" if left >= 90 else (f", about {left:.0f} s left" if done else "")
        say(f"{label}: {done:,}/{total:,} rules ({done * 100 // total}%){eta}")

    return cb


@dataclass
class UpdateResult:
    run: UpdateRun
    report: str | None
    exit_code: int


def refresh_sources(s: Session, w: Workspace, srcs: list[SourceConfig], say: Say) -> SyncOutcome:
    """Download only these sources, then validate new rules, index and rebuild auto-build profiles.
    No update run or gates: those compare whole-corpus updates (the Update button)."""
    from suriharvest.validate import validate as run_validate

    outcome = sync_sources(s, w, srcs, say)
    for eng in w.settings().engines:
        try:
            rep = run_validate(s, eng, ws=w, progress=progress_lines(say, f"validate {eng.name}"))
            say(f"validate {eng.name}: {rep.checked:,} checked, {rep.errors} do not load, {rep.cached:,} cached")
        except Exception as e:  # noqa: BLE001 - an engine problem must not stop the download
            s.rollback()
            say(f"[yellow]validate {eng.name} failed[/]: {escape(str(e))}")
    index_step(s, say, if_changed=True)
    build_profiles(s, w, say)
    return outcome


def update(s: Session, w: Workspace, say: Say, *, validate: bool = True, thresholds: Any = None) -> UpdateResult:
    from suriharvest.runs import (
        Gate,
        Thresholds,
        changes,
        corpus_counts,
        evaluate,
        gates_as_json,
        previous_baseline,
        snapshot,
        write_report,
    )

    run = UpdateRun(steps={})
    s.add(run)
    s.commit()
    steps: dict[str, str] = {}
    failed_sources: list[str] = []
    failed_engines: dict[str, str] = {}
    srcs = [c for c in load_sources(w) if c.active]
    try:
        before = snapshot(s)
        t0 = time.monotonic()
        outcome = sync_sources(s, w, srcs, say)
        failed_sources = outcome.failed
        steps["sync"] = f"{len(srcs) - len(failed_sources)}/{len(srcs)} sources ok, {time.monotonic() - t0:.0f}s"
        if validate:
            from suriharvest.validate import validate as run_validate

            for eng in w.settings().engines:
                t0 = time.monotonic()
                try:
                    rep = run_validate(s, eng, ws=w, progress=progress_lines(say, f"validate {eng.name}"))
                    steps[f"validate {eng.name}"] = (
                        f"{rep.checked:,} checked ({rep.errors:,} errors), {rep.cached:,} cached, {time.monotonic() - t0:.0f}s"
                    )
                    say(f"validate {eng.name}: {steps[f'validate {eng.name}']}")
                except Exception as e:  # noqa: BLE001 - an engine problem must not stop the update
                    s.rollback()
                    steps[f"validate {eng.name}"] = f"error: {e}"
                    failed_engines[eng.name] = str(e)
                    say(f"[red]validate {eng.name} failed[/]: {escape(str(e))}")
        t0 = time.monotonic()
        rebuilt = index_step(s, say, if_changed=True)
        steps["index"] = f"{time.monotonic() - t0:.0f}s" if rebuilt else "up to date"
        after = snapshot(s)
        run.counts = corpus_counts(s, after, len(srcs), failed_sources)
        run.changes = changes(s, before, after)
        prev = previous_baseline(s, run.id)
        gates = evaluate(run.counts, prev.counts if prev else None, thresholds or Thresholds())
        gates += [Gate(f"engine {n}", "fail", f"validation did not run: {msg[:300]}") for n, msg in failed_engines.items()]
        run.gates = gates_as_json(gates)
        bad = any(g.status == "fail" for g in gates)
        run.status = "failed" if bad else "passed"
        t0 = time.monotonic()
        built = build_profiles(s, w, say)
        if built:
            steps["profiles"] = f"{built} rebuilt, {time.monotonic() - t0:.0f}s"
    except Exception as e:  # noqa: BLE001 - record the crash in the run, then report it
        s.rollback()
        run = s.merge(run)
        run.status, run.error = "error", f"{type(e).__name__}: {e}"
        disk_full = (isinstance(e, OSError) and e.errno == errno.ENOSPC) or "disk is full" in str(e)  # not a bug: no traceback
        say(f"[red]update crashed[/]: {escape(str(e))}" + ("" if disk_full else f"\n{escape(traceback.format_exc(limit=5))}"))
        prev = previous_baseline(s, run.id)
    run.steps = steps
    run.finished_at = utcnow()
    s.commit()
    report = write_report(w, run, prev, s)
    run.report_path = str(report)
    s.commit()
    code = 0 if run.status == "passed" and not failed_sources else 1
    return UpdateResult(run, str(report), code)
