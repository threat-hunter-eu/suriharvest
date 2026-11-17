"""`suriharvest release build`: a flat, reproducible set of files for publishing (e.g. as GitHub release assets).

Per engine named `suricata-N` (from suriharvest.yaml):
  suricata-N.rules                      merged, deduplicated rules that loaded in that engine (sids stable, sid map)
  suricata-N.by-source.<source>.rules   the same rules split by source (licence boundaries)
  suriharvest-N.tar.gz                  suricata-update source: rules/suricata.rules (one rules file only),
                                        rules/datasets/ (if any), rules/classification.config + rules/reference.config (merged, see
                                        release_extras), NOTICE.md, LICENSES/ (publishers' licence files and full
                                        SPDX licence texts)
Shared:
  manifest.jsonl.gz, summary.json, changes.json, RELEASE_NOTES.md, validation.json, collisions.json, index.yaml,
  NOTICE.md, LICENSES.tar.gz, suricata-overrides.txt, sid-map.tsv, stats.json, recipes.tar.gz (with --recipes-from),
  SHA256SUMS.

Deterministic: no wall-clock time in any file (only --build-epoch), sorted output, tarballs with fixed mtimes.
`content_id` hashes what is published (engine, gid, exported sid, logic hash, rev, and the merged config files), so
an unchanged corpus gives the same id. The manifest also lists rules left out as duplicates of a published logic
(`excluded_reason: duplicate`, `duplicate_of: "gid:exported_sid"`); those rows do not count in content_id, changes
or gates. Release gates compare with `--previous` (a directory holding the last release's summary.json and,
optionally, manifest.jsonl.gz): the build fails when an engine loses more than --max-drop-pct of its rules or a
source loses more than --max-source-drop-pct (or vanishes).
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import re
import shutil
import tarfile
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from suriharvest import __version__
from suriharvest.config import LICENCE_FILE, MAX_LICENCE_BYTES, Workspace, catalog_sources, load_sources, source_root, version_tuple
from suriharvest.models import LogicGroup, Profile, Source, ValidationResult
from suriharvest.portable import rmtree
from suriharvest.release_extras import classtypes_of, duplicate_rows, merged_configs, references_by_source
from suriharvest.urls import public_link, redact_url

SCHEMA_VERSION = 1


class ReleaseError(RuntimeError):
    pass


@dataclass
class ReleaseResult:
    out: Path
    content_id: str
    engines: dict[str, dict[str, Any]]
    gates: list[dict[str, Any]] = field(default_factory=list)
    changes: dict[str, Any] = field(default_factory=dict)

    @property
    def failed(self) -> bool:
        return any(g["status"] == "fail" for g in self.gates)


SID_MAP_HEADER = "# logic_hash\tgid\toriginal_sid\texported_sid\tdate\trule_key\tsource\t[note]\n"


def short_name(engine: str) -> str:
    """suricata-7 -> 7; anything else is used as is."""
    m = re.fullmatch(r"suricata-?(\d+)(?:\.\d+)*", engine)
    return m.group(1) if m else re.sub(r"[^A-Za-z0-9._-]+", "-", engine)


def _engine_version(s: Session, engine: str) -> str | None:
    return s.scalar(
        select(ValidationResult.engine_version)
        .where(ValidationResult.engine == engine)
        .order_by(ValidationResult.checked_at.desc())
        .limit(1)
    )


def _tar_gz(path: Path, files: list[tuple[str, bytes]], epoch: int) -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for name, data in sorted(files):
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.mode, info.uname, info.gname = len(data), epoch, 0o644, "", ""
            tf.addfile(info, io.BytesIO(data))
    with path.open("wb") as fh, gzip.GzipFile(fileobj=fh, mode="wb", mtime=epoch, filename="") as gz:
        gz.write(buf.getvalue())


def _gzip(path: Path, data: bytes, epoch: int) -> None:
    with path.open("wb") as fh, gzip.GzipFile(fileobj=fh, mode="wb", mtime=epoch, filename="") as gz:
        gz.write(data)


def _previous_manifest(prev: Path) -> list[dict[str, Any]]:
    """Every row of the previous release's manifest (published and left-out duplicates)."""
    for name in ("manifest.jsonl.gz", "manifest.jsonl"):
        f = prev / name
        if f.exists():
            raw = gzip.decompress(f.read_bytes()) if name.endswith(".gz") else f.read_bytes()
            return [json.loads(x) for x in raw.decode().splitlines() if x.strip()]
    return []


def _read_previous(prev: Path | None) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    if prev is None:
        return None, []
    summary = json.loads((prev / "summary.json").read_text()) if (prev / "summary.json").exists() else None
    rows: list[dict[str, Any]] = []
    for name in ("manifest.jsonl.gz", "manifest.jsonl"):
        f = prev / name
        if f.exists():
            raw = gzip.decompress(f.read_bytes()) if name.endswith(".gz") else f.read_bytes()
            rows = [json.loads(x) for x in raw.decode().splitlines() if x.strip()]
            rows = [r for r in rows if not r.get("excluded_reason")]  # published rules only
            break
    return summary, rows


def build(
    s: Session,
    ws: Workspace,
    out: Path,
    *,
    engines: list[str],
    redistributable_only: bool = True,
    recipes_from: Path | None = None,
    download_base: str = "",
    build_epoch: int = 0,
    previous: Path | None = None,
    gates: bool = True,
    max_drop_pct: float = 5.0,
    max_source_drop_pct: float = 50.0,
) -> ReleaseResult:
    known = {e.name: e for e in ws.settings().engines}
    missing = [e for e in engines if e not in known]
    if missing:
        raise ReleaseError(f"engine(s) not in suriharvest.yaml: {', '.join(missing)}")
    if not engines:
        raise ReleaseError("no engine given")
    # An engine that never validated (it cannot run, or was just added) would give an empty or unchecked build.
    unvalidated = [e for e in engines if not _engine_version(s, e)]
    if unvalidated:
        raise ReleaseError(
            f"engine(s) without validation results: {', '.join(unvalidated)} (does the engine run? `suriharvest doctor`, "
            "then `suriharvest update` or `suriharvest validate`); refusing to build"
        )
    if out.exists() and any(out.iterdir()):
        raise ReleaseError(f"{out} is not empty")
    created = not out.exists()
    out.mkdir(parents=True, exist_ok=True)
    try:
        return _build(
            s,
            ws,
            out,
            engines=engines,
            redistributable_only=redistributable_only,
            recipes_from=recipes_from,
            download_base=download_base,
            build_epoch=build_epoch,
            previous=previous,
            gates=gates,
            max_drop_pct=max_drop_pct,
            max_source_drop_pct=max_source_drop_pct,
        )
    except BaseException:
        # never leave a partial build behind (the folder was empty or new)
        rmtree(out, ignore_errors=True)
        if not created:
            out.mkdir(parents=True, exist_ok=True)
        raise


def _build(
    s: Session,
    ws: Workspace,
    out: Path,
    *,
    engines: list[str],
    redistributable_only: bool,
    recipes_from: Path | None,
    download_base: str,
    build_epoch: int,
    previous: Path | None,
    gates: bool,
    max_drop_pct: float,
    max_source_drop_pct: float,
) -> ReleaseResult:
    from suriharvest.export import export
    from suriharvest.profiles import select_rules
    from suriharvest.validate import OVERRIDES

    known = {e.name: e for e in ws.settings().engines}
    when = datetime.fromtimestamp(build_epoch, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    sources = {r.name: r for r in s.scalars(select(Source))}
    configs = {c.name: c for c in load_sources(ws)}
    from suriharvest.majors import load_views, major_of

    views = load_views(s)  # per-major copies (majors.py): each engine builds from its own major's ruleset
    all_notices: dict[str, set[tuple[str, ...]]] = {}  # every engine's copy, for the release NOTICE.md / LICENSES
    all_holders: dict[str, list[str]] = {}
    manifest: list[dict[str, Any]] = []
    changes_by_source: dict[str, dict[str, int]] = {}  # source -> rules changed by the build (largest over engines)
    duplicates: list[dict[str, Any]] = []  # excluded rows (manifest only; not in content_id or changes)
    config_digests: list[str] = []
    eng_summary: dict[str, dict[str, Any]] = {}
    from suriharvest.sidmap import holders_from_manifest

    prev_summary, prev_rows = _read_previous(previous)
    collisions: list[dict[str, Any]] = []
    produced: list[str] = []
    for engine in engines:
        n = short_name(engine)
        # a transient profile: every enabled, non-junk rule, global exclusions, newest revision per rule key
        prof = Profile(name=f"release-{n}", query="", unit="logic", engine=engine, options={"redistributable_only": redistributable_only})
        sel = select_rules(s, prof, views=views)
        loads = {h for (h,) in s.execute(select(LogicGroup.logic_hash).where(func.instr(LogicGroup.loads_in, f'"{engine}"') > 0))}
        version = _engine_version(s, engine) or ""
        major = major_of(version) if views else None
        notices = {x: upstream_notices(_source_root(x, configs.get(x), ws, major)) for x in sources}
        file_holders = publisher_holders(sorted(sources), sources, configs, ws, major)
        for x, blocks in notices.items():
            all_notices.setdefault(x, set()).update(tuple(b) for b in blocks)
        for x, lines in file_holders.items():
            all_holders[x] = all_holders.get(x, []) + [y for y in lines if y not in all_holders.get(x, [])]
        # sources written for a newer Suricata (min_suricata) only go into the builds of engines that are new enough
        too_new = {n for n, c in configs.items() if c.min_suricata and version_tuple(c.min_suricata) > version_tuple(version)}
        hashes = [g.logic_hash for g in sel.kept if g.logic_hash in loads and g.canonical_source not in too_new]
        if not hashes:
            raise ReleaseError(
                f"engine {engine}: no publishable rule loads in it ({len(loads)} logics load in it in all); refusing a 0-rule build"
            )
        with tempfile.TemporaryDirectory(prefix="suriharvest-release-") as tmp:
            rep = export(
                s,
                Path(tmp),
                logic_hashes=hashes,
                redistributable_only=redistributable_only,
                remap_sids=True,
                remap_base=ws.settings().remap_base,
                sid_map=ws.sid_map_file,
                forbid={g.logic_hash for g, _, _ in sel.excluded},
                split_by_source=True,
                previous_holders=holders_from_manifest(r for r in prev_rows if r.get("engine") in (None, engine)),
                ws=ws,
                sid_map_today=when[:10] if build_epoch else None,
                engine=engine,
                views=views,
            )
            rows = [json.loads(x) for x in (Path(tmp) / "manifest.jsonl").read_text().splitlines() if x]
            # dataset files: export wrote them under datasets/<source>/ with the rule paths (and clashing names) rewritten
            ds_files = {p: (Path(tmp) / p).read_bytes() for p in sorted(rep.dataset_files)}
            if not rows:
                raise ReleaseError(f"engine {engine}: no rule left to publish; refusing a 0-rule build")

            def publish(text: str) -> str:
                # "\n" only: Suricata splits lines on "\n", str.splitlines also on \x0b \x0c \x1c-\x1e \x85 ...
                return "".join(x.rstrip("\r") + "\n" for x in text.split("\n") if x.strip() and not x.startswith("#"))

            # one section per source, in source order (Suricata does not depend on the order of rules)
            sections: dict[str, str] = {}
            for f in sorted((Path(tmp) / "by-source").glob("*.rules")):
                text = publish(f.read_text(encoding="utf-8"))
                if text.count("\n"):
                    sections[f.stem] = text
            in_build = sorted(sections)
            no_text = missing_licence_texts(in_build, sources)
            if no_text:
                raise ReleaseError(
                    f"no bundled licence text for {', '.join(no_text)}: add the SPDX text to src/suriharvest/licences/ "
                    "or leave the source out of the build"
                )
            missing = missing_attribution(in_build, sources, configs, notices, file_holders)
            if missing:
                raise ReleaseError(
                    f"no copyright line for {', '.join(missing)}: their licence asks for the copyright notice to be kept. Add "
                    "`copyright:` to the source in sources.yaml (the holder line of the publisher's LICENSE or feed header; "
                    "for a publisher that states none, name it and say so), then build again"
                )
            remapped_by: dict[str, int] = {}
            for r in rows:
                if r.get("exported_sid") != r.get("sid"):
                    remapped_by[r["source"]] = remapped_by.get(r["source"], 0) + 1
            for x in in_build:
                m = changes_by_source.setdefault(x, {"remapped": 0, "datasets": 0})
                m["remapped"] = max(m["remapped"], remapped_by.get(x, 0))
                m["datasets"] = max(m["datasets"], rep.dataset_rewritten.get(x, 0))
            body = "".join(
                _comment(f"---- source {x} ({sources[x].licence or 'unknown'}): {sections[x].count(chr(10))} rules ----") + sections[x]
                for x in in_build
            )
            merged = (
                f"# suriharvest {engine}: {len(rows)} rules, build {when}\n"
                + _licence_block(in_build, sources, download_base, n)
                + _changes_line(when, remapped_by, rep.dataset_rewritten, in_build)
                + _merged_header(in_build, notices, configs, file_holders)
                + body
            )
            _check_count(f"suricata-{n}.rules", merged, len(rows))
            (out / f"suricata-{n}.rules").write_text(merged, encoding="utf-8", newline="\n")
            produced.append(f"suricata-{n}.rules")
            tar_files = [("rules/suricata.rules", merged.encode())]
            by_source: dict[str, dict[str, int]] = {}
            for x in in_build:
                count = sections[x].count("\n")
                text = (
                    _source_header(x, notices, holders(x, configs.get(x), notices, file_holders))
                    + _licence_block([x], sources, download_base, n)
                    + _changes_line(when, remapped_by, rep.dataset_rewritten, [x])
                    + sections[x]
                )
                name = f"suricata-{n}.by-source.{x}.rules"
                _check_count(name, text, count)
                (out / name).write_text(text, encoding="utf-8", newline="\n")
                produced.append(name)
                by_source[x] = {"rules": count, "enabled": count}
        class_conflicts: list[dict[str, Any]] = []
        cfg_files = merged_configs(
            [(x, _source_root(x, configs.get(x), ws, major)) for x in sorted(by_source, key=lambda x: (sources[x].priority, x))],
            classtypes_of(s, {r["logic_hash"] for r in rows}),
            references_by_source(s, rows),
            conflicts=class_conflicts,
        )
        tar_files += [(f"rules/{k}", v) for k, v in cfg_files.items()]
        config_digests += [f"{engine}\t{k}\t{hashlib.sha256(v).hexdigest()}\n" for k, v in sorted(cfg_files.items())]
        # dataset contents are published content: a changed IOC list is a new release
        config_digests += [f"{engine}\tdataset\t{p}\t{hashlib.sha256(d).hexdigest()}\n" for p, d in sorted(ds_files.items())]
        if ds_files:
            # relative `load datasets/<source>/...` resolves next to the rule file (rules/). The tarball carries
            # suricata.rules only: suricata-update loads every *.rules member, per-source copies would be duplicates.
            tar_files += [(f"rules/{p}", data) for p, data in ds_files.items()]
            _tar_gz(out / f"suricata-{n}.datasets.tar.gz", list(ds_files.items()), build_epoch)
            produced.append(f"suricata-{n}.datasets.tar.gz")
        names = sorted(by_source)
        filled = filled_ids(names, sources, configs, ws, notices, file_holders, major)
        notice = _notice(names, sources, configs, notices, filled, file_holders, changes_by_source, when)
        tar_files.append(("NOTICE.md", notice.encode()))
        tar_files += _licence_files(names, sources, configs, ws, notices, file_holders, major)
        _tar_gz(out / f"suriharvest-{n}.tar.gz", tar_files, build_epoch)
        produced.append(f"suriharvest-{n}.tar.gz")
        held_by = {(r["gid"], r["exported_sid"]): r["source"] for r in rows}
        for r in rows:
            manifest.append(
                {
                    "engine": engine,
                    **{
                        k: r.get(k)
                        for k in ("gid", "sid", "exported_sid", "rev", "rule_key", "source", "licence", "logic_hash", "flags", "msg")
                    },
                }
            )
            if r.get("exported_sid") != r.get("sid"):
                collisions.append(
                    {
                        "engine": engine,
                        "gid": r["gid"],
                        "sid": r["sid"],
                        "exported_sid": r["exported_sid"],
                        "logic_hash": r["logic_hash"],
                        "source": r["source"],
                        "rule_key": r.get("rule_key"),
                        "msg": r.get("msg"),
                        "sid_kept_by": held_by.get((r["gid"], r["sid"])),
                    }
                )
        duplicates += duplicate_rows(s, engine, rows, set(by_source), major)
        eng_summary[engine] = {
            "version": version,
            "image": known[engine].image,
            "rules": len(rows),
            "enabled": len(rows),
            "flowbit_setters_added": rep.setters_added,
            "dataset_files": sorted(ds_files),
            "left_out_missing_files": len(rep.left_out_datasets),
            "left_out_datasets": rep.left_out_datasets,
            "dataset_renames": rep.dataset_renames,
            "classtype_conflicts": class_conflicts,
            "left_out_licence": rep.skipped_licence,
            "by_source": by_source,
        }
    manifest.sort(key=lambda r: (r["engine"], r["gid"], r["exported_sid"], r["logic_hash"]))
    notices = {x: [list(b) for b in sorted(bs)] for x, bs in all_notices.items()}
    file_holders = {x: lines[:20] for x, lines in all_holders.items()}
    # retirement needs the previous release's manifest (sidmap_check.py refuses it otherwise); every row of both
    # manifests counts, left-out duplicates included
    retired = _retire_sid_map(ws, manifest + duplicates, _previous_manifest(previous)) if previous is not None and prev_rows else 0
    content_id = hashlib.sha256(
        (
            f"{SCHEMA_VERSION}\n"
            + "".join(f"{r['engine']}\t{r['gid']}\t{r['exported_sid']}\t{r['logic_hash']}\t{r['rev']}\n" for r in manifest)
            + "".join(config_digests)
        ).encode()
    ).hexdigest()
    _gzip(out / "manifest.jsonl.gz", "".join(json.dumps(r, sort_keys=True) + "\n" for r in manifest + duplicates).encode(), build_epoch)
    # changes and gates against the previous release
    from suriharvest.sidmap import SidMap

    notes = {h: e.note for h, e in SidMap(ws.sid_map_file).entries.items() if e.note}
    changes = (
        _changes(prev_rows, manifest, notes)
        if prev_rows
        else {"added": [], "removed": [], "modified": [], "reclaimed": [], "moved": [], "previous": None}
    )
    gate_list = _gates(prev_summary, eng_summary, max_drop_pct, max_source_drop_pct) if gates else []
    src_rows = []
    for name in sorted({x for e in eng_summary.values() for x in e["by_source"]}):
        row, cfg = sources.get(name), configs.get(name)
        src_rows.append(
            {
                "name": name,
                "url": redact_url(row.url) if row else None,
                "licence": row.licence if row else None,
                "redistribute": row.redistribute if row else None,
                "status": cfg.status if cfg else None,
                "rules": {e: v["by_source"].get(name, {}).get("rules", 0) for e, v in eng_summary.items()},
            }
        )
    summary = {
        "schema_version": SCHEMA_VERSION,
        "content_id": content_id,
        "generated_at": when,
        "suriharvest": __version__,
        "redistributable_only": redistributable_only,
        "engines": eng_summary,
        "sources": src_rows,
        "gates": gate_list,
        "sid_map_retired": retired,
    }
    all_names = sorted({x for e in eng_summary.values() for x in e["by_source"]})
    files: dict[str, str] = {
        "summary.json": json.dumps(summary, indent=2, sort_keys=True) + "\n",
        "changes.json": json.dumps(changes, indent=2, sort_keys=True) + "\n",
        "collisions.json": json.dumps(sorted(collisions, key=lambda c: (c["engine"], c["sid"], c["exported_sid"])), indent=2) + "\n",
        "validation.json": json.dumps(_validation(s, engines), indent=2, sort_keys=True) + "\n",
        "NOTICE.md": _notice(
            all_names,
            sources,
            configs,
            notices,
            filled_ids(all_names, sources, configs, ws, notices, file_holders),
            file_holders,
            changes_by_source,
            when,
        ),
        "suricata-overrides.txt": "".join(f"--set {o}\n" for o in OVERRIDES),
        "index.yaml": _index_yaml(eng_summary, download_base, {n: r.licence for n, r in sources.items()}),
        "RELEASE_NOTES.md": _notes(summary, changes),
        "stats.json": json.dumps(
            {"content_id": content_id, "generated_at": when, "rules": {e: v["rules"] for e, v in eng_summary.items()}}, sort_keys=True
        )
        + "\n",
    }
    for name, text in files.items():
        (out / name).write_text(text, encoding="utf-8", newline="\n")
    produced += [*files, "manifest.jsonl.gz"]
    _tar_gz(out / "LICENSES.tar.gz", _licence_files(all_names, sources, configs, ws, notices, file_holders), build_epoch)
    produced.append("LICENSES.tar.gz")
    # the full text of every licence in the build as its own asset, next to the loose .rules files that link to it
    ids = {i for x in all_names for i in spdx_ids(sources[x].licence if x in sources else None)}
    ids |= {c for i in ids for c in _LICENCE_COMPANIONS.get(_LICENCE_ALIASES.get(i, i), ())}
    for i in sorted(ids):
        if (t := licence_text(i)) is not None:
            (out / f"LICENSES.{i}.txt").write_bytes(t)
            produced.append(f"LICENSES.{i}.txt")
    if ws.sid_map_file.exists():
        if ws.sid_map_file.stat().st_size:
            shutil.copyfile(ws.sid_map_file, out / "sid-map.tsv")
        else:  # no clash yet: GitHub refuses a 0-byte release asset, so ship the column header (a comment) instead
            (out / "sid-map.tsv").write_text(SID_MAP_HEADER, encoding="utf-8", newline="\n")
        produced.append("sid-map.tsv")
    if recipes_from is not None:
        _recipes(out / "recipes.tar.gz", recipes_from, build_epoch)
        produced.append("recipes.tar.gz")
    sums = "".join(f"{hashlib.sha256((out / f).read_bytes()).hexdigest()}  {f}\n" for f in sorted(set(produced)))
    (out / "SHA256SUMS").write_text(sums, encoding="utf-8", newline="\n")
    return ReleaseResult(out, content_id, eng_summary, gate_list, changes)


def _retire_sid_map(ws: Workspace, manifest: list[dict[str, Any]], prev_rows: list[dict[str, Any]]) -> int:
    """Remove the sid map rows of rules that neither this release nor the previous one publishes (sidmap.retire):
    the map holds rules that are out there, so it does not grow with every rule that ever clashed."""
    from suriharvest.sidmap import SidMap

    if not ws.sid_map_file.exists():
        return 0
    rows = manifest + prev_rows
    smap = SidMap(ws.sid_map_file)
    gone = smap.retire(
        {r["logic_hash"] for r in rows if r.get("logic_hash")},
        {(r["source"], r["rule_key"]) for r in rows if r.get("source") and r.get("rule_key")},
    )
    smap.save()
    return len(gone)


def _changes(prev: list[dict[str, Any]], now: list[dict[str, Any]], notes: dict[str, str] | None = None) -> dict[str, Any]:
    """added / removed / modified rules against the previous release. `reclaimed`: rules whose exported sid moved
    because the sidallocation.org owner of the sid reclaimed it (sid map note reclaimed_by= / owner_reclaim=).
    `moved`: every other published sid that moved (adding an engine major can remap a rule that only
    clashes in the new major's ruleset, in every engine's build)."""
    notes = notes or {}
    a = {(r["engine"], r["logic_hash"]): r for r in prev}
    b = {(r["engine"], r["logic_hash"]): r for r in now}

    def brief(r: dict[str, Any]) -> dict[str, Any]:
        return {k: r.get(k) for k in ("engine", "logic_hash", "exported_sid", "rev", "source")}

    modified, reclaimed, moved = [], [], []
    for k in sorted(a.keys() & b.keys()):
        what = [f"{f} {a[k].get(f)} -> {b[k].get(f)}" for f in ("rev", "exported_sid", "source") if a[k].get(f) != b[k].get(f)]
        if what:
            modified.append({**brief(b[k]), "change": "; ".join(what)})
        if a[k].get("exported_sid") != b[k].get("exported_sid"):
            row = {**brief(b[k]), "gid": b[k].get("gid"), "previous_sid": a[k].get("exported_sid")}
            if notes.get(k[1]):
                reclaimed.append({**row, "reason": notes[k[1]]})
            else:  # e.g. a second engine major: a clash in its ruleset remaps the rule in every engine (one sid map)
                moved.append({**row, "reason": "sid clash recorded in the shared sid map"})
    return {
        "added": [brief(b[k]) for k in sorted(b.keys() - a.keys())],
        "removed": [brief(a[k]) for k in sorted(a.keys() - b.keys())],
        "modified": modified,
        "reclaimed": reclaimed,
        "moved": moved,
    }


def _gates(prev: dict[str, Any] | None, now: dict[str, dict[str, Any]], max_drop: float, max_src_drop: float) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not prev:
        return [{"name": "previous release", "status": "skipped", "detail": "no previous summary.json"}]
    for engine, cur in now.items():
        old = (prev.get("engines") or {}).get(engine)
        if not old:
            out.append({"name": f"rules {engine}", "status": "skipped", "detail": "engine not in the previous release"})
            continue
        before, after = old.get("rules", 0), cur["rules"]
        drop = 100.0 * (before - after) / before if before else 0.0
        st = "fail" if drop > max_drop else "pass"
        out.append({"name": f"rules {engine}", "status": st, "detail": f"{before:,} -> {after:,} ({-drop:+.1f}%, limit -{max_drop}%)"})
        for src, v in (old.get("by_source") or {}).items():
            b, a = v.get("rules", 0), cur["by_source"].get(src, {}).get("rules", 0)
            d = 100.0 * (b - a) / b if b else 0.0
            if a == 0 and b > 0:
                out.append({"name": f"source {src} ({engine})", "status": "fail", "detail": f"vanished ({b:,} rules before)"})
            elif d > max_src_drop:
                out.append(
                    {"name": f"source {src} ({engine})", "status": "fail", "detail": f"{b:,} -> {a:,} (-{d:.1f}%, limit -{max_src_drop}%)"}
                )
    return out


def _validation(s: Session, engines: list[str]) -> dict[str, Any]:
    """Per canonical source and engine: logics that load and fail (with error categories)."""
    out: dict[str, Any] = {}
    for src, loads, fails in s.execute(select(LogicGroup.canonical_source, LogicGroup.loads_in, LogicGroup.fails_in)):
        for e in engines:
            d = out.setdefault(src, {}).setdefault(e, {"loads": 0, "fails": 0})
            d["loads"] += e in (loads or [])
            d["fails"] += e in (fails or [])
    return out


def _notice(
    names: list[str],
    sources: dict[str, Source],
    configs: dict[str, Any],
    notices: dict[str, list[list[str]]] | None = None,
    filled: dict[str, list[str]] | None = None,
    file_holders: dict[str, list[str]] | None = None,
    changes: dict[str, dict[str, int]] | None = None,
    when: str = "",
) -> str:
    notices, filled, changes = notices or {}, filled or {}, changes or {}
    any_ds = any(v.get("datasets") for v in changes.values())
    lines = [
        (
            "# NOTICE\n\nThis ruleset is a merged, deduplicated build of the sources below. Each rule keeps its publisher's\n"
            "licence; the merged rules file is ordered by source, with a `# ---- source NAME (LICENCE) ----` line before\n"
            "each source's rules, and manifest.jsonl.gz maps every rule to its source and licence.\n\n"
            + (f"Changes suriharvest made to rule text (build {when}):\n\n" if when else "Changes suriharvest makes to rule text:\n\n")
            + "- a rule whose gid:sid is used by another publisher's rule gets a new sid (each one is listed in\n"
            "  collisions.json);\n"
            + (
                "- a rule that loads a dataset file gets that file's path rewritten to `datasets/<source>/...` (and a\n"
                "  dataset name that two sources define differently is renamed, see summary.json `dataset_renames`);\n"
                if any_ds or not changes
                else ""
            )
            + "- nothing else: profile `modify` and `thresholds` overrides are not applied to a release build. Comment lines\n"
            "  of the publishers' files and rules they ship disabled are not copied (their leading notices are kept below\n"
            "  and on top of the per-source files).\n\n"
            "The number of changed rules is listed per source below.\n\n"
            "The full text of every licence named here is in `LICENSES/texts/<SPDX id>.txt` (in LICENSES.tar.gz and in each\n"
            "suriharvest-N.tar.gz, and as the release asset `LICENSES.<SPDX id>.txt`), next to the licence files each\n"
            "publisher ships (`LICENSES/<source>/`).\n\n"
            "| source | licence | homepage / url |\n|---|---|---|\n"
        )
    ]
    for n in names:
        row, cfg = sources.get(n), configs.get(n)
        home = _public_link(row, cfg)
        lines.append(f"| {n} | {(row.licence if row else '') or 'unknown'} | {home} |\n")
    lines.append("\n## Copyright and attribution\n")
    for n in names:
        row, cfg = sources.get(n), configs.get(n)
        licence = (row.licence if row else None) or "unknown"
        home = _public_link(row, cfg)
        lines.append(f"\n### {n}\n\nLicence: {licence}")
        texts = [
            f"`LICENSES/{n}/LICENSE.{i}.txt`" if i in filled.get(n, []) else f"`LICENSES/texts/{i}.txt`"
            for i in spdx_ids(licence)
            if licence_text(i) is not None
        ]
        lines.append(f" (full text: {', '.join(texts)})\n" if texts else "\n")
        hs = holders(n, cfg, notices, file_holders)
        if hs:
            lines.append("\n" + "".join(f"- {_md_safe(h)}\n" for h in hs))
        else:
            lines.append(f"\nRules (c) their publisher, the maintainers of {n}" + (f" ({home})" if home else "") + ".\n")
        if n in changes:
            c = changes[n]
            what = [f"{c['remapped']} sid(s) remapped"] if c.get("remapped") else []
            what += [f"{c['datasets']} dataset load path(s) rewritten"] if c.get("datasets") else []
            lines.append(
                f"\nChanged by suriharvest{(' on ' + when[:10]) if when else ''}: {', '.join(what)}.\n"
                if what
                else "\nRule text as published (no rule changed).\n"
            )
        for block in notices.get(n, []):
            text = "\n".join(block).replace("```", "` ` `")
            lines.append("\nNotice shipped with the rules (verbatim):\n\n```\n" + text + "\n```\n")
    return "".join(lines)


# Licences whose text asks for nothing to be kept: no copyright line is needed to redistribute them.
NO_ATTRIBUTION = frozenset({"CC0-1.0", "0BSD", "Unlicense", "MIT-0", "PDDL-1.0"})
# Licence texts that are templates ("Copyright (c) <year> <copyright holders>"): a filled-in copy per source is
# published as LICENSES/<source>/LICENSE.<id>.txt when the source ships no licence file of its own.
TEMPLATE_LINE = {
    "MIT": "Copyright (c) <year> <copyright holders>",
    "BSD-2-Clause": "Copyright (c) <year> <owner>",
    "BSD-3-Clause": "Copyright (c) <year> <owner>.",
}


def needs_attribution(licence: str | None) -> bool:
    """Does redistributing under this licence require keeping a copyright notice? Free text or unknown: yes."""
    ids = spdx_ids(licence)
    return not ids or any(i not in NO_ATTRIBUTION for i in ids)


def holders(name: str, cfg: Any, notices: dict[str, list[list[str]]], file_holders: dict[str, list[str]] | None = None) -> list[str]:
    """Copyright lines of a source: the catalog / sources.yaml `copyright:` field first, then the lines found in the
    publisher's own notice block on top of its rules, then those in the licence files it ships (`file_holders`,
    see publisher_holders), deduplicated."""
    out = [x.strip() for x in (getattr(cfg, "copyright", None) or "").splitlines() if x.strip()]
    for x in copyright_lines(notices.get(name, [])) + (file_holders or {}).get(name, []):
        if x not in out:
            out.append(x)
    return out


def publisher_holders(
    names: list[str], sources: dict[str, Source], configs: dict[str, Any], ws: Workspace, major: str | None = None
) -> dict[str, list[str]]:
    """Copyright lines found in the licence files each redistributable source ships (LICENSE, COPYING, NOTICE ...;
    for git sources the files sync keeps from the repository root)."""
    out: dict[str, list[str]] = {}
    for n in names:
        lines: list[str] = []
        for _, f in _publisher_files(n, sources.get(n), configs.get(n), ws, major):
            head = f.read_bytes()[:16384].decode("utf-8", "replace").splitlines()[:80]
            lines += [x for x in copyright_lines([[_CTRL.sub("", t)[:300] for t in head]]) if x not in lines]
        if lines:
            out[n] = lines[:20]
    return out


def missing_attribution(
    names: list[str],
    sources: dict[str, Source],
    configs: dict[str, Any],
    notices: dict[str, list[list[str]]],
    file_holders: dict[str, list[str]] | None = None,
) -> list[str]:
    """Sources in a build whose licence asks for a copyright notice but that have no copyright line: no
    `copyright:` field, none in the publisher's notice block, none in its licence files."""
    return [
        n
        for n in names
        if needs_attribution(sources[n].licence if n in sources else None) and not holders(n, configs.get(n), notices, file_holders)
    ]


def filled_text(spdx_id: str, lines: list[str]) -> bytes | None:
    """The SPDX template text of `spdx_id` with its copyright placeholder line replaced by `lines`."""
    line, text = TEMPLATE_LINE.get(spdx_id), licence_text(spdx_id)
    if line is None or text is None or not lines:
        return None
    decoded = text.decode("utf-8")
    if line not in decoded:
        return None
    return decoded.replace(line, "\n".join(lines), 1).encode("utf-8")


def _md_safe(text: str) -> str:
    return re.sub(r"[<>`|\[\]]", " ", text)


# ---------------------------------------------------------------------------------------------------------------
# upstream copyright notices: the comment block at the top of a publisher's rules files (e.g. ET's
# "Copyright (c) 2003-2026, Emerging Threats" + BSD conditions + GPL pointer), kept in NOTICE.md and verbatim on
# top of the by-source files (BSD-3-Clause clause 1-2 and GPL-2.0 ask for it when the rules are redistributed).

MAX_NOTICE_FILES = 2000
MAX_NOTICE_BLOCKS = 3
MAX_NOTICE_LINES = 80
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_RULE_WORD = re.compile(r"(alert|drop|reject\w*|pass|accept|config)\s")


def _source_root(n: str, cfg: Any, ws: Workspace, major: str | None = None) -> Path:
    """A source's folder; for a source downloaded per Suricata major, the copy of `major` (the newest when None)."""
    from suriharvest.majors import PER_MAJOR_TYPES, variant_dir

    root = source_root(ws, n, cfg)
    return variant_dir(root, major) if cfg is None or cfg.type in PER_MAJOR_TYPES else root


def upstream_notices(root: Path) -> list[list[str]]:
    """Distinct leading comment blocks of the rules files under `root` that mention a copyright or a licence
    (verbatim, "#" stripped, control characters removed, size capped). Sorted, so builds stay reproducible."""
    blocks: set[tuple[str, ...]] = set()
    if not root.is_dir() or root.is_symlink():
        return []
    files = sorted(p for p in root.rglob("*.rules") if p.is_file() and not p.is_symlink())[:MAX_NOTICE_FILES]
    for f in files:
        with f.open("rb") as fh:
            head = fh.read(64 * 1024).decode("utf-8", "replace")
        block: list[str] = []
        for line in head.splitlines()[: MAX_NOTICE_LINES * 2]:
            t = line.strip()
            if not t:
                if block:
                    block.append("")
                continue
            if not t.startswith("#"):
                break
            # a trailing backslash would continue the comment onto the next line in Suricata: never copy one
            body = _CTRL.sub("", t.lstrip("#").strip()).rstrip("\\ \t")
            if _RULE_WORD.match(body):
                break  # a disabled rule: the header is over
            block.append(body[:300])
        while block and not block[-1]:
            block.pop()
        if block and re.search(r"copyright|licen[cs]e|\(c\)|\u00a9", " ".join(block), re.IGNORECASE):
            blocks.add(tuple(block[:MAX_NOTICE_LINES]))
    return [list(b) for b in sorted(blocks)][:MAX_NOTICE_BLOCKS]


# A copyright notice line starts with "Copyright" followed by (c), (C), the sign or a year, or with "(c) <year>" /
# "\u00a9 <year>". Licence conditions that merely mention copyright ("Redistributions ... must retain the above
# copyright notice", "THE COPYRIGHT HOLDERS AND CONTRIBUTORS ...") and template lines ("<year> <copyright holders>")
# are not holders.
_COPYRIGHT_LINE = re.compile(r"^[\s*#-]*(?:copyright\s*(?:\(c\)|\u00a9|\d)|(?:\(c\)|\u00a9)\s*\d)", re.IGNORECASE)


# The copyright of a licence TEXT (the GPL's "Copyright (C) 1989, 1991 Free Software Foundation, Inc.") is not the
# copyright of the rules it ships with.
_LICENCE_STEWARD = re.compile(r"Free Software Foundation|Creative Commons Corporation|Mozilla Foundation", re.IGNORECASE)


def copyright_lines(blocks: list[list[str]]) -> list[str]:
    out: list[str] = []
    for b in blocks:
        for line in b:
            t = line.strip().lstrip("#*- \t").strip()  # a "#  Copyright ..." line of a commented LICENSE file
            if _COPYRIGHT_LINE.match(t) and "<" not in t and not _LICENCE_STEWARD.search(t) and t not in out:
                out.append(t)
    return out[:20]


def _source_header(name: str, notices: dict[str, list[list[str]]], holder_lines: list[str] | None = None) -> str:
    """Comment block on top of a by-source file: the publisher's copyright lines and its own notice, verbatim."""
    out = [f"# Rules from source {name}. Licence and attribution: NOTICE.md and LICENSES/.\n"]
    blocks = notices.get(name, [])
    shown = {x.strip() for b in blocks for x in b}
    extra = [x for x in holder_lines or [] if x not in shown]
    if extra:
        out.append("#\n" + "".join(_comment(x) for x in extra))
    for block in blocks:
        out.append("#\n" + "".join(_comment(x) for x in block))
    out.append("#\n")  # a plain last line: nothing in the header can run into the first rule
    return "".join(out)


def _asset(name: str, base: str) -> str:
    return f"{base.rstrip('/')}/{name}" if base else name


def _licence_block(names: list[str], sources: dict[str, Source], base: str, n: str) -> str:
    """Licence header of a loose rules file: the licences of the rules in it, each with the
    release asset holding its full text and the SPDX page, and where NOTICE.md, the publishers' licence files and
    the per-rule map are. The same text is in suriharvest-N.tar.gz next to rules/ (NOTICE.md, LICENSES/)."""
    ids = sorted({i for x in names for i in spdx_ids(sources[x].licence if x in sources else None)})
    out = ["# Licences of the rules in this file (each rule keeps its publisher's licence):\n"]
    for i in ids:
        text = f"LICENSES.{i}.txt" if licence_text(i) is not None else None
        out.append(_comment(f"  {i}: " + (f"full text {_asset(text, base)} ; " if text else "") + f"https://spdx.org/licenses/{i}.html"))
    free = [x for x in names if x in sources and not spdx_ids(sources[x].licence)]
    out += [_comment(f"  {x}: {sources[x].licence or 'unknown'} (see NOTICE.md)") for x in free]
    out.append(_comment(f"Copyright notices and attribution: {_asset('NOTICE.md', base)}"))
    out.append(
        _comment(f"Publishers' licence files and all licence texts: {_asset('LICENSES.tar.gz', base)} (also in suriharvest-{n}.tar.gz)")
    )
    out.append(_comment(f"Source and licence of every rule: {_asset('manifest.jsonl.gz', base)}"))
    return "".join(out)


def _changes_line(when: str, remapped: dict[str, int], datasets: dict[str, int], names: list[str]) -> str:
    """The modification notice of a rules file (GPL-2.0 2(a), GPL-3.0 5(a), CC BY 3(a)(1)(B)): what was changed,
    how many rules, and the build date."""
    r = sum(remapped.get(x, 0) for x in names)
    d = sum(datasets.get(x, 0) for x in names)
    what = [f"{r} sid(s) remapped (collisions.json)"] if r else []
    what += [f"{d} dataset load path(s) rewritten"] if d else []
    if not what:
        return _comment(f"Rule text as published; build {when[:10]}. Comment lines and disabled rules are not copied.")
    return _comment(
        f"Changed by suriharvest on {when[:10]}: {', '.join(what)}; no other change to rule text. Comment lines and "
        "disabled rules are not copied."
    )


def _merged_header(
    names: list[str],
    notices: dict[str, list[list[str]]],
    configs: dict[str, Any] | None = None,
    file_holders: dict[str, list[str]] | None = None,
) -> str:
    out = [
        "# Each rule keeps its publisher's licence: NOTICE.md lists them with their copyright notices and\n",
        "# LICENSES/ holds the licence texts. Copyright notices of the publishers in this file:\n",
    ]
    for n in names:
        lines = holders(n, (configs or {}).get(n), notices, file_holders)
        out += [_comment(f"  {n}: {x}") for x in lines] or [f"#   {n}: see NOTICE.md\n"]
    out.append("#\n")
    return "".join(out)


def _comment(text: str) -> str:
    """One `#` comment line of copied upstream text: no control characters, no trailing backslash (Suricata would
    join the next line, i.e. the first rule, into the comment)."""
    return f"# {_CTRL.sub('', text)}".rstrip().rstrip("\\").rstrip() + "\n"


def loaded_rule_count(text: str) -> int:
    """Rules Suricata would read from `text`: lines ending in a backslash are joined with the next one first,
    then every logical line that is neither empty nor a comment counts."""
    n, buf = 0, ""
    for line in text.split("\n"):  # "\n" only, like Suricata (and parser.logical_lines)
        if line.endswith("\\"):
            buf += line[:-1]
            continue
        logical, buf = buf + line, ""
        if logical.strip() and not logical.lstrip().startswith("#"):
            n += 1
    return n + (1 if buf.strip() and not buf.lstrip().startswith("#") else 0)


def _check_count(name: str, text: str, want: int) -> None:
    got = loaded_rule_count(text)
    if got != want:
        raise ReleaseError(f"{name}: Suricata would read {got} rules, expected {want} (a header line swallowed a rule?)")


def _public_link(row: Source | None, cfg: Any) -> str:
    """Homepage when the source has one (the fetch URL is never shown then), else the redacted fetch URL."""
    return public_link(cfg.homepage if cfg is not None else None, row.url if row else None)


SPDX_EXPR = re.compile(r"^[A-Za-z0-9.+-]+(?: (?:AND|OR|WITH) [A-Za-z0-9.+-]+)*$")
MAX_LICENCE_DEPTH = 3


def spdx_ids(expr: str | None) -> list[str]:
    """SPDX ids of a licence expression ("BSD-3-Clause AND GPL-2.0-only"); [] when it is free text."""
    if not expr or not SPDX_EXPR.fullmatch(expr.strip()):
        return []
    return sorted({x for x in expr.split() if x not in ("AND", "OR", "WITH")})


def _safe_file(root: Path, rel: str) -> Path | None:
    """root/rel when it is a regular file inside root, reached without symlinks or .git, small enough."""
    parts = Path(rel).parts
    if not parts or Path(rel).is_absolute() or ".." in parts or ".git" in parts:
        return None
    cur = root
    for part in parts:
        cur = cur / part
        if cur.is_symlink():
            return None
    if not cur.is_file() or cur.stat().st_size > MAX_LICENCE_BYTES:
        return None
    return cur


def _licence_candidates(root: Path, cfg: Any) -> list[str]:
    """Relative paths of the licence files a source contributes: its explicit `licence_files` list when given;
    otherwise, for downloaded sources only (the corpus folder holds nothing but the publisher's download), files
    named LICENSE / LICENCE / COPYING / NOTICE (optionally .txt or .md) up to three folders deep. A local folder
    contributes only what `licence_files` names: it may hold anything else of the user's."""
    if cfg is not None and cfg.licence_files:
        return sorted(dict.fromkeys(cfg.licence_files))
    if cfg is not None and cfg.type == "local":
        return []
    out = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = Path(dirpath).relative_to(root)
        dirnames[:] = sorted(d for d in dirnames if d != ".git" and len(rel_dir.parts) < MAX_LICENCE_DEPTH - 1)
        out += [str(rel_dir / f) if rel_dir.parts else f for f in filenames if LICENCE_FILE.match(f)]
    return sorted(out)


def _publisher_files(n: str, row: Source | None, cfg: Any, ws: Workspace, major: str | None = None) -> list[tuple[str, Path]]:
    """(flat name, file) of the licence files a redistributable source ships next to its rules (`major`: the copy of
    that Suricata major for a source downloaded per major, majors.py)."""
    out: list[tuple[str, Path]] = []
    if row is None or row.redistribute != "yes":
        return out
    root = _source_root(n, cfg, ws, major)
    if root.is_dir() and not root.is_symlink():
        for rel in _licence_candidates(root, cfg):
            f = _safe_file(root, rel)
            if f is not None:
                out.append(("__".join(Path(rel).parts), f))
    return out


def filled_ids(
    names: list[str],
    sources: dict[str, Source],
    configs: dict[str, Any],
    ws: Workspace,
    notices: dict[str, list[list[str]]],
    file_holders: dict[str, list[str]] | None = None,
    major: str | None = None,
) -> dict[str, list[str]]:
    """Per source, the template licences (MIT, BSD) published as a filled-in copy: the source is redistributable,
    ships no licence file of its own, and has copyright lines."""
    out: dict[str, list[str]] = {}
    for n in names:
        row, cfg = sources.get(n), configs.get(n)
        if row is None or row.redistribute != "yes" or _publisher_files(n, row, cfg, ws, major):
            continue
        hs = holders(n, cfg, notices, file_holders)
        ids = [i for i in spdx_ids(row.licence) if filled_text(i, hs) is not None]
        if ids:
            out[n] = ids
    return out


def _licence_files(
    names: list[str],
    sources: dict[str, Source],
    configs: dict[str, Any],
    ws: Workspace,
    notices: dict[str, list[list[str]]] | None = None,
    file_holders: dict[str, list[str]] | None = None,
    major: str | None = None,
) -> list[tuple[str, bytes]]:
    """LICENSES/<source>/<file>: the licence texts each publisher ships next to its rules, as downloaded (git
    sources: the LICENSE / COPYING / NOTICE files of the repository root or `licence_files`, kept by sync), plus
    LICENSES/INDEX.md (source, SPDX expression, files, spdx.org links). Only sources with `redistribute: yes`
    contribute files. A redistributable source without a licence file of its own gets LICENSES/<source>/LICENSE.<id>.txt:
    the MIT / BSD template text with its copyright lines filled in."""
    notices = notices or {}
    files: list[tuple[str, bytes]] = []
    texts: dict[str, bytes] = {}
    filled = filled_ids(names, sources, configs, ws, notices, file_holders, major)
    rows = ["# Licences\n\n| source | licence | texts in this archive | reference |\n|---|---|---|---|\n"]
    for n in names:
        row, cfg = sources.get(n), configs.get(n)
        found: list[str] = []
        for flat, f in _publisher_files(n, row, cfg, ws, major):
            files.append((f"LICENSES/{n}/{flat}", f.read_bytes()))
            found.append(f"`{flat}`")
        for i in filled.get(n, []):
            files.append((f"LICENSES/{n}/LICENSE.{i}.txt", filled_text(i, holders(n, cfg, notices, file_holders)) or b""))
            found.append(f"`LICENSE.{i}.txt`")
        licence = (row.licence if row else None) or "unknown"
        for i in spdx_ids(licence):
            for j in (i, *_LICENCE_COMPANIONS.get(_LICENCE_ALIASES.get(i, i), ())):
                if (t := licence_text(j)) is not None:
                    texts[j] = t
                    found.append(f"`texts/{j}.txt`")
        refs = ", ".join(f"[{i}](https://spdx.org/licenses/{i}.html)" for i in spdx_ids(licence)) or "-"
        rows.append(f"| {n} | {licence} | {', '.join(found) or '-'} | {refs} |\n")
    files += [(f"LICENSES/texts/{i}.txt", t) for i, t in sorted(texts.items())]
    files.append(("LICENSES/INDEX.md", "".join(rows).encode()))
    return files


LICENCE_TEXTS = Path(__file__).parent / "licences"
_LICENCE_ALIASES = {
    "GPL-2.0": "GPL-2.0-only",
    "GPL-2.0-or-later": "GPL-2.0-only",
    "GPL-2.0+": "GPL-2.0-only",
    "GPL-3.0": "GPL-3.0-only",
    "GPL-3.0-or-later": "GPL-3.0-only",
    "GPL-3.0+": "GPL-3.0-only",
    "LGPL-2.1": "LGPL-2.1-only",
    "LGPL-2.1-or-later": "LGPL-2.1-only",
    "LGPL-3.0": "LGPL-3.0-only",
    "LGPL-3.0-or-later": "LGPL-3.0-only",
    "AGPL-3.0": "AGPL-3.0-only",
    "AGPL-3.0-or-later": "AGPL-3.0-only",
    "EUPL-1.2-or-later": "EUPL-1.2",
}
# Licences that add permissions to another text: both texts travel together (LGPL-3.0 = GPL-3.0 + permissions).
_LICENCE_COMPANIONS = {"LGPL-3.0-only": ("GPL-3.0-only",)}


def missing_licence_texts(names: Any, sources: dict[str, Any]) -> list[str]:
    """`source: id` for every SPDX id of the published sources whose full text is not bundled (src/suriharvest/
    licences): a build never ships rules without their licence text (GPL/AGPL §4, CC §3(a)(1)(C))."""
    out = []
    for x in sorted(names):
        lic = sources[x].licence if x in sources else None
        out += [f"{x}: {i}" for i in spdx_ids(lic) if licence_text(i) is None]
    return out


def licence_text(spdx_id: str) -> bytes | None:
    """Full text of a licence shipped with suriharvest (src/suriharvest/licences, from SPDX license-list-data)."""
    name = _LICENCE_ALIASES.get(spdx_id, spdx_id)
    if not re.fullmatch(r"[A-Za-z0-9.+-]+", name):
        return None
    f = LICENCE_TEXTS / f"{name}.txt"
    return f.read_bytes() if f.is_file() else None


def combined_licence(licences: Any) -> str:
    """One SPDX expression for a build of several sources (every source's terms apply to its own rules: AND).
    "Various" when a source has no licence or a free-text one (not an SPDX expression)."""
    parts: set[str] = set()
    for lic in licences:
        lic = (lic or "").strip()
        if not lic or not SPDX_EXPR.fullmatch(lic):
            return "Various"
        if " OR " in lic or " WITH " in lic:
            parts.add(f"({lic})" if " OR " in lic else lic)
        else:
            parts.update(x for x in lic.split() if x != "AND")
    return " AND ".join(sorted(parts)) or "Various"


def _index_yaml(engines: dict[str, Any], base: str, licences: dict[str, str | None] | None = None) -> str:
    data: dict[str, Any] = {"version": 1, "sources": {}}
    for engine, info in engines.items():
        n = short_name(engine)
        by_source = info.get("by_source") or {}
        data["sources"][f"suriharvest/suricata-{n}"] = {
            "vendor": "suriharvest",
            "summary": f"Merged, deduplicated free Suricata rules validated on Suricata {n}",
            "license": combined_licence((licences or {}).get(x) for x in sorted(by_source)) if by_source else "Various",
            "url": f"{base.rstrip('/')}/suriharvest-{n}.tar.gz" if base else f"suriharvest-{n}.tar.gz",
            "min-version": f"{n}.0.0" if n.isdigit() else "7.0.0",
            "checksum": False,
        }
    return yaml.safe_dump(data, sort_keys=True)


def _notes(summary: dict[str, Any], changes: dict[str, Any]) -> str:
    lines = [f"# suriharvest rules {summary['generated_at'][:10]}\n\n", f"content id `{summary['content_id'][:16]}`\n\n"]
    lines.append("| engine | version | rules |\n|---|---|---:|\n")
    for e, v in summary["engines"].items():
        lines.append(f"| {e} | {v.get('version') or '-'} | {v['rules']:,} |\n")
    if changes.get("added") is not None and (changes.get("added") or changes.get("removed") or changes.get("modified")):
        lines.append(
            f"\nChanges since the previous release: +{len(changes['added'])} -{len(changes['removed'])} ~{len(changes['modified'])}\n"
        )
    if changes.get("reclaimed"):
        lines.append(
            "\nSids reclaimed by their sidallocation.org owner (the other rule moved once to a new sid; update suppressions "
            "and thresholds keyed on the old sid):\n"
        )
        lines += [
            f"- {c['engine']} {c.get('gid') or 1}:{c['previous_sid']} -> {c.get('gid') or 1}:{c['exported_sid']} ({c['source']}, {c['reason']})\n"
            for c in changes["reclaimed"][:50]
        ]
        if len(changes["reclaimed"]) > 50:
            lines.append(f"- ... {len(changes['reclaimed']) - 50} more in changes.json\n")
    if changes.get("moved"):
        lines.append("\nOther published sids that moved (update suppressions and thresholds keyed on the old sid):\n")
        lines += [
            f"- {c['engine']} {c.get('gid') or 1}:{c['previous_sid']} -> {c.get('gid') or 1}:{c['exported_sid']} ({c['source']}, {c['reason']})\n"
            for c in changes["moved"][:50]
        ]
        if len(changes["moved"]) > 50:
            lines.append(f"- ... {len(changes['moved']) - 50} more in changes.json\n")
    bad = [g for g in summary["gates"] if g["status"] == "fail"]
    if bad:
        lines.append("\n**Release gates failed:**\n" + "".join(f"- {g['name']}: {g['detail']}\n" for g in bad))
    return "".join(lines)


def _recipes(path: Path, catalog: Path, epoch: int) -> None:
    """Sources the release does not redistribute (licence unclear, NC, needs a key): an update.yaml snippet for
    suricata-update and a README per source. Nothing is downloaded."""
    files = []
    entries = [c for c in catalog_sources(catalog) if c.synced_status and (c.tier == "user-fetch" or c.redistribute != "yes")]
    safe = {c.name: redact_url(c.url, keep_placeholders=True) for c in entries}
    urls = [u.replace("${suricata_version}", "%(__version__)s").replace("${secret}", "%(secret-code)s") for u in safe.values() if u]
    files.append(("recipes/update.yaml", yaml.safe_dump({"sources": urls}, sort_keys=False).encode()))
    for c in entries:
        home = f"Homepage: {redact_url(c.homepage)}\n" if c.homepage and redact_url(c.homepage) else ""
        text = (
            f"# {c.name}\n\nURL: {safe[c.name] or '(local source)'}\n{home}"
            f"Licence: {c.licence or 'unknown'}\nRedistribute: {c.redistribute}\n\n{c.notes or ''}\n"
        )
        files.append((f"recipes/{c.name}/README.md", text.encode()))
    _tar_gz(path, files, epoch)
