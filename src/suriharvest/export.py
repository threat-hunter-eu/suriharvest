"""Export a ruleset that Suricata / suricata-update can load.

- Units: logic (every selected logic group) or family (best of each family).
- Text: the canonical copy's original text. Rules every publisher ships disabled (commented out, e.g. ET's
  emerging-deleted.rules) or flagged deleted by their publisher keep that state: a query export writes them
  commented out by default (`disabled="comment"`), or leaves them out (`"omit"`), or enables them (`"enable"`, what
  you ask for with --include-disabled). A fixed selection (profile / release build) is exported as selected.
- Licence: everything is exported by default (the rules go to your own sensors); --redistributable-only keeps
  only rules whose canonical source says `redistribute: yes` (for a file you share or publish). Source, licence
  and redistribute go in the manifest.
- flowbits/xbits: rules that set a bit a selected rule checks are added automatically (from the whole corpus);
  bits nobody sets and external files the rules need are reported.
- SIDs are never rewritten silently: two exported rules with the same gid:sid stop the export, unless remapping
  is asked for; remapped sids come from a persistent map keyed by logic hash, so they never move between builds
  (see sidmap.py).
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from suriharvest.config import DEFAULT_DATASET_SID_BASE, DEFAULT_REMAP_BASE, Workspace
from suriharvest.db import in_list
from suriharvest.identity import _bits
from suriharvest.models import LogicGroup, RuleVersion, Source
from suriharvest.parser import ParseError, add_noalert, logical_lines, parse_rule, replace_sid
from suriharvest.search import build, parse_query
from suriharvest.urls import redact_url
from suriharvest.validate import dataset_paths

PERMISSIVE = {"mit", "cc0-1.0", "bsd", "bsd-2-clause", "bsd-3-clause", "apache-2.0", "cc-by-4.0", "isc"}
COPYLEFT_PREFIX = ("gpl", "lgpl", "agpl", "cc-by-sa", "mpl")


def _rule_licences(ws: Workspace | None) -> dict[str, Any]:
    """Sources of the workspace whose licence splits by rule (rule_licences in sources.yaml), by name."""
    from suriharvest.config import ConfigError, load_sources

    if ws is None:
        return {}
    try:
        return {c.name: c for c in load_sources(ws) if c.rule_licences}
    except ConfigError:
        return {}  # a broken sources.yaml is reported by sync; the manifest falls back to the source licence


def licence_class(licence: str | None) -> str:
    lic = (licence or "").strip().lower()
    if lic in PERMISSIVE:
        return "permissive"
    if lic.startswith(COPYLEFT_PREFIX):
        return "copyleft"
    if not lic:
        return "none"
    return "restricted"


DISABLED_MODES = ("comment", "omit", "enable")


@dataclass
class _Setter:
    id: int
    logic_hash: str
    rev: int | None
    flowbits_set: list[str]
    best_priority: int = 1_000_000


def _live_setters(s: Session) -> dict[int, _Setter]:
    """The live versions that set a flowbit, with the best priority of the enabled sources carrying them (what
    index.load_live gives, for these rows only: loading every live version decodes all its JSON columns)."""
    from sqlalchemy import func

    from suriharvest.models import Occurrence

    q = (
        select(RuleVersion.id, RuleVersion.logic_hash, RuleVersion.rev, RuleVersion.flowbits_set, func.min(Source.priority))
        .join(Occurrence, Occurrence.version_id == RuleVersion.id)
        .join(Source, Source.id == Occurrence.source_id)
        .where(Occurrence.present.is_(True), Source.enabled.is_(True), func.json_array_length(RuleVersion.flowbits_set) > 0)
        .group_by(RuleVersion.id)
    )
    return {vid: _Setter(vid, h, rev, list(bits or []), prio) for vid, h, rev, bits, prio in s.execute(q)}


def upstream_disabled(g: LogicGroup) -> bool:
    """Shipped disabled by every publisher that carries it, or flagged deleted by its publisher."""
    return not g.enabled_anywhere or "deleted" in (g.flags or [])


_OPT_NUMBER = re.compile(r"\s*:\s*(\d+)\s*;")


def _fast_option(low: str, kw: str) -> int | bool | None:
    """The number of the option `kw` ("sid"/"gid") in a lower-cased rule line that holds `kw` at most once and no
    backslash: None when absent, False when the occurrence is not provably a plain `kw:N;` option. It is one when
    it starts an option (after the first "(" or an unescaped ";", which without backslashes is always an option
    boundary) outside any quoted value, and reads `:N;`."""
    i = low.find(kw)
    if i < 0:
        return None
    j = i - 1
    while j >= 0 and low[j].isspace():
        j -= 1
    if j < 0 or not (low[j] == ";" or j == low.find("(")) or low.count('"', 0, i) % 2:
        return False
    m = _OPT_NUMBER.match(low, i + len(kw))
    return int(m.group(1)) if m else False


def _fast_gid_sid(text: str) -> tuple[int, int] | None:
    """gid:sid of a rule line without the full parser, or None (then parse_rule decides) unless it provably agrees
    with the parser: keywords are case-insensitive, so the checks run on the lower-cased line; a backslash anywhere,
    "sid" or "gid" more than once, or an occurrence that is not a plain option all fall back."""
    low = text.lower()
    if "\\" in low or low.count("sid") != 1 or low.count("gid") > 1:
        return None
    if any(";" in q for q in low.split('"')[1::2]):  # an unescaped ";" inside quotes: the parser refuses the line
        return None
    sid, gid = _fast_option(low, "sid"), _fast_option(low, "gid")
    if sid is None or sid is False or gid is False:
        return None
    return (1 if gid is None else gid, sid)


def check_unique_sids(path: Path) -> None:
    """Every enabled rule in a written rules file must have its own gid:sid (Suricata drops duplicates, keeping the
    higher rev: a rule that slipped through would silently replace another one on the sensor)."""
    seen: dict[tuple[int, int], int] = {}
    dups: list[str] = []
    for ll in logical_lines(path.read_text(encoding="utf-8")):
        if ll.text.startswith("#"):
            continue
        key = _fast_gid_sid(ll.text)
        if key is None:  # unusual text (escapes, several sid/gid options): the full parser decides
            try:
                r = parse_rule(ll.text, ll.line_no)
            except ParseError:
                continue
            key = (r.gid, r.sid or 0)
        if key in seen:
            dups.append(f"{key[0]}:{key[1]} (lines {seen[key]} and {ll.line_no})")
        else:
            seen[key] = ll.line_no
    if dups:
        raise SidCollision(f"{path.name}: duplicate gid:sid after export: {', '.join(dups[:20])}")


class SidCollision(RuntimeError):
    pass


@dataclass
class ExportReport:
    rules: int = 0
    setters_added: int = 0
    setters_back: dict[str, str] = field(default_factory=dict)  # logic hash -> rule key: excluded setters brought back
    skipped_licence: dict[str, int] = field(default_factory=dict)
    missing_setters: list[str] = field(default_factory=list)
    needed_files: list[str] = field(default_factory=list)
    out: Path | None = None
    remapped: int = 0
    disabled_upstream: int = 0  # rules disabled upstream that were written commented out or left out
    by_source: dict[str, int] = field(default_factory=dict)
    datasets: Any = None  # export_formats.DatasetReport
    suricata_update: Any = None  # export_formats.SuricataUpdateReport
    skipped_malformed: int = 0  # rules whose sid could not be rewritten (e.g. several sid options): left out
    skipped_failing: int = 0  # rules left out because they fail to load in an engine (include_failing=False)
    dataset_files: dict[str, str] = field(default_factory=dict)  # published path (datasets/<source>/...) -> sha256
    left_out_datasets: list[dict[str, Any]] = field(default_factory=list)  # dataset rules left out, with the reason
    dataset_renames: list[dict[str, Any]] = field(default_factory=list)  # dataset names changed to avoid a clash
    dataset_rewritten: dict[str, int] = field(default_factory=dict)  # source -> rules whose dataset load path was rewritten
    modified: set[str] = field(default_factory=set)  # logic hashes written with a profile's modify entries applied
    modify_refused: dict[str, str] = field(default_factory=dict)  # logic hash -> why its rewrite was taken back


def export(
    s: Session,
    out_dir: Path,
    query: str = "",
    *,
    unit: str = "family",
    redistributable_only: bool = False,
    include_junk: bool = False,
    logic_hashes: list[str] | None = None,
    fmt: str = "rules",
    managed: set[str] | dict[str, str] | None = None,  # dict: source -> OISF index name
    iocs_as_datasets: bool = False,
    sid_base: int = DEFAULT_DATASET_SID_BASE,
    remap_sids: bool = False,
    remap_base: int = DEFAULT_REMAP_BASE,
    sid_map: Path | None = None,
    priorities: dict[str, int] | None = None,
    forbid: set[str] | None = None,
    # excluded rules a needed flowbit brings back, as suricata-update's resolve_flowbits does after disable.conf:
    # every one of them that sets a bit an enabled rule checks is written enabled, with `noalert` (profile option
    # `flowbit_setters: suricata-update`, set by import-conf)
    setters_back: set[str] | None = None,
    split_by_source: bool = False,
    excluded: list | None = None,
    include_failing: bool = True,
    disabled: str | None = None,
    previous_holders: Any = None,  # sidmap.Previous
    rewrite: Callable[[LogicGroup, str], str] | None = None,
    check_modified: Callable[[dict[str, tuple[int, int, str]]], dict[str, str]] | None = None,
    ws: Workspace | None = None,
    sid_map_today: str | None = None,
    engine: str | None = None,
    views: dict[str, Any] | None = None,
) -> ExportReport:
    """Export the rules a query selects, or exactly `logic_hashes` (a profile build) when given.

    `disabled`: what to do with rules disabled upstream (see the module docstring); default "comment" for a query,
    "enable" for a fixed selection.

    `ws`: the workspace, to find the files dataset rules load; they are written to datasets/<source>/ next to
    suricata.rules (and by-source/), with the rule paths rewritten (dataset_files.py). Without it, or when a file
    cannot be shipped, such rules are left out and listed in `left_out_datasets`.

    `rewrite(group, text)` changes a rule's text before its sid is remapped (profile modify entries, see
    overrides.py); rules it changed are marked `"modified": true` in the manifest. The flowbit closure works on the
    rewritten texts. A rewrite is taken back (the rule is written as published, listed in `modify_refused`) when it
    removes a flowbit setter that other rules of the export need, or when `check_modified({logic hash: (gid, sid,
    text)})` returns an error for it (the profile's engine: see profiles.make_build).

    Per-major copies (majors.py): the export writes the ruleset of `engine`'s Suricata major (the newest major
    without an engine): rules that major does not see are left out, the others get that major's text; `views`:
    majors.load_views, when the caller has it."""
    from suriharvest.sidalloc import overlapping

    if disabled is None:
        disabled = "enable" if logic_hashes is not None else "comment"
    if disabled not in DISABLED_MODES:
        raise ValueError(f"disabled must be one of {', '.join(DISABLED_MODES)}")

    for label, base in (("remap base", remap_base if remap_sids else None), ("dataset sid base", sid_base if iocs_as_datasets else None)):
        if base is not None and (clash := overlapping(base, base + 99_999)):
            raise SidCollision(f"{label} {base:,} overlaps allocated sid ranges: {', '.join(clash)}; pick a free range")
    rep = ExportReport()
    if logic_hashes is not None:
        groups = (
            list(s.scalars(select(LogicGroup).where(in_list(LogicGroup.logic_hash, logic_hashes)).order_by(LogicGroup.sid)))
            if logic_hashes
            else []
        )
    else:
        stmt = build(parse_query(query), families=(unit == "family"), include_junk=include_junk)
        groups = list(s.scalars(stmt.order_by(LogicGroup.sid)))
    from suriharvest.majors import scoped, view_of_engine

    view = view_of_engine(s, engine, views)
    if view is not None:
        groups = [x for g in groups if (x := scoped(g, view)) is not None]
    sources = {r.name: r for r in s.scalars(select(Source))}
    prio = priorities if priorities is not None else {r.name: r.priority for r in sources.values()}
    # Everything goes to your own sensors by default; the redistribution policy is opt-in.

    ok_seen: dict[str, bool] = {}

    def ok(g: LogicGroup) -> bool:
        """May this rule be written? Counted once per rule (the flowbit closure may ask again)."""
        if g.logic_hash in ok_seen:
            return ok_seen[g.logic_hash]
        res = True
        if not include_failing and g.fails_in:
            rep.skipped_failing += 1
            res = False
        else:
            src = sources[g.canonical_source]
            if redistributable_only and src.redistribute != "yes":
                key = f"redistribute: {src.redistribute}"
                rep.skipped_licence[key] = rep.skipped_licence.get(key, 0) + 1
                res = False
        ok_seen[g.logic_hash] = res
        return res

    picked = [g for g in groups if ok(g)]
    # Rules disabled upstream: left out (omit) or kept apart so they neither pull in flowbit setters nor satisfy
    # a checker (comment); written commented out after the closure.
    commented: list[LogicGroup] = []
    if disabled != "enable":
        off = [g for g in picked if upstream_disabled(g)]
        picked = [g for g in picked if not upstream_disabled(g)]
        rep.disabled_upstream = len(off)
        if disabled == "comment":
            commented = off
    # flowbits: add setters from the corpus
    live = _live_setters(s)
    if view is not None:
        live = {k: v for k, v in live.items() if k in view.versions}
    setters: dict[str, list[int]] = defaultdict(list)
    for sv in live.values():
        for b in sv.flowbits_set:
            setters[b].append(sv.id)
    for ids in setters.values():  # best first: priority of the source, then the newest revision
        ids.sort(key=lambda i: (live[i].best_priority, -(live[i].rev or 0), live[i].logic_hash))
    version_ids = {g.canonical_version_id for g in picked}
    base_versions = {v.id: v for v in s.scalars(select(RuleVersion).where(in_list(RuleVersion.id, version_ids)))} if version_ids else {}
    # hashes only (loading every group decodes all its JSON columns); a setter's group is loaded when it is tried
    group_hashes = set(s.scalars(select(LogicGroup.logic_hash)))
    base = list(picked)
    loaded: dict[str, tuple[LogicGroup, RuleVersion] | None] = {}
    reverted: dict[str, str] = {}  # logic hash -> why its rewrite was taken back (rule written unmodified)
    brought_back: set[str] = set()  # excluded setters a checked flowbit brought back (setters_back)
    bits_of: dict[tuple[str, str], tuple[set[str], set[str]]] = {}

    def text_after(g: LogicGroup, v: RuleVersion) -> str:
        """The text a rule is written with: after the profile's modify entries, unless one was taken back."""
        if rewrite is None or g.logic_hash in reverted:
            return v.raw
        return rewrite(g, v.raw)

    def bits(g: LogicGroup, v: RuleVersion) -> tuple[set[str], set[str]]:
        """flowbits (set, checked) of the text that is written: a modify entry may add or remove them."""
        t = text_after(g, v)
        if t == v.raw:
            return set(v.flowbits_set), set(v.flowbits_check)
        key = (g.logic_hash, t)
        if key not in bits_of:
            try:
                sets, checks = _bits(parse_rule(t))
            except ParseError:
                sets, checks = v.flowbits_set, v.flowbits_check
            bits_of[key] = (set(sets), set(checks))
        return bits_of[key]

    def setter(i: int) -> tuple[LogicGroup, RuleVersion] | None:
        h = live[i].logic_hash
        if h not in loaded:
            g = scoped(s.scalar(select(LogicGroup).where(LogicGroup.logic_hash == h)), view)
            nv = s.get(RuleVersion, g.canonical_version_id) if g is not None else None
            loaded[h] = (g, nv) if g is not None and nv is not None else None
        return loaded[h]

    while True:
        picked = list(base)
        versions = dict(base_versions)
        bits_set: set[str] = set()
        for g in picked:
            bits_set |= bits(g, versions[g.canonical_version_id])[0]
        pending = list(picked)
        seen_bits: set[str] = set()
        rep.setters_added = 0
        brought_back.clear()
        while pending:
            g0 = pending.pop()
            for b in sorted(bits(g0, versions[g0.canonical_version_id])[1]):
                if b in seen_bits:
                    continue
                seen_bits.add(b)
                for i in setters.get(b, []) if setters_back else []:
                    # suricata-update enables every disabled setter of a checked bit, also when another rule sets it
                    if live[i].logic_hash not in setters_back or live[i].logic_hash in brought_back:
                        continue
                    found = setter(i)
                    if found is None:
                        continue
                    g, nv = found
                    if g.canonical_version_id in versions or not ok(g) or b not in bits(g, nv)[0]:
                        continue
                    versions[nv.id] = nv
                    bits_set |= bits(g, nv)[0]
                    picked.append(g)
                    pending.append(g)
                    brought_back.add(g.logic_hash)
                if b in bits_set:
                    continue
                # The best setter first; when it cannot be used (excluded by the analyst, not redistributable,
                # fails in the engine, its rewrite drops the bit) the next one is tried. None left: reported below.
                for i in setters.get(b, []):
                    if live[i].logic_hash not in group_hashes:
                        continue
                    found = setter(i)
                    if found is None:
                        continue
                    g, nv = found
                    if g.logic_hash in (forbid or set()) or g.canonical_version_id in versions or not ok(g):
                        continue
                    if b not in bits(g, nv)[0]:
                        continue
                    versions[nv.id] = nv
                    bits_set |= bits(g, nv)[0]
                    picked.append(g)
                    pending.append(g)
                    rep.setters_added += 1
                    break
        # A rewrite must not take away a flowbit that other rules of the build check and nothing else sets, and
        # (with check_modified, the profile's engine) must load: otherwise the rule is written unmodified.
        checked = set().union(*(bits(g, versions[g.canonical_version_id])[1] for g in picked)) if picked else set()
        back: dict[str, str] = {}
        if rewrite is not None:
            for g in picked:
                v = versions[g.canonical_version_id]
                if text_after(g, v) == v.raw:
                    continue
                lost = (set(v.flowbits_set) - bits(g, v)[0]) & (checked - bits_set)
                if lost:
                    back[g.logic_hash] = (
                        f"{g.rule_key}: it removes the setter of {', '.join(sorted(lost))}, which other rules in the build check"
                    )
            if check_modified is not None:
                todo = {
                    g.logic_hash: (g.gid, g.sid, text_after(g, versions[g.canonical_version_id]))
                    for g in picked
                    if g.logic_hash not in back and text_after(g, versions[g.canonical_version_id]) != versions[g.canonical_version_id].raw
                }
                for h, err in check_modified(todo).items():
                    rule_key = next(g.rule_key for g in picked if g.logic_hash == h)
                    back[h] = (
                        f"{rule_key}: {err}" if err.startswith("not applied") else f"{rule_key}: the modified rule does not load ({err})"
                    )
        if not back:
            break
        reverted.update(back)  # the closure runs again on the original texts of these rules
    rep.missing_setters = sorted(checked - bits_set)
    rep.setters_back = {g.logic_hash: g.rule_key for g in picked if g.logic_hash in brought_back}
    rep.modify_refused = dict(reverted)
    if commented:
        more = {g.canonical_version_id for g in commented} - set(versions)
        if more:
            versions |= {v.id: v for v in s.scalars(select(RuleVersion).where(in_list(RuleVersion.id, more)))}
        have = {g.logic_hash for g in picked}
        picked += [g for g in commented if g.logic_hash not in have]
    off_hashes = {g.logic_hash for g in commented}
    # sid collisions (commented-out rules count: they keep their sid if someone enables them later)
    by_sid: dict[tuple[int, int], list[LogicGroup]] = defaultdict(list)
    for g in picked:
        by_sid[(g.gid, g.sid)].append(g)
    clashes = {k: v for k, v in by_sid.items() if len(v) > 1}
    remapped: dict[str, int] = {}  # logic hash -> new sid
    if remap_sids:
        # The best rule of a clash keeps the sid, the others get new sids; every decision is kept in the sid map,
        # so a rule keeps its exported sid from build to build (deterministic ranking, never the row id).
        from suriharvest.sidmap import SidMap

        smap = SidMap(sid_map, today=sid_map_today)  # release builds date new rows from --build-epoch
        from suriharvest.sidalloc import owner as sid_owner

        def is_owner(g: LogicGroup) -> bool:
            alloc = sid_owner(g.gid, g.sid, g.msg)
            src = sources.get(g.canonical_source)
            return alloc is not None and src is not None and src.sid_namespace == alloc.namespace

        remapped = smap.assign(
            picked,
            lambda g: (prio.get(g.canonical_source, 50), -g.score, g.logic_hash),
            remap_base,
            owner=is_owner,
            previous=previous_holders,
        )
        smap.save()
        rep.remapped = len(remapped)
    elif clashes:
        lines = [
            f"  {gid}:{sid}: "
            + ", ".join(f"{g.logic_hash[:12]} ({g.canonical_source})" for g in gs[:5])
            + (f" +{len(gs) - 5} more" if len(gs) > 5 else "")
            for (gid, sid), gs in list(clashes.items())[:20]
        ]
        raise SidCollision(
            f"{len(clashes)} gid:sid values are used by more than one exported rule ({sum(len(v) - 1 for v in clashes.values())} rules would not load):\n"
            + "\n".join(lines)
            + "\nnarrow the selection, drop one of each, or pass --remap-colliding-sids"
        )

    def _text(g: LogicGroup) -> str:
        v = versions[g.canonical_version_id]
        raw = text_after(g, v)
        if raw != v.raw:
            modified.add(g.logic_hash)
        if g.logic_hash in brought_back:
            raw = add_noalert(raw)  # suricata-update's rule.format(), at the real sid option
        if g.logic_hash in remapped:
            raw = replace_sid(raw, remapped[g.logic_hash])
        if g.logic_hash in off_hashes:
            return "# " + raw.lstrip("#").lstrip()
        return raw

    # one malformed rule (attacker-controlled text) must not abort the export: leave it out and count it
    modified: set[str] = set()
    texts: dict[str, str] = {}
    for g in picked:
        try:
            texts[g.logic_hash] = _text(g)
        except (ParseError, KeyError):
            rep.skipped_malformed += 1
    # dataset rules: ship their files (paths rewritten, names kept apart per definition) or leave them out
    from suriharvest.dataset_files import DatasetPacker, ship

    order = sorted(
        (g for g in picked if g.logic_hash in texts),
        key=lambda g: (prio.get(g.canonical_source, 50), g.canonical_source, g.gid, g.sid, g.logic_hash),
    )
    shipped = ship(
        ((g.logic_hash, g.canonical_source, texts[g.logic_hash]) for g in order),
        DatasetPacker(s, ws, major=view.major if view else None) if ws else None,
    )
    for g in order:  # licence notices state which rules were changed (dataset paths and names)
        if g.logic_hash in shipped.texts and shipped.texts[g.logic_hash] != texts[g.logic_hash]:
            rep.dataset_rewritten[g.canonical_source] = rep.dataset_rewritten.get(g.canonical_source, 0) + 1
    texts = shipped.texts
    by_hash = {g.logic_hash: g for g in picked}
    for d in shipped.left_out:
        g = by_hash[d["key"]]
        rep.left_out_datasets.append({"logic_hash": g.logic_hash, "gid": g.gid, "sid": g.sid, "source": d["source"], "reason": d["reason"]})
    for d in shipped.renamed:
        g = by_hash[d["key"]]
        rep.dataset_renames.append({"logic_hash": g.logic_hash, "gid": g.gid, "sid": g.sid, **{k: v for k, v in d.items() if k != "key"}})
    picked = [g for g in picked if g.logic_hash in texts]

    def text_of(g: LogicGroup) -> str:
        return texts[g.logic_hash]

    out_dir.mkdir(parents=True, exist_ok=True)
    for rel, data in sorted(shipped.files.items()):
        for base in (out_dir, out_dir / "by-source") if split_by_source else (out_dir,):
            dst = base / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(data)
        rep.dataset_files[rel] = hashlib.sha256(data).hexdigest()
    picked.sort(key=lambda g: (g.gid, g.sid))
    if iocs_as_datasets:
        from suriharvest.export_formats import ioc_datasets

        # only enabled rules become dataset entries: a disabled IOC rule stays a commented-out rule
        active, rep.datasets = ioc_datasets(s, [g for g in picked if g.logic_hash not in off_hashes], out_dir, sid_base)
        picked = sorted(active + [g for g in picked if g.logic_hash in off_hashes], key=lambda g: (g.gid, g.sid))
    rule_licence = _rule_licences(ws)
    with (out_dir / "manifest.jsonl").open("w", encoding="utf-8", newline="\n") as fm:
        for g in picked:
            v = versions[g.canonical_version_id]
            src = sources[g.canonical_source]
            fm.write(
                json.dumps(
                    {
                        "logic_hash": g.logic_hash,
                        "rule_key": g.rule_key,
                        "gid": g.gid,
                        "sid": g.sid,
                        "rev": g.rev,
                        "source": src.name,
                        "licence": rule_licence[src.name].licence_of(g.sid, g.msg) if src.name in rule_licence else src.licence,
                        "url": redact_url(src.url),
                        "flags": g.flags,
                        "is_ioc": g.is_ioc,
                        "redistribute": src.redistribute,
                        "exported_sid": remapped.get(g.logic_hash, g.sid),
                        "enabled": g.logic_hash not in off_hashes,
                        "msg": g.msg,
                    }
                    | ({"modified": True} if g.logic_hash in modified else {})
                )
                + "\n"
            )
            shipped_paths = set(dataset_paths(v.raw))  # dataset files ship with the rule (or it was left out)
            rep.needed_files += [f for f in v.files if f not in shipped_paths]
    if fmt == "suricata-update":
        from suriharvest.export_formats import suricata_update_files

        rep.suricata_update = suricata_update_files(
            s, out_dir, picked, managed or set(), {g.canonical_version_id: text_of(g) for g in picked}, excluded
        )
    else:
        with (out_dir / "suricata.rules").open("w", encoding="utf-8", newline="\n") as fr:
            what = "a fixed selection (profile build)" if logic_hashes is not None else f"query {query!r}, unit {unit}"
            fr.write(f"# suriharvest export: {len(picked)} rules, {what}\n")
            for g in picked:
                fr.write(text_of(g) + "\n")
        check_unique_sids(out_dir / "suricata.rules")
    if split_by_source:
        # one file per (canonical) source, same texts as suricata.rules
        by = out_dir / "by-source"
        by.mkdir(exist_ok=True)
        groups_by_source: dict[str, list[LogicGroup]] = defaultdict(list)
        for g in picked:
            groups_by_source[g.canonical_source].append(g)
        for name, gs in sorted(groups_by_source.items()):
            with (by / f"{name}.rules").open("w", encoding="utf-8", newline="\n") as f:
                f.write(f"# suriharvest export: {len(gs)} rules from source {name}\n")
                for g in gs:
                    f.write(text_of(g) + "\n")
        rep.by_source = {n: len(gs) for n, gs in groups_by_source.items()}
    rep.rules = len(picked)
    rep.needed_files = sorted(set(rep.needed_files))
    rep.missing_setters = sorted(set(rep.missing_setters))
    rep.modified = modified
    rep.out = out_dir
    return rep
