"""Profiles (named rulesets) and exclusions.

A profile is a named ruleset to build, e.g. "default", "ioc-only", "suricata8". Its candidate rules are a search
query; exclusions (per profile, or global) remove rules you do not want there, each with a reason. A build writes
the ruleset, the list of excluded rules with the reason for each, and what changed since the previous build.
Suggestions point at groups of rules that are usually left out (informational categories, retired rules, rules
that do not load, stale IOC rules), with counts and examples, before anything is excluded.

Exclusion kinds:
  msg_contains  substring of the rule name, case-sensitive
  msg_exact     the whole name
  msg_regex     Python regular expression on the name (case-insensitive)
  sid           a sid (any gid, any namespace)
  rule_key      namespace:gid:sid
  logic         a logic hash
  category      name prefix category ("ET INFO", "GPL NETBIOS")
  classtype     a classtype
  source        a source name (rules only that source carries)
  query         any search query (suriharvest search syntax)
  rule_regex    Python regular expression on the whole rule text (case-insensitive; suricata-update `re:`)
  metadata      "key value" in the rule's metadata (case-insensitive; suricata-update `metadata:`)
  file          rule file name in any source, shell pattern allowed (suricata-update `group:`)
A matched rule key is remembered on the exclusion, so a rule renamed upstream stays excluded.
"""

from __future__ import annotations

import fnmatch
import json
import os
import posixpath
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from suriharvest.config import Workspace
from suriharvest.db import in_list
from suriharvest.models import Exclusion, LogicGroup, Occurrence, Profile, ProfileBuild, RuleVersion, utcnow
from suriharvest.portable import windows_unsafe_name
from suriharvest.ruleopts import U32_MAX, option_int
from suriharvest.search import QueryError, build, parse_query
from suriharvest.userregex import UserRegex, compile_user

KINDS = (
    "msg_contains",
    "msg_exact",
    "msg_regex",
    "sid",
    "rule_key",
    "logic",
    "category",
    "classtype",
    "source",
    "query",
    "rule_regex",
    "metadata",
    "file",
)
SET_KINDS = ("query", "rule_regex", "metadata", "file")  # matched through a precomputed set of logic hashes
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")


class ProfileError(ValueError):
    pass


# ---------------------------------------------------------------------------------------------------------------
# profiles and exclusions


def get(s: Session, name: str) -> Profile:
    t = s.scalar(select(Profile).where(Profile.name == name))
    if t is None:
        raise ProfileError(f"no profile {name!r} (create it with `suriharvest profile create {name}`)")
    return t


def create(
    s: Session,
    name: str,
    *,
    query: str = "",
    unit: str = "logic",
    engine: str | None = None,
    description: str | None = None,
    options: dict | None = None,
) -> Profile:
    if not NAME.fullmatch(name):
        raise ProfileError("profile names: letters, digits, . _ - (max 100)")
    unsafe = windows_unsafe_name(name)
    if unsafe:
        raise ProfileError(f"profile name {name!r}: {unsafe}")
    if name.lower() in ("all", GLOBAL_FILE) or name.startswith("."):
        raise ProfileError(f"{name!r} is reserved (global exclusions use 'all' and exclusions/{GLOBAL_FILE}.yaml)")
    if unit not in ("logic", "family"):
        raise ProfileError("unit must be logic or family")
    if s.scalar(select(Profile).where(Profile.name == name)) is not None:
        raise ProfileError(f"profile {name!r} exists")
    try:
        parse_query(query)
    except QueryError as e:
        raise ProfileError(f"query: {e}") from e
    t = Profile(name=name, query=query, unit=unit, engine=engine, description=description, options=options or {"remap_sids": True})
    s.add(t)
    s.commit()
    return t


def exclusions(s: Session, profile: Profile | None) -> list[Exclusion]:
    q = select(Exclusion)
    q = (
        q.where((Exclusion.profile_id == profile.id) | Exclusion.profile_id.is_(None))
        if profile
        else q.where(Exclusion.profile_id.is_(None))
    )
    return list(s.scalars(q.order_by(Exclusion.id)))


def _check(kind: str, value: str) -> None:
    if kind not in KINDS:
        raise ProfileError(f"kind must be one of {', '.join(KINDS)}")
    if not value.strip():
        raise ProfileError("empty value")
    if kind in ("msg_regex", "rule_regex"):
        try:
            re.compile(value)
        except re.error as e:
            raise ProfileError(f"bad regular expression: {e}") from e
    if kind == "metadata" and len(value.split(None, 1)) != 2:
        raise ProfileError("metadata needs 'key value', e.g. 'deployment perimeter'")
    if kind == "sid" and option_int(value) is None:
        raise ProfileError(f"sid must be a whole number from 0 to {U32_MAX}")
    if kind == "query":
        try:
            parse_query(value)
        except QueryError as e:
            raise ProfileError(f"query: {e}") from e


def add_exclusion(
    s: Session,
    profile: Profile | None,
    kind: str,
    value: str,
    reason: str | None = None,
    author: str | None = None,
    review_at: datetime | None = None,
) -> tuple[Exclusion, int]:
    """Add an exclusion (or return the existing identical one). Returns it and how many rules it matches now."""
    _check(kind, value)
    tid = profile.id if profile else None
    ex = s.scalar(
        select(Exclusion).where(
            Exclusion.profile_id.is_(tid) if tid is None else Exclusion.profile_id == tid, Exclusion.kind == kind, Exclusion.value == value
        )
    )
    if ex is None:
        ex = Exclusion(
            profile_id=tid, kind=kind, value=value, reason=reason, author=author or os.environ.get("USER"), review_at=review_at, keys=[]
        )
        s.add(ex)
        s.flush()
    elif reason:
        ex.reason = reason
    matched = preview(s, kind, value)
    ex.keys = sorted(set(ex.keys or []) | {g.rule_key for g in matched})
    ex.last_matched, ex.last_checked_at = len(matched), utcnow()
    s.commit()
    return ex, len(matched)


def remove_exclusion(s: Session, ex_id: int) -> None:
    ex = s.get(Exclusion, ex_id)
    if ex is None:
        raise ProfileError(f"no exclusion {ex_id}")
    s.delete(ex)
    s.commit()


# ---------------------------------------------------------------------------------------------------------------
# matching


def set_hits(s: Session, items: list[Any]) -> dict[int, set[str]]:
    """Logic hashes matched by each item of a set kind (query, rule_regex, metadata, file), in one pass per kind."""
    hits: dict[int, set[str]] = {ex.id: set() for ex in items if ex.kind in SET_KINDS}
    for ex in items:
        if ex.kind == "query":
            stmt = build(parse_query(ex.value), families=False, include_junk=True, include_dropped=True)
            hits[ex.id] = set(s.scalars(stmt.with_only_columns(LogicGroup.logic_hash)))
    canon = select(LogicGroup.logic_hash, RuleVersion.raw, RuleVersion.rule_metadata).join(
        RuleVersion, RuleVersion.id == LogicGroup.canonical_version_id
    )
    rx = [(ex.id, compile_user(ex.value)) for ex in items if ex.kind == "rule_regex"]  # bounded cost (userregex.py)
    md = [(ex.id, *(p.lower() for p in ex.value.split(None, 1))) for ex in items if ex.kind == "metadata"]
    if rx or md:
        for lh, raw, meta in s.execute(canon):
            for i, p in rx:
                if p.search(raw or ""):
                    hits[i].add(lh)
            if md:
                pairs = {(k.lower(), str(v).lower()) for k, vs in (meta or {}).items() for v in vs}
                for i, k, v in md:
                    if (k, v) in pairs:
                        hits[i].add(lh)
    files = [(ex.id, ex.value) for ex in items if ex.kind == "file"]
    if files:
        rows = s.execute(
            select(RuleVersion.logic_hash, Occurrence.path)
            .join(Occurrence, Occurrence.version_id == RuleVersion.id)
            .where(Occurrence.present.is_(True))
            .distinct()
        )
        from suriharvest.majors import strip_variant

        for lh, raw_path in rows:
            path = strip_variant(raw_path.replace("\\", "/"))  # a per-major copy (@8/rules/x.rules) is still rules/x.rules
            base = posixpath.basename(path)
            stem = posixpath.splitext(base)[0]  # `emerging-malware` matches emerging-malware.rules (as suricata-update's group:)
            for i, pat in files:
                if fnmatch.fnmatchcase(base, pat) or fnmatch.fnmatchcase(stem, pat) or fnmatch.fnmatchcase(path, pat):
                    hits[i].add(lh)
    return hits


@dataclass
class Matcher:
    """Matches logic groups against a list of exclusions (or override selectors); the first matching item wins.
    sid, rule key and remembered keys are dictionary lookups, so thousands of sid entries stay cheap."""

    items: list[Any]
    query_hits: dict[int, set[str]] = field(default_factory=dict)  # item id -> logic hashes (set kinds)
    _regex: dict[int, UserRegex] = field(default_factory=dict)
    _pos: dict[int, int] = field(default_factory=dict)
    _by_sid: dict[int, list[Any]] = field(default_factory=dict)
    _by_key: dict[str, list[Any]] = field(default_factory=dict)  # rule_key kind and remembered keys
    _rest: list[Any] = field(default_factory=list)
    _contains: re.Pattern[str] | None = None  # every msg_contains value in one pattern: a cheap first test

    @classmethod
    def build(cls, s: Session, items: list[Any]) -> Matcher:
        m = cls(items)
        m.query_hits = set_hits(s, items)
        m._regex = {ex.id: compile_user(ex.value) for ex in items if ex.kind == "msg_regex"}
        m._pos = {ex.id: i for i, ex in enumerate(items)}
        for ex in items:
            if ex.kind == "sid":
                m._by_sid.setdefault(option_int(ex.value) or -1, []).append(ex)
            elif ex.kind == "rule_key":
                m._by_key.setdefault(ex.value, []).append(ex)
            else:
                m._rest.append(ex)
            for k in ex.keys or []:
                if ex.kind != "rule_key" or k != ex.value:
                    m._by_key.setdefault(k, []).append(ex)
        contains = [ex.value for ex in items if ex.kind == "msg_contains"]
        m._contains = re.compile("|".join(re.escape(v) for v in contains)) if contains else None
        return m

    def _hit(self, ex: Any, g: Any, msg: str) -> bool:
        k, v = ex.kind, ex.value
        return (
            (k == "msg_contains" and v in msg)
            or (k == "msg_exact" and v == msg)
            or (k == "msg_regex" and self._regex[ex.id].search(msg))
            or (k == "logic" and g.logic_hash.startswith(v))
            or (k == "category" and (g.category or "").lower() == v.lower())
            or (k == "classtype" and (g.classtype or "") == v)
            or (k == "source" and g.sources == [v])
            or (k in SET_KINDS and g.logic_hash in self.query_hits.get(ex.id, set()))
        )

    def matches(self, g: Any, first: bool = False) -> list[Any]:
        """Every matching item in list order (or only the first one)."""
        found = {ex.id: ex for ex in self._by_sid.get(g.sid, ())}
        found |= {ex.id: ex for ex in self._by_key.get(g.rule_key, ())}
        best = min((self._pos[i] for i in found), default=len(self.items))
        msg = g.msg or ""
        maybe_contains = self._contains is not None and self._contains.search(msg) is not None
        for ex in self._rest:
            if first and self._pos[ex.id] >= best:
                break
            if ex.id in found or (ex.kind == "msg_contains" and not maybe_contains):
                continue
            if self._hit(ex, g, msg):
                found[ex.id] = ex
                best = min(best, self._pos[ex.id])
        out = sorted(found.values(), key=lambda ex: self._pos[ex.id])
        return out[:1] if first else out

    def match(self, g: Any) -> Any | None:
        hit = self.matches(g, first=True)
        return hit[0] if hit else None


def preview(s: Session, kind: str, value: str, limit: int | None = None) -> list[Any]:
    """Live logic groups an exclusion of this kind/value would match (no sticky keys), best score first."""
    from sqlalchemy import func

    _check(kind, value)
    stmt = select(*LIGHT)
    cond = {
        "msg_contains": func.instr(LogicGroup.msg, value) > 0,
        "msg_exact": LogicGroup.msg == value,
        "sid": LogicGroup.sid == (option_int(value) if option_int(value) is not None else -1),
        "rule_key": LogicGroup.rule_key == value,
        "logic": LogicGroup.logic_hash.like(value + "%"),
        "category": func.lower(LogicGroup.category) == value.lower(),
        "classtype": LogicGroup.classtype == value,
        "source": LogicGroup.sources == [value],
    }.get(kind)
    if cond is not None:
        rows = list(s.execute(stmt.where(cond).order_by(LogicGroup.score.desc()).limit(limit)))
    elif kind == "query":
        q = build(parse_query(value), families=False, include_junk=True, include_dropped=True)
        rows = list(s.execute(q.with_only_columns(*LIGHT).order_by(LogicGroup.score.desc()).limit(limit)))
    elif kind in SET_KINDS:
        hit = set_hits(s, [_Item(0, kind, value)])[0]
        rows = [r for r in s.execute(stmt.order_by(LogicGroup.score.desc())) if r.logic_hash in hit]
        rows = rows[:limit] if limit else rows
    else:  # msg_regex
        rx = compile_user(value)
        rows = [r for r in s.execute(stmt.order_by(LogicGroup.score.desc())) if rx.search(r.msg or "")]
        rows = rows[:limit] if limit else rows
    return rows


@dataclass
class _Item:
    """A selector that is not an Exclusion row (previews, profile overrides)."""

    id: int
    kind: str
    value: str
    keys: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------------------------------------------
# candidates, builds and diffs


# Columns the matcher, builds and review pages need: loading these rows is ~10x faster than full ORM objects.
LIGHT = (
    LogicGroup.id,
    LogicGroup.logic_hash,
    LogicGroup.rule_key,
    LogicGroup.gid,
    LogicGroup.sid,
    LogicGroup.rev,
    LogicGroup.msg,
    LogicGroup.category,
    LogicGroup.classtype,
    LogicGroup.sources,
    LogicGroup.canonical_source,
    LogicGroup.fails_in,
    LogicGroup.score,
    LogicGroup.flags,
    LogicGroup.redistributable,
    LogicGroup.enabled_anywhere,
)


def candidates(s: Session, t: Profile, ov: Any = None) -> list[Any]:
    """The profile's query; by default only rules their publisher ships enabled (commented-out rules are left
    out), plus disabled ones an `enable` entry picks. options.include_disabled takes every disabled rule."""
    stmt = build(parse_query(t.query), families=(t.unit == "family"), include_junk=False, include_dropped=False)
    every = bool((t.options or {}).get("include_disabled"))
    wants = ov is not None and bool(ov.items["enable"])
    if not every and not wants:
        stmt = stmt.where(LogicGroup.enabled_anywhere.is_(True))
    rows = list(s.execute(stmt.with_only_columns(*LIGHT).order_by(LogicGroup.sid)))
    if every or not wants:
        return rows
    return [g for g in rows if g.enabled_anywhere or ov.enables(g)]


@dataclass
class Selection:
    kept: list[Any]  # light rows (LIGHT columns)
    excluded: list[tuple[Any, str, int | None]]  # row, reason, exclusion id


def select_rules(s: Session, t: Profile, ov: Any = None, views: dict[str, Any] | None = None) -> Selection:
    """Candidates minus exclusions. `ov`: the profile's Overrides (built here when not given).

    With per-major copies (majors.py) only the rules the profile engine's Suricata major sees are candidates (the
    newest major's without an engine), enabled as that major's copy ships them; `views`: majors.load_views, when
    the caller has it."""
    from suriharvest.majors import Scoped, view_of_engine
    from suriharvest.overrides import Overrides

    if ov is None:
        ov = Overrides(s, t)
    view = view_of_engine(s, t.engine, views)
    every = bool((t.options or {}).get("include_disabled"))
    items = exclusions(s, t)
    m = Matcher.build(s, items)
    kept, excluded = [], []
    for g in candidates(s, t, ov):
        ex = m.match(g)
        pick = view.canonical.get(g.logic_hash) if view is not None else None
        if ex is not None:
            why = f"{ex.kind}: {ex.value}" + (f" ({ex.reason})" if ex.reason else "")
            if not ov.enable_beats(g, why):
                excluded.append((g, why, ex.id))
                continue
        elif ov.items["enable"]:
            ov.enables(g)  # an enable entry that picks a rule shipped enabled matched it (not "matched no rule")
        if view is not None and pick is None:
            excluded.append((g, f"not in the Suricata {view.major} ruleset of its source", None))
        elif t.engine and t.engine in (g.fails_in or []):
            excluded.append((g, f"does not load in {t.engine}", None))
        elif pick is not None and not pick.enabled and not every and not ov.enables(g):
            excluded.append((g, f"disabled in the Suricata {view.major} ruleset of its source", None))  # type: ignore[union-attr]
        else:
            kept.append(Scoped(g, pick) if pick is not None else g)  # revision, sid and source as this major has them
    kept, more = pick_revisions(s, kept, share_only=bool((t.options or {}).get("redistributable_only")))
    excluded += more
    return Selection(kept, excluded)


def pick_revisions(s: Session, kept: list[Any], *, share_only: bool = False) -> tuple[list[Any], list[tuple[Any, str, None]]]:
    """One copy per rule key (ambiguous keys are different rules and all stay).

    rev orders revisions only within one lineage: the texts one source ever published under that key. Across sources
    sid ownership decides first (the source whose sid_namespace owns the key's namespace, sidallocation.org), then
    source priority. So the best source's newest revision is kept; a copy from another source that its lineage never
    carried is dropped when its rev is not higher (an old mirror or fork), and otherwise kept as a different rule
    that loses the sid: export remaps it and the release lists it in collisions.json. A source can no longer replace
    a publisher's rule by reusing its sid and msg with a higher rev.

    share_only (a redistributable build): only copies whose canonical source allows redistribution compete, so a
    non-redistributable copy can never push a redistributable rule out (export then leaves it out by licence)."""
    from suriharvest.models import Occurrence, RuleKey, RuleVersion, Source

    ambiguous = set(s.scalars(select(RuleKey.rule_key).where(RuleKey.ambiguous.is_(True))))
    info = {
        name: (prio, ns or name, red)
        for name, prio, ns, red in s.execute(select(Source.name, Source.priority, Source.sid_namespace, Source.redistribute))
    }
    prio = {k: v[0] for k, v in info.items()}
    by_key: dict[str, list[Any]] = {}
    for g in kept:
        if g.rule_key not in ambiguous:
            by_key.setdefault(g.rule_key, []).append(g)
    contested = {k: gs for k, gs in by_key.items() if len(gs) > 1}
    # Keys in the namespace of a source of this workspace (the sidallocation.org owner, e.g. et:) whose copies all
    # come from other sources: the owner ships its rule disabled (commented out, so not a candidate) or not at all.
    # Such a copy is published only when the owner itself ever carried that exact text (a mirror); anything else
    # would go out under the owner's sid and name.
    owner_ns: dict[str, set[str]] = {}
    for name, (_, ns_, _) in info.items():
        owner_ns.setdefault(ns_, set()).add(name)
    every_key: dict[str, list[Any]] = {}
    for g in kept:  # ambiguous keys too: an owner's key is never another source's to publish under
        every_key.setdefault(g.rule_key, []).append(g)
    foreign = {
        k: gs
        for k, gs in every_key.items()
        if (ns := k.split(":", 1)[0]) in owner_ns and all(info.get(g.canonical_source, (0, g.canonical_source, ""))[1] != ns for g in gs)
    }
    if not contested and not foreign:
        return kept, []
    hashes = {g.logic_hash for gs in (*contested.values(), *foreign.values()) for g in gs}
    lineage: dict[str, set[str]] = {}  # source -> logic hashes it ever published (present or not)
    q = (
        select(RuleVersion.logic_hash, Source.name)
        .join(Occurrence, Occurrence.version_id == RuleVersion.id)
        .join(Source, Source.id == Occurrence.source_id)
        .distinct()
    )
    for h, name in s.execute(q):
        if h in hashes:
            lineage.setdefault(name, set()).add(h)
    drop: dict[int, str] = {}
    for key, gs in foreign.items():
        owners = owner_ns[key.split(":", 1)[0]]
        for g in gs:
            if not any(g.logic_hash in lineage.get(o, set()) for o in owners):
                drop[id(g)] = (
                    f"uses the sid of {key} ({', '.join(sorted(owners))}) with text that source never published: "
                    "left out (the owner's rule is disabled or absent)"
                )
    for key, gs in contested.items():
        ns = key.split(":", 1)[0]
        compete = [g for g in gs if not share_only or info.get(g.canonical_source, (0, "", "no"))[2] == "yes"]
        if len(compete) < 2:
            continue
        names = {n for g in compete for n in (g.sources or [g.canonical_source])} | {g.canonical_source for g in compete}
        order = sorted(names, key=lambda n: (info.get(n, (50, n, ""))[1] != ns, info.get(n, (50, n, ""))[0], n))
        rest = list(compete)
        winners: list[tuple[str, Any]] = []
        for name in order:
            mine = [g for g in rest if g.logic_hash in lineage.get(name, set())]
            if not mine:
                continue
            best = min(mine, key=lambda g: rank_revision(g, prio))
            winners.append((name, best))
            for g in mine:
                if g is not best:
                    drop[id(g)] = f"older revision (rev {g.rev}) of {key}: rev {best.rev} from {name} is kept"
            taken = {id(g) for g in mine}
            rest = [g for g in rest if id(g) not in taken]
        for g in rest:  # no lineage known (should not happen): fall back to the old ranking against the first winner
            winners.append((g.canonical_source, g))
        (first_src, first), others = winners[0], winners[1:]
        for _name, g in others:
            if (g.rev or 0) <= (first.rev or 0):
                drop[id(g)] = f"older revision (rev {g.rev}) of {key}: {first_src} owns the rule (rev {first.rev} is kept)"
            # else: a different rule with the same sid from another source: kept, export remaps it (collisions)
    if not drop:
        return kept, []
    return [g for g in kept if id(g) not in drop], [(g, drop[id(g)], None) for g in kept if id(g) in drop]


def rank_revision(g: Any, prio: dict[str, int]) -> tuple:
    """Which revision of one lineage to keep (smallest wins): highest rev, then the best source priority, then the
    highest score, then the logic hash, so equal revisions never depend on query order."""
    return (-(g.rev or 0), prio.get(g.canonical_source, 50), -(g.score or 0), g.logic_hash)


BUILD_FORMAT = 2  # bump when the build output changes, so older builds are not reused


def build_fingerprint(s: Session, t: Profile) -> str:
    """Index state + this profile's settings and exclusions: equal fingerprints build the same ruleset."""
    from suriharvest.db import get_meta
    from suriharvest.identity import sha256_hex

    ex = sorted((e.kind, e.value, tuple(e.keys or [])) for e in exclusions(s, t))
    return sha256_hex(
        repr(
            [
                get_meta(s, "index_fingerprint"),
                get_meta(s, "indexed_at"),
                t.query,
                t.unit,
                t.engine,
                sorted((t.options or {}).items(), key=str),
                ex,
            ]
        )
    )


def profile_dir(ws: Workspace, t: Profile) -> Path:
    return ws.data / "profiles" / t.name


def last_build(s: Session, t: Profile) -> ProfileBuild | None:
    return s.scalars(select(ProfileBuild).where(ProfileBuild.profile_id == t.id).order_by(ProfileBuild.id.desc()).limit(1)).first()


def _manifest(path: Path) -> dict[str, dict[str, Any]]:
    f = path / "manifest.jsonl"
    if not f.exists():
        return {}
    return {d["logic_hash"]: d for d in (json.loads(x) for x in f.read_text(encoding="utf-8").splitlines() if x)}


def _modified_checker(ws: Workspace, t: Profile, ov: Any) -> Any:
    """Rules the profile's modify entries rewrote are run through its engine (`suricata -T`) before they ship.
    Fail-safe: without an engine (or when it cannot run) no rewrite is validated, so none is applied: the rules
    ship unmodified and the build summary says why."""
    from suriharvest.validate import modified_checker

    cfg = next((e for e in ws.settings().engines if e.name == t.engine), None) if t.engine else None
    if cfg is None:
        ov.applied.unchecked = "the profile has no engine: modify entries were not applied (set one with `profile set --engine`)"
        return lambda todo: {h: "not applied: the profile has no engine to validate the modified rule" for h in todo}

    def note(why: str) -> None:
        ov.applied.unchecked = why

    return modified_checker(ws, cfg, note)


# a rule's own threshold / detection_filter option (Suricata then ignores threshold.config entries but suppress)
_OWN_THRESHOLD = re.compile(r"[(;]\s*(?:threshold|detection_filter)\s*:", re.IGNORECASE)


def make_build(s: Session, ws: Workspace, t: Profile) -> ProfileBuild:
    from suriharvest.export import export
    from suriharvest.overrides import Overrides
    from suriharvest.sidmap import holders_from_manifest

    if t.engine and t.engine not in {e.name for e in ws.settings().engines}:
        raise ProfileError(
            f"profile {t.name}: engine {t.engine!r} is not in suriharvest.yaml; fix it with `suriharvest profile set {t.name} --engine NAME`"
        )
    load_files(s, ws)  # hand edits of exclusions/*.yaml count
    ov = Overrides(s, t)
    sel = select_rules(s, t, ov)
    prev = last_build(s, t)
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%SZ")  # UTC, like the CLI and the web UI
    out = profile_dir(ws, t) / stamp
    n = 1
    while out.exists():  # two builds in the same second must not share (and overwrite) a folder
        n += 1
        out = profile_dir(ws, t) / f"{stamp}-{n}"
    rep = export(
        s,
        out,
        logic_hashes=[g.logic_hash for g in sel.kept],
        remap_sids=bool(t.options.get("remap_sids", True)),
        remap_base=int(t.options.get("remap_base") or ws.settings().remap_base),
        sid_map=ws.sid_map_file,
        redistributable_only=bool(t.options.get("redistributable_only", False)),
        iocs_as_datasets=bool(t.options.get("iocs_as_datasets", False)),
        forbid={g.logic_hash for g, _, _ in sel.excluded},
        setters_back={g.logic_hash for g, _, ex_id in sel.excluded if ex_id is not None}
        if t.options.get("flowbit_setters") == "suricata-update"
        else None,
        split_by_source=True,
        previous_holders=holders_from_manifest(_manifest(Path(prev.path)).values()) if prev else None,
        rewrite=ov.rewrite if ov.items["modify"] else None,
        check_modified=_modified_checker(ws, t, ov) if ov.items["modify"] else None,
        ws=ws,
        engine=t.engine,
    )
    ov.settle(rep.modified, rep.modify_refused)
    if rep.setters_back:  # shipped (noalert) after all: not excluded
        sel.excluded = [x for x in sel.excluded if x[0].logic_hash not in rep.setters_back]
    by_hash = {g.logic_hash: g for g in sel.kept}
    sel.excluded += [(by_hash[d["logic_hash"]], d["reason"], None) for d in rep.left_out_datasets if d["logic_hash"] in by_hash]
    if ov.items["thresholds"]:
        man = _manifest(out)
        on = [h for h, d in man.items() if d.get("enabled", True)]
        rows = list(s.execute(select(*LIGHT).where(in_list(LogicGroup.logic_hash, on))))
        own = {
            h
            for h, raw in s.execute(
                select(LogicGroup.logic_hash, RuleVersion.raw)
                .join(RuleVersion, RuleVersion.id == LogicGroup.canonical_version_id)
                .where(in_list(LogicGroup.logic_hash, on))
            )
            if _OWN_THRESHOLD.search(raw or "")
        }
        lines = ov.thresholds(sorted(((r, man[r.logic_hash]["exported_sid"]) for r in rows), key=lambda x: (x[0].gid, x[1])), own)
        (out / "threshold.config").write_text(
            f"# suriharvest: thresholds of profile {t.name} ({len(lines)} lines), sids as exported in suricata.rules\n"
            + "".join(x + "\n" for x in lines),
            encoding="utf-8",
            newline="\n",
        )
    applied = ov.finish()
    (out / "logic_hashes.txt").write_text("".join(h + "\n" for h in sorted(_manifest(out))), encoding="utf-8", newline="\n")
    with (out / "excluded.jsonl").open("w", encoding="utf-8", newline="\n") as f:
        for g, why, ex_id in sel.excluded:
            f.write(
                json.dumps(
                    {"logic_hash": g.logic_hash, "sid": g.sid, "rule_key": g.rule_key, "msg": g.msg, "reason": why, "exclusion": ex_id}
                )
                + "\n"
            )
    # sticky keys and match counts
    per_ex = Counter(ex_id for _, _, ex_id in sel.excluded if ex_id is not None)
    keys: dict[int, set[str]] = {}
    for g, _, ex_id in sel.excluded:
        if ex_id is not None:
            keys.setdefault(ex_id, set()).add(g.rule_key)
    for ex in exclusions(s, t):
        ex.last_matched, ex.last_checked_at = per_ex.get(ex.id, 0), utcnow()
        ex.keys = sorted(set(ex.keys or []) | keys.get(ex.id, set()))
    now = _manifest(out)
    before = _manifest(Path(prev.path)) if prev else {}
    msgs = {g.logic_hash: g.msg for g in sel.kept}

    def brief(d: dict[str, Any]) -> dict[str, Any]:
        return {
            "logic_hash": d["logic_hash"],
            "sid": d["sid"],
            "exported_sid": d.get("exported_sid"),
            "source": d.get("source"),
            "msg": msgs.get(d["logic_hash"], d.get("msg")),
        }

    plus, minus = set(now.keys() - before.keys()), set(before.keys() - now.keys())
    revised = pair_new_revisions(before, now, plus, minus)
    plus -= {n for _, n in revised}
    minus -= {o for o, _ in revised}
    added = [brief(now[h]) for h in plus]
    removed = [brief(before[h]) for h in minus]
    changed = [
        {**brief(now[n]), "change": f"rev {before[o].get('rev')} -> {now[n].get('rev')}", "previous_logic_hash": o} for o, n in revised
    ]
    reasons = Counter(
        "does not load" if why.startswith("does not load") else "older revision" if why.startswith("older revision") else why.split(":")[0]
        for _, why, _ in sel.excluded
    )
    summary = {
        "candidates": len(sel.kept) + len(sel.excluded),
        "excluded_by": dict(reasons),
        "added": len(added),
        "removed": len(removed),
        "changed": len(changed),
        "added_sample": sorted(added, key=lambda d: d["sid"])[:50],
        "removed_sample": sorted(removed, key=lambda d: d["sid"])[:50],
        "flowbit_setters_added": rep.setters_added,
        "flowbit_setters_back": sorted(rep.setters_back.values())[:50],
        "missing_setters": rep.missing_setters[:50],
        "remapped_sids": rep.remapped,
        "needed_files": rep.needed_files[:50],
        "previous_build": prev.id if prev else None,
        "fingerprint": build_fingerprint(s, t),
        "by_source": rep.by_source,
        **applied.summary(),
    }
    (out / "changes.json").write_text(json.dumps({"added": added, "removed": removed, "changed": changed}), encoding="utf-8", newline="\n")
    b = ProfileBuild(profile_id=t.id, path=str(out), rules=rep.rules, excluded=len(sel.excluded), summary=summary)
    s.add(b)
    s.commit()
    _point_latest(out)
    return b


def _point_latest(out: Path) -> None:
    """data/profiles/<name>/latest -> the newest build folder (a relative symlink; LATEST holds the folder name too,
    for systems without symlinks). Sensors and scripts can use .../latest/suricata.rules."""
    link, tmp, marker = out.parent / "latest", out.parent / ".latest.tmp", out.parent / "LATEST"
    if marker.is_symlink():  # an earlier build put `latest` over it (case-insensitive file system)
        marker.unlink()
    marker.write_text(out.name + "\n", encoding="utf-8", newline="\n")
    if link.exists() and os.path.samefile(link, marker):
        return  # case-insensitive file system (Windows, macOS): `latest` IS `LATEST`; the file is the pointer
    try:
        if tmp.is_symlink() or tmp.exists():
            tmp.unlink()
        tmp.symlink_to(out.name, target_is_directory=True)
        tmp.replace(link)  # atomic swap: a reader never sees a missing link
    except OSError:
        pass


# ---------------------------------------------------------------------------------------------------------------
# suggestions for the analyst


@dataclass
class Suggestion:
    title: str
    why: str
    kind: str
    value: str
    count: int
    examples: list[str]


# Name categories that are mostly informational / policy / hunting: high volume, low severity.
NOISY_CATEGORIES = ("INFO", "POLICY", "HUNTING", "GAMES", "CHAT", "P2P", "INAPPROPRIATE", "USER_AGENTS")
SUGGESTED_QUERIES = (
    ("Retired by the publisher", "flag:retired", "moved to the retired set: no longer maintained"),
    ("Deleted by the publisher", "flag:deleted", "kept by ET only for history; disabled upstream"),
    ("Deprecated by the publisher", "flag:deprecated", "ET deprecation_reason metadata"),
    ("Disabled by default upstream", "enabled:no", "the publisher ships them commented out (noisy or expensive)"),
    ("High performance impact", "perf:high", "ET performance_impact High: costly on busy sensors"),
    ("Checks a flowbit that nothing sets", "flag:missing_setter", "can never fire"),
    ("IOC rules not updated for 2+ years", "ioc:yes updated<{two_years_ago}", "indicators age fast"),
    ("No content usable as fast pattern", "flag:no_prefilter_content", "evaluated on every packet of the protocol"),
)


def suggestions(s: Session, t: Profile, examples: int = 3) -> list[Suggestion]:
    sel = select_rules(s, t)
    live = sel.kept
    if not live:
        return []
    out: list[Suggestion] = []
    cats = Counter(g.category for g in live if g.category)
    for cat, n in cats.most_common():
        words = cat.split()
        if len(words) == 2 and words[1].upper() in NOISY_CATEGORIES:
            ex = [g.msg or "" for g in live if g.category == cat][:examples]
            out.append(Suggestion(f"Category {cat}", "informational / policy rules: high volume, low severity", "category", cat, n, ex))
    kept_hashes = {g.logic_hash for g in live}
    two_years_ago = f"{datetime.now().year - 2}-{datetime.now():%m-%d}"
    for title, q, why in SUGGESTED_QUERIES:
        query = q.format(two_years_ago=two_years_ago)
        stmt = build(parse_query(query), families=False, include_junk=True, include_dropped=True)
        hits = [g for g in s.execute(stmt.with_only_columns(*LIGHT)) if g.logic_hash in kept_hashes]
        if hits:
            out.append(Suggestion(title, why, "query", query, len(hits), [g.msg or "" for g in hits[:examples]]))
    by_sid = Counter((g.gid, g.sid) for g in live)
    clashing = sum(n - 1 for n in by_sid.values() if n > 1)
    if clashing:
        worst = [f"sid {sid}: {n} rules" for (_, sid), n in by_sid.most_common(3) if n > 1]
        remap = bool((t.options or {}).get("remap_sids", True))
        out.append(
            Suggestion(
                "Rules sharing a sid with another rule",
                "Suricata loads only one rule per gid:sid; "
                + ("the build gives the others new sids (remap_sids on)" if remap else "turn on remap_sids or exclude them"),
                "info",
                "",
                clashing,
                worst,
            )
        )
    return sorted(out, key=lambda x: -x.count)


def built_hashes(b: ProfileBuild | None) -> set[str]:
    if b is None:
        return set()
    f = Path(b.path) / "logic_hashes.txt"
    return set(f.read_text(encoding="utf-8").split()) if f.exists() else set(_manifest(Path(b.path)))


def new_since_last_build(s: Session, t: Profile) -> list[Any]:
    """Rules that would be in the profile now and are not in its last build."""
    return new_since(s, t, last_build(s, t))


# ---------------------------------------------------------------------------------------------------------------
# exclusions on disk: exclusions/<profile>.yaml and exclusions/all-profiles.yaml

GLOBAL_FILE = "all-profiles"


def exclusion_file(ws: Workspace, t: Profile | None) -> Path:
    return ws.root / "exclusions" / f"{t.name if t else GLOBAL_FILE}.yaml"


def _scope_items(s: Session, t: Profile | None) -> list[Exclusion]:
    q = select(Exclusion).where(Exclusion.profile_id == t.id) if t else select(Exclusion).where(Exclusion.profile_id.is_(None))
    return list(s.scalars(q.order_by(Exclusion.id)))


def render_file(s: Session, t: Profile | None) -> str:
    items = _scope_items(s, t)
    head = (
        f"# suriharvest exclusions for {t.name if t else 'every profile'}. Edit here or in the web UI: both stay in sync.\n"
        "# rule_exclusions: rule name substrings (case-sensitive).\n"
        "# exclusions: other kinds (msg_exact msg_regex sid rule_key logic category classtype source query).\n"
    )
    data: dict[str, Any] = {"rule_exclusions": [], "exclusions": []}
    for ex in items:
        extra = {k: v for k, v in (("reason", ex.reason), ("review", ex.review_at.date().isoformat() if ex.review_at else None)) if v}
        if ex.kind == "msg_contains":
            data["rule_exclusions"].append({"msg": ex.value, **extra})
        else:
            data["exclusions"].append({"kind": ex.kind, "value": ex.value, **extra})
    if t is not None:
        from suriharvest.overrides import entries

        head += "# enable / modify / thresholds: profile overrides, applied at every build (docs/profiles.md).\n"
        data |= {k: v for k, v in entries(t).items() if v}
    return head + yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=200)


def save_files(s: Session, ws: Workspace, keep: set[str] | None = None) -> None:
    """Write every scope's file and remember what was written (so a later hand edit is recognised). Files named in
    `keep` (broken hand edits that were reported) are left as they are."""
    from suriharvest.db import set_meta
    from suriharvest.identity import sha256_hex

    for t in [None, *s.scalars(select(Profile).order_by(Profile.name))]:
        f = exclusion_file(ws, t)
        if keep and f.name in keep:
            continue
        text = render_file(s, t)
        if t is None and not _scope_items(s, None) and not f.exists():
            continue
        f.parent.mkdir(parents=True, exist_ok=True)
        if not f.exists() or f.read_text(encoding="utf-8") != text:
            f.write_text(text, encoding="utf-8", newline="\n")
        set_meta(s, f"exclusions_file:{f.name}", sha256_hex(text))
    s.commit()


def _parse_file(f: Path) -> list[tuple[str, str, str | None, datetime | None]]:
    data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
    out = []
    for it in data.get("rule_exclusions") or []:
        if isinstance(it, dict) and it.get("msg"):
            out.append(("msg_contains", str(it["msg"]), it.get("reason"), _date(it.get("review"))))
    for it in data.get("exclusions") or []:
        if isinstance(it, dict) and it.get("kind") and it.get("value") is not None:
            out.append((str(it["kind"]), str(it["value"]), it.get("reason"), _date(it.get("review"))))
    return out


def _parse_sections(f: Path, t: Profile | None, skipped: list[str] | None = None) -> dict[str, list[dict[str, Any]]]:
    """enable / modify / thresholds of a profile file, checked. A broken entry raises ValueError with its number,
    or, with `skipped`, is left out and described there (one bad entry must not cost the others)."""
    from suriharvest.overrides import SECTIONS, OverrideError, normalise

    data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
    out: dict[str, list[dict[str, Any]]] = {}
    for sec in SECTIONS:
        items = data.get(sec) or []
        if not items:
            continue
        if t is None:
            raise ValueError(f"{sec}: only in a profile's file, not in {GLOBAL_FILE}.yaml")
        if not isinstance(items, list):
            raise ValueError(f"{sec}: expected a list")
        out[sec] = []
        for n, x in enumerate(items, 1):
            try:
                out[sec].append(normalise(sec, x))
            except OverrideError as e:
                if skipped is None:
                    raise ValueError(f"{sec} #{n}: {e}") from e
                skipped.append(f"{sec} #{n} skipped: {e}")
    return out


def _date(v: Any) -> datetime | None:
    if not v:
        return None
    return datetime.fromisoformat(str(v))


@dataclass
class FileSync:
    added: int = 0
    removed: int = 0
    errors: list[str] = field(default_factory=list)


def load_files(s: Session, ws: Workspace) -> FileSync:
    """Apply hand edits: a file whose content differs from what suriharvest last wrote is the truth for its scope
    (entries added, changed and removed). A broken file is reported and left alone."""
    from suriharvest.db import get_meta
    from suriharvest.identity import sha256_hex

    res = FileSync()
    broken: set[str] = set()
    for t in [None, *s.scalars(select(Profile).order_by(Profile.name))]:
        f = exclusion_file(ws, t)
        if not f.exists():
            continue
        text = f.read_text(encoding="utf-8")
        if get_meta(s, f"exclusions_file:{f.name}") == sha256_hex(text):
            continue
        try:
            wanted = _parse_file(f)
            for kind, value, _, _ in wanted:
                _check(kind, value)
            skipped: list[str] = []
            sections = _parse_sections(f, t, skipped)
        except (yaml.YAMLError, ProfileError, ValueError) as e:
            res.errors.append(f"{f.name}: {e}")
            broken.add(f.name)
            continue
        if skipped:  # the other entries apply; the file stays as written until the entry is fixed
            res.errors += [f"{f.name}: {x} (the other entries apply)" for x in skipped]
            broken.add(f.name)
        have = {(ex.kind, ex.value): ex for ex in _scope_items(s, t)}
        keys = set()
        for kind, value, reason, review in wanted:
            keys.add((kind, value))
            ex = have.get((kind, value))
            if ex is None:
                add_exclusion(s, t, kind, value, reason or f"added in {f.name}", author="file", review_at=review)
                res.added += 1
            else:
                ex.reason, ex.review_at = reason or ex.reason, review
        for key, ex in have.items():
            if key not in keys:
                s.delete(ex)
                res.removed += 1
        if t is not None:
            from suriharvest.overrides import SECTIONS, set_entries

            for sec in SECTIONS:
                set_entries(t, sec, sections.get(sec, []))
        s.commit()
    save_files(s, ws, keep=broken)
    return res


# ---------------------------------------------------------------------------------------------------------------
# what changed between builds


def pair_new_revisions(
    old: dict[str, dict[str, Any]], new: dict[str, dict[str, Any]], plus: set[str], minus: set[str]
) -> list[tuple[str, str]]:
    """(old logic hash, new logic hash) for rules that left and arrived under the same rule key
    (namespace:gid:sid): a new revision of one rule, not a removed rule plus an added one."""
    gone: dict[str, list[str]] = {}
    for h in sorted(minus):
        if key := old.get(h, {}).get("rule_key"):
            gone.setdefault(key, []).append(h)
    pairs = []
    for h in sorted(plus):
        key = new.get(h, {}).get("rule_key")
        if key and gone.get(key):
            pairs.append((gone[key].pop(0), h))
    return pairs


@dataclass
class BuildDiff:
    added: list[dict[str, Any]]
    removed: list[dict[str, Any]]
    changed: list[dict[str, Any]] = field(default_factory=list)  # same logic, new rev / exported sid / source


def diff_builds(old: ProfileBuild | None, new: ProfileBuild) -> BuildDiff:
    """Rules in `new` and not in `old` and the other way round, plus rules in both whose rev, exported sid or
    source changed (from the manifests)."""
    if old is None:
        return BuildDiff([], [])
    man_new, man_old = _manifest(Path(new.path)), _manifest(Path(old.path))
    a, b = set(man_old) or built_hashes(old), set(man_new) or built_hashes(new)
    plus, minus = b - a, a - b

    def brief(m: dict[str, dict[str, Any]], h: str) -> dict[str, Any]:
        d = m.get(h, {})
        return {"logic_hash": h, "sid": d.get("sid"), "exported_sid": d.get("exported_sid"), "msg": d.get("msg"), "source": d.get("source")}

    changed = []
    for old_h, new_h in pair_new_revisions(man_old, man_new, plus, minus):
        plus.discard(new_h)
        minus.discard(old_h)
        o, n = man_old[old_h], man_new[new_h]
        what = [f"{k} {o.get(k)} -> {n.get(k)}" for k in ("rev", "exported_sid", "source") if o.get(k) != n.get(k)]
        changed.append({**brief(man_new, new_h), "change": "; ".join([*what, "new logic"])})
    for h in sorted(a & b):
        o, n = man_old.get(h, {}), man_new.get(h, {})
        what = [f"{k} {o.get(k)} -> {n.get(k)}" for k in ("rev", "exported_sid", "source") if o.get(k) != n.get(k)]
        if what:
            changed.append({**brief(man_new, h), "change": "; ".join(what)})
    return BuildDiff(
        sorted((brief(man_new, h) for h in plus), key=lambda d: d["sid"] or 0),
        sorted((brief(man_old, h) for h in minus), key=lambda d: d["sid"] or 0),
        sorted(changed, key=lambda d: d["sid"] or 0),
    )


def get_build(s: Session, t: Profile, ref: str) -> ProfileBuild | None:
    """A build of this profile by id, or 'latest' / 'previous'."""
    q = select(ProfileBuild).where(ProfileBuild.profile_id == t.id).order_by(ProfileBuild.id.desc())
    if ref in ("latest", "previous"):
        rows = list(s.scalars(q.limit(2)))
        idx = 0 if ref == "latest" else 1
        return rows[idx] if len(rows) > idx else None
    if option_int(ref) is None:
        return None
    b = s.get(ProfileBuild, option_int(ref))
    return b if b is not None and b.profile_id == t.id else None


def new_since(s: Session, t: Profile, ref: ProfileBuild | None) -> list[Any]:
    """Rules the profile selects now that are not in build `ref`."""
    before = built_hashes(ref)
    return [g for g in select_rules(s, t).kept if g.logic_hash not in before]


def add_source_to_query(query: str, source: str) -> str:
    """Make a profile's candidates include `source`. An empty query (every rule) or one without a source filter
    already includes it; a `source:a,b` term gets the name appended."""
    import shlex

    try:
        tokens = shlex.split(query)
    except ValueError:
        return query
    for i, tok in enumerate(tokens):
        if tok.startswith("source:"):
            names = [n for n in tok[7:].split(",") if n]
            if source in names:
                return query
            tokens[i] = "source:" + ",".join([*names, source])
            return " ".join(shlex.quote(t) if " " in t else t for t in tokens)
    return query
