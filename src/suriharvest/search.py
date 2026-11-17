"""Search the index: FTS5 over msg/contents/metadata/references plus inline filters.

    suriharvest search 'cobalt strike app:http ioc:no loads:local'

Filters: dialect:suricata|both|snort cat:"ET INFO" enabled:no perf:high updated<2024-01-01 proto: app: buffer: classtype:
source: sid: ioc:(yes|no|domain|ip|ja3...) verdict:(keep|review|drop|none)
loads:<engine> fails:<engine> flag: severity: mitre: score>=N. Words without a colon go to full-text search.
By default one row per family, junk and dropped rules hidden (`all` options turn that off).
"""

from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import Select, func, or_, select, text
from sqlalchemy.orm import Session

from suriharvest.models import LogicGroup, LogicGroupValue, Occurrence, Quarantine, RuleVersion, ValidationResult

FILTERS = (
    "dialect",
    "cat",
    "category",
    "enabled",
    "perf",
    "redistributable",
    "proto",
    "app",
    "buffer",
    "classtype",
    "source",
    "sid",
    "ioc",
    "verdict",
    "loads",
    "fails",
    "flag",
    "severity",
    "mitre",
    "key",
)


class QueryError(ValueError):
    pass


# One query is typed by a person: these caps keep a pasted blob from tying up the server.
MAX_QUERY_CHARS = 1024
MAX_QUERY_TERMS = 32
MAX_SID = 2**32 - 1  # Suricata sids are unsigned 32-bit
_NUMBER = re.compile(r"[0-9]{1,10}")


@dataclass
class Query:
    words: list[str] = field(default_factory=list)
    filters: list[tuple[str, str]] = field(default_factory=list)
    min_score: int | None = None


def check_size(q: str) -> None:
    """Interactive searches (web page, API, CLI search): refuse a query a person would not type."""
    if len(q) > MAX_QUERY_CHARS:
        raise QueryError(f"query too long ({len(q)} characters, at most {MAX_QUERY_CHARS})")
    if len(q.split()) > MAX_QUERY_TERMS:
        raise QueryError(f"too many terms ({len(q.split())}, at most {MAX_QUERY_TERMS})")


def parse_query(q: str) -> Query:
    out = Query()
    try:
        tokens = shlex.split(q)
    except ValueError as e:
        raise QueryError(str(e)) from e
    for tok in tokens:
        m = re.fullmatch(r"score>=([0-9]{1,6})", tok)
        if m:
            out.min_score = int(m.group(1))
            continue
        m = re.fullmatch(r"updated([<>])(\d{4}-\d{2}-\d{2})", tok)
        if m:
            out.filters.append(("updated" + m.group(1), m.group(2)))
            continue
        key, sep, val = tok.partition(":")
        if sep and key.lower() in FILTERS and val:
            out.filters.append((key.lower(), val))
        else:
            out.words.append(tok)
    return out


def _has(kind: str, value: str):  # type: ignore[no-untyped-def]
    """The group's `kind` list (models.VALUE_KINDS) holds `value`, ignoring case: an indexed lookup in
    logic_group_values, which keeps each element and SQLite's lower() of it."""
    return LogicGroup.id.in_(
        select(LogicGroupValue.group_id).where(LogicGroupValue.kind == kind, LogicGroupValue.lvalue == func.lower(value))
    )


# Control characters (NUL ends an FTS5 string: "unterminated string") and lone surrogates (not encodable as
# UTF-8) never reach MATCH: they become spaces.
_FTS_JUNK = re.compile(r"[\x00-\x1f\x7f\ud800-\udfff]")


def _phrase(w: str) -> str:
    return '"' + w.replace('"', '""') + '"'


def _term(w: str) -> str:
    """One FTS term. A long single word also matches the same letters written as two words, so `cobaltstrike`
    finds "Cobalt Strike" (and still finds "CobaltStrike")."""
    quoted = _phrase(w)
    if len(w) < 8 or not w.isalpha():
        return quoted
    splits = [_phrase(f"{w[:i]} {w[i:]}") for i in range(3, len(w) - 2)]
    return "(" + " OR ".join([quoted, *splits]) + ")"


def _fts_query(words: list[str]) -> str:
    """Words are ANDed; two plain words also match their joined spelling (`cobalt strike` finds "CobaltStrike").

    Total: every word is a quoted phrase and terms are joined with an explicit AND (FTS5 refuses an implicit AND
    next to a parenthesised group), so any input gives a valid MATCH expression; "" when no word is left."""
    words = [c for c in (_FTS_JUNK.sub(" ", w).strip() for w in words) if c]
    if not words:
        return ""
    if len(words) == 2 and all(w.isalpha() for w in words):
        a, b = (_phrase(w) for w in words)
        return f"(({a} AND {b}) OR {_phrase(words[0] + words[1])})"
    return " AND ".join(_term(w) for w in words)


def build(q: Query, *, families: bool = True, include_junk: bool = False, include_dropped: bool = False) -> Select:
    stmt = select(LogicGroup)
    fts = _fts_query(q.words) if q.words else ""
    if fts:
        stmt = stmt.where(LogicGroup.id.in_(text("SELECT rowid FROM rules_fts WHERE rules_fts MATCH :fts").bindparams(fts=fts)))
    verdict_filtered = False
    for key, val in q.filters:
        lv = val.lower()
        if key == "proto":
            stmt = stmt.where(LogicGroup.protocol == lv)
        elif key == "app":
            stmt = stmt.where(LogicGroup.app_layer == lv)
        elif key == "buffer":
            stmt = stmt.where(_has("buffers", lv))
        elif key == "classtype":
            stmt = stmt.where(LogicGroup.classtype == val)
        elif key == "source":
            names = [v for v in val.split(",") if v]  # source:a,b = carried by a or b
            stmt = stmt.where(or_(*[_has("sources", n) for n in names]))
        elif key == "sid":
            if not _NUMBER.fullmatch(val) or int(val) > MAX_SID:
                raise QueryError(f"sid: needs a number from 0 to {MAX_SID}")
            stmt = stmt.where(LogicGroup.sid == int(val))
        elif key == "key":
            stmt = stmt.where(LogicGroup.rule_key == val)
        elif key == "ioc":
            if lv in ("yes", "true", "1"):
                stmt = stmt.where(LogicGroup.is_ioc.is_(True))
            elif lv in ("no", "false", "0"):
                stmt = stmt.where(LogicGroup.is_ioc.is_(False))
            else:
                stmt = stmt.where(LogicGroup.ioc_type == lv)
        elif key == "dialect":
            stmt = stmt.where(_has("flags", "dialect:" + lv))
        elif key in ("cat", "category"):
            stmt = stmt.where(LogicGroup.category.collate("NOCASE") == lv)
        elif key == "enabled":
            stmt = stmt.where(LogicGroup.enabled_anywhere.is_(lv in ("yes", "true", "1")))
        elif key == "perf":
            stmt = stmt.where(LogicGroup.performance_impact.collate("NOCASE") == lv)
        elif key == "updated<":
            stmt = stmt.where(LogicGroup.updated < val)
        elif key == "updated>":
            stmt = stmt.where(LogicGroup.updated > val)
        elif key == "redistributable":
            stmt = stmt.where(LogicGroup.redistributable.is_(lv in ("yes", "true", "1")))
        elif key == "verdict":
            verdict_filtered = True
            stmt = stmt.where(LogicGroup.verdict.is_(None) if lv == "none" else LogicGroup.verdict == lv)
        elif key == "loads":
            stmt = stmt.where(_has("loads_in", val))
        elif key == "fails":
            stmt = stmt.where(_has("fails_in", val))
        elif key == "flag":
            stmt = stmt.where(_has("flags", lv))
        elif key == "severity":
            stmt = stmt.where(LogicGroup.severity.collate("NOCASE") == lv)
        elif key == "mitre":
            stmt = stmt.where(_has("mitre", val.upper()))
    if q.min_score is not None:
        stmt = stmt.where(LogicGroup.score >= q.min_score)
    if families:
        stmt = stmt.where(LogicGroup.is_family_best.is_(True))
    if not include_junk:
        stmt = stmt.where(LogicGroup.junk.is_(False))
    if not include_dropped and not verdict_filtered:
        stmt = stmt.where(or_(LogicGroup.verdict.is_(None), LogicGroup.verdict != "drop"))
    return stmt


def search(
    s: Session,
    query: str,
    *,
    limit: int = 50,
    offset: int = 0,
    families: bool = True,
    include_junk: bool = False,
    include_dropped: bool = False,
) -> tuple[int, list[LogicGroup]]:
    stmt = build(parse_query(query), families=families, include_junk=include_junk, include_dropped=include_dropped)
    total = s.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    return total, page_rows(s, stmt, [LogicGroup.score.desc(), LogicGroup.id], limit, offset)


def page_rows(s: Session, stmt: Select, order: list[Any], limit: int, offset: int) -> list[LogicGroup]:
    """One page of a search: the matching ids are sorted first, then only the page's rows are read.

    Sorting whole rows copies each matching row into SQLite's sorter, one allocation per row, and SQLite counts
    every allocation under one process-wide lock: concurrent searches in the web server's threads then wait on
    each other. `order` must end with a unique column so the page is the same either way."""
    ids = list(s.scalars(stmt.with_only_columns(LogicGroup.id).order_by(*order).limit(limit).offset(offset)))
    if not ids:
        return []
    by_id = {g.id: g for g in s.scalars(select(LogicGroup).where(LogicGroup.id.in_(ids)))}
    return [by_id[i] for i in ids]


def resolve(s: Session, ref: str) -> list[LogicGroup]:
    """Find groups by logic hash (prefix >= 8), rule key (ns:gid:sid), or bare sid."""
    if re.fullmatch(r"[0-9a-f]{8,64}", ref):
        return list(s.scalars(select(LogicGroup).where(LogicGroup.logic_hash.like(ref + "%"))))
    if ref.count(":") == 2:
        return list(s.scalars(select(LogicGroup).where(LogicGroup.rule_key == ref)))
    if _NUMBER.fullmatch(ref) and int(ref) <= MAX_SID:
        return list(s.scalars(select(LogicGroup).where(LogicGroup.sid == int(ref)).order_by(LogicGroup.score.desc())))
    return []


ROW_FIELDS = (
    "logic_hash",
    "rule_key",
    "sid",
    "rev",
    "msg",
    "score",
    "score_parts",
    "app_layer",
    "canonical_source",
    "sources",
    "n_sources",
    "family_id",
    "family_size",
    "is_ioc",
    "ioc_type",
    "ioc_value",
    "flags",
    "loads_in",
    "fails_in",
    "verdict",
)


def row_dict(g: LogicGroup) -> dict[str, Any]:
    """The JSON shape of one search hit (CLI `search --json` and `GET /api/search`)."""
    return {k: getattr(g, k) for k in ROW_FIELDS}


def corpus_stats(s: Session) -> dict[str, Any]:
    """Corpus funnel and validation counts (CLI `stats --json` and `GET /api/stats`)."""
    from suriharvest.db import get_meta

    rep: dict[str, Any] = json.loads(get_meta(s, "index_report") or "{}")
    rep["occurrences_present"] = s.scalar(select(func.count()).select_from(Occurrence).where(Occurrence.present.is_(True))) or 0
    rep["versions_total"] = s.scalar(select(func.count()).select_from(RuleVersion)) or 0
    rep["quarantined"] = s.scalar(select(func.count()).select_from(Quarantine).where(Quarantine.present.is_(True))) or 0
    rep["disabled_upstream"] = s.scalar(select(func.count()).select_from(LogicGroup).where(LogicGroup.enabled_anywhere.is_(False))) or 0
    ioc = s.execute(select(LogicGroup.ioc_type, func.count()).where(LogicGroup.is_ioc.is_(True)).group_by(LogicGroup.ioc_type)).all()
    rep["ioc_types"] = {k: n for k, n in ioc}
    val = s.execute(
        select(ValidationResult.engine, ValidationResult.status, func.count()).group_by(ValidationResult.engine, ValidationResult.status)
    ).all()
    rep["validation"] = {f"{e}:{st}": n for e, st, n in val}
    rep["indexed_at"] = get_meta(s, "indexed_at")
    return rep
