"""Database tables.

Corpus (never deleted): sources, sync_log, rule_versions, occurrences, quarantine.
Results (cache entries keyed by everything that changes them): validation_results.
Derived (rebuilt by `suriharvest index`): logic_groups, logic_group_values, rule_keys, rules_fts.
User data (never rewritten by a rebuild): verdicts.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class Meta(Base):
    __tablename__ = "meta"
    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[str] = mapped_column(Text)


class Source(Base):
    __tablename__ = "sources"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    type: Mapped[str] = mapped_column(String(20))
    url: Mapped[str] = mapped_column(Text)
    licence: Mapped[str | None] = mapped_column(String(100))
    priority: Mapped[int] = mapped_column(Integer, default=50)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    redistribute: Mapped[str] = mapped_column(String(10), default="unknown")  # yes | no | unknown
    sid_namespace: Mapped[str] = mapped_column(String(200))
    last_commit: Mapped[str | None] = mapped_column(String(64))
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime)


class SyncLog(Base):
    __tablename__ = "sync_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id"), index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime)
    old_commit: Mapped[str | None] = mapped_column(String(64))
    new_commit: Mapped[str | None] = mapped_column(String(64))
    files_added: Mapped[int] = mapped_column(Integer, default=0)
    files_changed: Mapped[int] = mapped_column(Integer, default=0)
    files_removed: Mapped[int] = mapped_column(Integer, default=0)
    rules_seen: Mapped[int] = mapped_column(Integer, default=0)
    versions_new: Mapped[int] = mapped_column(Integer, default=0)
    quarantined: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(20), default="running")
    error: Mapped[str | None] = mapped_column(Text)


class RuleVersion(Base):
    """One distinct rule text (content_hash). Facts are computed once at ingest."""

    __tablename__ = "rule_versions"
    id: Mapped[int] = mapped_column(primary_key=True)
    content_hash: Mapped[str] = mapped_column(String(64), unique=True)
    logic_hash: Mapped[str] = mapped_column(String(64), index=True)
    semantic_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    alerting_hash: Mapped[str] = mapped_column(String(64))
    gid: Mapped[int] = mapped_column(Integer, default=1)
    sid: Mapped[int] = mapped_column(Integer, index=True)
    rev: Mapped[int | None] = mapped_column(Integer)
    msg: Mapped[str | None] = mapped_column(Text)
    action: Mapped[str] = mapped_column(String(20))
    protocol: Mapped[str] = mapped_column(String(30))
    app_layer: Mapped[str] = mapped_column(String(30), index=True)
    classtype: Mapped[str | None] = mapped_column(String(100))
    buffers: Mapped[list[Any]] = mapped_column(JSON, default=list)
    contents: Mapped[list[Any]] = mapped_column(JSON, default=list)
    rule_metadata: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)
    references: Mapped[list[Any]] = mapped_column(JSON, default=list)
    flowbits_set: Mapped[list[Any]] = mapped_column(JSON, default=list)
    flowbits_check: Mapped[list[Any]] = mapped_column(JSON, default=list)
    files: Mapped[list[Any]] = mapped_column(JSON, default=list)
    ioc_type: Mapped[str | None] = mapped_column(String(30))
    ioc_value: Mapped[str | None] = mapped_column(Text)
    flags: Mapped[list[Any]] = mapped_column(JSON, default=list)
    features: Mapped[list[Any]] = mapped_column(JSON, default=list, server_default="[]")
    raw: Mapped[str] = mapped_column(Text)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Occurrence(Base):
    """Where a version was seen. `ordinal` separates identical rules repeated in one file."""

    __tablename__ = "occurrences"
    __table_args__ = (UniqueConstraint("source_id", "path", "version_id", "ordinal"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    version_id: Mapped[int] = mapped_column(ForeignKey("rule_versions.id"), index=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id"), index=True)
    path: Mapped[str] = mapped_column(Text)
    ordinal: Mapped[int] = mapped_column(Integer, default=0)
    line_no: Mapped[int] = mapped_column(Integer)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    commit: Mapped[str | None] = mapped_column(String(64))
    present: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Quarantine(Base):
    """Lines that look like rules but cannot be parsed (kept with the error, never silently dropped)."""

    __tablename__ = "quarantine"
    __table_args__ = (Index("ix_quarantine_src_path", "source_id", "path"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id"))
    path: Mapped[str] = mapped_column(Text)
    line_no: Mapped[int] = mapped_column(Integer)
    content_hash: Mapped[str] = mapped_column(String(64))
    raw: Mapped[str] = mapped_column(Text)
    error: Mapped[str] = mapped_column(Text)
    present: Mapped[bool] = mapped_column(Boolean, default=True)
    seen_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class ValidationResult(Base):
    """Does a rule load in an engine? Keyed by (content_hash, engine, config_hash): a cache entry."""

    __tablename__ = "validation_results"
    content_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    engine: Mapped[str] = mapped_column(String(100), primary_key=True)
    config_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    engine_version: Mapped[str] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(20))  # ok | error
    category: Mapped[str | None] = mapped_column(String(40))  # unknown_keyword | disabled_protocol | missing_file | ...
    error: Mapped[str | None] = mapped_column(Text)
    checked_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class LogicGroup(Base):
    """Derived: one row per unique logic among live versions (rebuilt by `suriharvest index`)."""

    __tablename__ = "logic_groups"
    id: Mapped[int] = mapped_column(primary_key=True)
    logic_hash: Mapped[str] = mapped_column(String(64), unique=True)
    semantic_hash: Mapped[str | None] = mapped_column(String(64), index=True)
    canonical_version_id: Mapped[int] = mapped_column(Integer)
    canonical_source: Mapped[str] = mapped_column(String(200), index=True)
    rule_key: Mapped[str] = mapped_column(String(250), index=True)  # namespace:gid:sid
    gid: Mapped[int] = mapped_column(Integer)
    sid: Mapped[int] = mapped_column(Integer, index=True)
    rev: Mapped[int | None] = mapped_column(Integer)
    msg: Mapped[str | None] = mapped_column(Text)
    classtype: Mapped[str | None] = mapped_column(String(100), index=True)
    action: Mapped[str] = mapped_column(String(20))
    protocol: Mapped[str] = mapped_column(String(30))
    app_layer: Mapped[str] = mapped_column(String(30), index=True)
    buffers: Mapped[list[Any]] = mapped_column(JSON, default=list)
    is_ioc: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    ioc_type: Mapped[str | None] = mapped_column(String(30))
    ioc_value: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str | None] = mapped_column(String(30))
    confidence: Mapped[str | None] = mapped_column(String(30))
    performance_impact: Mapped[str | None] = mapped_column(String(30))
    mitre: Mapped[list[Any]] = mapped_column(JSON, default=list)
    enabled_anywhere: Mapped[bool] = mapped_column(Boolean, default=True)
    copies: Mapped[int] = mapped_column(Integer, default=1)
    sources: Mapped[list[Any]] = mapped_column(JSON, default=list)
    n_sources: Mapped[int] = mapped_column(Integer, default=1)  # independent sources (mirrors excluded)
    loads_in: Mapped[list[Any]] = mapped_column(JSON, default=list)
    fails_in: Mapped[list[Any]] = mapped_column(JSON, default=list)
    family_id: Mapped[int] = mapped_column(Integer, index=True)
    family_size: Mapped[int] = mapped_column(Integer, default=1)
    is_family_best: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    score_parts: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    flags: Mapped[list[Any]] = mapped_column(JSON, default=list)
    junk: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    verdict: Mapped[str | None] = mapped_column(String(10), index=True)
    updated: Mapped[str | None] = mapped_column(String(20))
    redistributable: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0", index=True)  # a source allows it
    indicator_groups: Mapped[int] = mapped_column(Integer, default=1, server_default="1")  # logic groups with the same IOC
    category: Mapped[str | None] = mapped_column(String(100), index=True)  # name prefix: "ET INFO", "GPL NETBIOS", first word


# The list columns of logic_groups that search filters and facets read through logic_group_values.
VALUE_KINDS = ("buffers", "sources", "flags", "loads_in", "fails_in", "mitre")


class LogicGroupValue(Base):
    """Derived: one row per element of a logic group's list columns (VALUE_KINDS), rebuilt with logic_groups.

    Search filters (`buffer:`, `source:`, `flag:`, `dialect:`, `loads:`, `fails:`, `mitre:`) look a value up here by
    (kind, lvalue) instead of parsing every row's JSON, and the search facets count from here. `pos` is the element's
    index in the list (duplicates are kept, as json_each returns them); `lvalue` is SQLite's lower(value)."""

    __tablename__ = "logic_group_values"
    __table_args__ = (Index("ix_logic_group_values_lookup", "kind", "lvalue"), {"sqlite_with_rowid": False})
    group_id: Mapped[int] = mapped_column(Integer, primary_key=True)  # logic_groups.id
    kind: Mapped[str] = mapped_column(String(10), primary_key=True)
    pos: Mapped[int] = mapped_column(Integer, primary_key=True)
    value: Mapped[str | None] = mapped_column(Text)
    lvalue: Mapped[str | None] = mapped_column(Text)


class NearDuplicate(Base):
    """Derived: two logics whose (buffer, content) sets overlap strongly, same route, different family.
    Shown as "similar"; never merged."""

    __tablename__ = "near_duplicates"
    a: Mapped[str] = mapped_column(String(64), primary_key=True)  # logic hash
    b: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    jaccard: Mapped[float] = mapped_column(Float)


class RuleKey(Base):
    """Derived: what a (namespace, gid, sid) points to. Ambiguous keys do not link families."""

    __tablename__ = "rule_keys"
    rule_key: Mapped[str] = mapped_column(String(250), primary_key=True)
    n_versions: Mapped[int] = mapped_column(Integer)
    n_logics: Mapped[int] = mapped_column(Integer)
    n_clusters: Mapped[int] = mapped_column(Integer)
    ambiguous: Mapped[bool] = mapped_column(Boolean, index=True)


class Verdict(Base):
    """User data: triage verdict on a logic hash, a rule key or a source (overlay, never a deletion)."""

    __tablename__ = "verdicts"
    scope: Mapped[str] = mapped_column(String(10), primary_key=True)  # logic | rule | source
    key: Mapped[str] = mapped_column(String(250), primary_key=True)
    verdict: Mapped[str] = mapped_column(String(10))  # keep | review | drop
    note: Mapped[str | None] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class UpdateRun(Base):
    """One `suriharvest update`: steps, corpus counts, gate results and the report path."""

    __tablename__ = "update_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime)
    status: Mapped[str] = mapped_column(String(20), default="running")  # running | passed | failed | error
    accepted: Mapped[bool] = mapped_column(Boolean, default=False)  # a failed run made the new baseline by hand
    steps: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)  # step -> seconds / status
    counts: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    gates: Mapped[list[Any]] = mapped_column(JSON, default=list)
    changes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    report_path: Mapped[str | None] = mapped_column(Text)
    error: Mapped[str | None] = mapped_column(Text)


class Profile(Base):
    """User data: a named ruleset to build (which rules, which engine they must load in, which exclusions)."""

    __tablename__ = "profiles"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    description: Mapped[str | None] = mapped_column(Text)
    query: Mapped[str] = mapped_column(Text, default="")  # candidate rules (search syntax); "" = everything
    unit: Mapped[str] = mapped_column(String(10), default="logic")  # logic | family
    engine: Mapped[str | None] = mapped_column(String(100))  # engine of suriharvest.yaml the profile runs; failing rules are left out
    options: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)  # remap_sids, iocs_as_datasets, auto_build, ...
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Exclusion(Base):
    """User data: rules a profile must not receive. profile_id NULL = every profile.
    `keys` remembers the rule keys the exclusion matched, so a rule renamed upstream stays excluded."""

    __tablename__ = "exclusions"
    id: Mapped[int] = mapped_column(primary_key=True)
    profile_id: Mapped[int | None] = mapped_column(ForeignKey("profiles.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(
        String(20)
    )  # msg_contains | msg_exact | msg_regex | sid | rule_key | logic | category | classtype | source | query
    value: Mapped[str] = mapped_column(Text)
    reason: Mapped[str | None] = mapped_column(Text)
    author: Mapped[str | None] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    review_at: Mapped[datetime | None] = mapped_column(DateTime)  # revisit this exclusion after this date
    keys: Mapped[list[Any]] = mapped_column(JSON, default=list)
    last_matched: Mapped[int] = mapped_column(Integer, default=0)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime)


class ProfileBuild(Base):
    """A ruleset built for a profile; files in data/profiles/<name>/<build id>/."""

    __tablename__ = "profile_builds"
    id: Mapped[int] = mapped_column(primary_key=True)
    profile_id: Mapped[int] = mapped_column(ForeignKey("profiles.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    path: Mapped[str] = mapped_column(Text)
    rules: Mapped[int] = mapped_column(Integer, default=0)
    excluded: Mapped[int] = mapped_column(Integer, default=0)
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)  # counts per reason, diff with previous build
