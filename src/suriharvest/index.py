"""Derived index: logic groups, rule keys, families, flags, scores and full-text search.

Rebuilt from the corpus and results on every `suriharvest index`. User data (verdicts) is read, never
written here.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from collections.abc import Set as AbstractSet
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Text, cast, delete, func, insert, select, text
from sqlalchemy.orm import Session

from suriharvest.db import in_list, set_meta
from suriharvest.models import (
    VALUE_KINDS,
    LogicGroup,
    LogicGroupValue,
    NearDuplicate,
    Occurrence,
    RuleKey,
    RuleVersion,
    Source,
    ValidationResult,
    Verdict,
)

MSG_WORD = re.compile(r"[a-z0-9]+")
KEY_JACCARD = 0.3  # contents overlap that makes two versions of one sid "the same rule"


@dataclass
class V:
    """A live version with what the index needs from its occurrences."""

    id: int
    content_hash: str
    logic_hash: str
    semantic_hash: str | None
    gid: int
    sid: int
    rev: int | None
    msg: str | None
    classtype: str | None
    action: str
    protocol: str
    app_layer: str
    buffers: list[str]
    contents: list[str]
    metadata: dict[str, list[str]]
    references: list[str]
    flowbits_set: list[str]
    flowbits_check: list[str]
    files: list[str]
    ioc_type: str | None
    ioc_value: str | None
    flags: list[str]
    raw: str
    features: list[str]
    sources: dict[str, int] = field(default_factory=dict)  # source name -> priority
    namespaces: dict[str, int] = field(default_factory=dict)  # namespace -> best priority
    copies: int = 0
    enabled: bool = False
    restricted_sources: set[str] = field(default_factory=set)  # redistribute is not "yes"

    @property
    def redistributable(self) -> bool:
        """At least one source that allows redistribution carries this exact text."""
        return any(n not in self.restricted_sources for n in self.sources)

    @property
    def best_priority(self) -> int:
        return min(self.sources.values())

    @property
    def best_source(self) -> str:
        return min(self.sources.items(), key=lambda kv: (kv[1], kv[0]))[0]

    @property
    def rule_key(self) -> str:
        ns = publisher_namespace(self.msg, self.gid, self.sid) or min(self.namespaces.items(), key=lambda kv: (kv[1], kv[0]))[0]
        return f"{ns}:{self.gid}:{self.sid}"


_WORD = re.compile(r"[A-Za-z0-9]")


def category_of(msg: str | None) -> str | None:
    """Name prefix used to triage by name: "ET INFO", "ET MALWARE", "GPL NETBIOS", else the first word
    ("TGI", "Phishing/Fraud"). Emoji and dashes in front are skipped."""
    words = [w.strip("-:,[]()") for w in (msg or "").split()]
    words = [w for w in words if _WORD.search(w)]
    if not words:
        return None
    if words[0] in ("ET", "GPL") and len(words) > 1:
        return f"{words[0]} {words[1]}"[:100]
    return words[0][:100]


def publisher_namespace(msg: str | None, gid: int, sid: int) -> str | None:
    """Namespace of the publisher that owns this sid (sidallocation.org table, see sidalloc.py), if any: the same
    sid means the same rule in any file that carries it (a mirror, a fork, a bundle that copies the rules)."""
    from suriharvest.sidalloc import owner

    a = owner(gid, sid, msg)
    return a.namespace if a else None


class UnionFind:
    def __init__(self) -> None:
        self.parent: dict[Any, Any] = {}

    def find(self, x: Any) -> Any:
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: Any, b: Any) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def jaccard(a: AbstractSet[str], b: AbstractSet[str]) -> float:
    if not a and not b:
        return 1.0
    return len(a & b) / len(a | b)


def msg_words(msg: str | None) -> frozenset[str]:
    return frozenset(MSG_WORD.findall((msg or "").lower()))


def load_live(s: Session) -> dict[int, V]:
    cols = [
        RuleVersion.id,
        RuleVersion.content_hash,
        RuleVersion.logic_hash,
        RuleVersion.semantic_hash,
        RuleVersion.gid,
        RuleVersion.sid,
        RuleVersion.rev,
        RuleVersion.msg,
        RuleVersion.classtype,
        RuleVersion.action,
        RuleVersion.protocol,
        RuleVersion.app_layer,
        RuleVersion.buffers,
        RuleVersion.contents,
        RuleVersion.rule_metadata,
        RuleVersion.references,
        RuleVersion.flowbits_set,
        RuleVersion.flowbits_check,
        RuleVersion.files,
        RuleVersion.ioc_type,
        RuleVersion.ioc_value,
        RuleVersion.flags,
        RuleVersion.raw,
        RuleVersion.features,
    ]
    live_ids = select(Occurrence.version_id).join(Source, Source.id == Occurrence.source_id)
    live_ids = live_ids.where(Occurrence.present.is_(True), Source.enabled.is_(True)).distinct()
    out: dict[int, V] = {}
    for row in s.execute(select(*cols).where(in_list(RuleVersion.id, live_ids))):
        out[row[0]] = V(*row)
    q = (
        select(Occurrence.version_id, Source.name, Source.priority, Source.sid_namespace, Occurrence.enabled, Source.redistribute)
        .join(Source, Source.id == Occurrence.source_id)
        .where(Occurrence.present.is_(True), Source.enabled.is_(True))
    )
    for vid, name, prio, _ns, enabled, redistribute in s.execute(q):
        v = out.get(vid)
        if v is None:
            continue
        v.sources[name] = prio
        if redistribute != "yes":
            v.restricted_sources.add(name)
        v.copies += 1
        v.enabled = v.enabled or enabled
    # A text keeps every namespace it was ever published under: a fork still carrying an old ET revision stays
    # in the "et" namespace after ET moved on.
    q = select(Occurrence.version_id, Source.priority, Source.sid_namespace).join(Source, Source.id == Occurrence.source_id).distinct()
    for vid, prio, ns in s.execute(q):
        v = out.get(vid)
        if v is not None:
            v.namespaces[ns] = min(prio, v.namespaces.get(ns, prio))
    return out


def cluster_rule_keys(versions: dict[int, V]) -> tuple[dict[str, list[list[int]]], dict[str, int]]:
    """rule_key -> clusters of version ids that are the same rule. Edges: same logic, similar msg, or contents
    Jaccard >= KEY_JACCARD. More than one cluster -> the key is ambiguous."""
    by_key: dict[str, list[V]] = defaultdict(list)
    for v in versions.values():
        by_key[v.rule_key].append(v)
    clusters: dict[str, list[list[int]]] = {}
    n_logics: dict[str, int] = {}
    for key, vs in by_key.items():
        n_logics[key] = len({v.logic_hash for v in vs})
        if len(vs) == 1:
            clusters[key] = [[vs[0].id]]
            continue
        uf = UnionFind()
        words = {v.id: msg_words(v.msg) for v in vs}
        cont = {v.id: set(v.contents) for v in vs}
        for i, a in enumerate(vs):
            uf.find(a.id)
            for b in vs[i + 1 :]:
                if (
                    a.logic_hash == b.logic_hash
                    or (words[a.id] and jaccard(words[a.id], words[b.id]) >= 0.5)
                    or ((cont[a.id] or cont[b.id]) and jaccard(cont[a.id], cont[b.id]) >= KEY_JACCARD)
                ):
                    uf.union(a.id, b.id)
        groups: dict[int, list[int]] = defaultdict(list)
        for v in vs:
            groups[uf.find(v.id)].append(v.id)
        clusters[key] = sorted(groups.values())
    return clusters, n_logics


def _canonical(vs: list[V]) -> V:
    return min(vs, key=lambda v: (v.best_priority, not v.enabled, -(v.rev or 0), v.id))


def _updated(meta: dict[str, list[str]]) -> str | None:
    for k in ("updated_at", "created_at"):
        if meta.get(k):
            return max(meta[k]).replace("_", "-")[:10]
    return None


def _score(g: dict[str, Any], has_long_content: bool, metadata_fields: int, now: datetime) -> tuple[int, dict[str, int]]:
    """Explainable 0-100 ranking aid."""
    parts: dict[str, int] = {}
    if g["fails_in"] and not g["loads_in"]:
        parts["loads"] = 0
    elif g["fails_in"]:
        parts["loads"] = 15
    elif g["loads_in"]:
        parts["loads"] = 30
    else:
        parts["loads"] = 15  # not validated yet
    parts["sources"] = {0: 0, 1: 10, 2: 15}.get(g["n_sources"], 20)
    parts["behaviour"] = 0 if g["is_ioc"] else 10
    parts["prefilter"] = 10 if has_long_content else 0
    parts["metadata"] = round(10 * metadata_fields / 4)
    fresh = 5
    if g["updated"]:
        try:
            age = (now - datetime.fromisoformat(g["updated"]).replace(tzinfo=UTC)).days
            fresh = 10 if age < 730 else 5 if age < 1825 else 0
        except ValueError:
            pass
    parts["freshness"] = fresh
    parts["enabled_upstream"] = 10 if g["enabled_anywhere"] else 0
    if "deprecated" in g["flags"]:
        parts["deprecated"] = -15
    elif "deleted" in g["flags"]:
        parts["deleted"] = -15
    elif "retired" in g["flags"]:
        parts["retired"] = -10
    if g["junk"]:
        parts["junk"] = -20
    return max(0, min(100, sum(parts.values()))), parts


def latest_validation(s: Session) -> dict[str, dict[str, tuple[str, str | None]]]:
    """content_hash -> engine -> (status, category) from the newest result per (hash, engine)."""
    out: dict[str, dict[str, tuple[str, str | None, Any]]] = defaultdict(dict)
    for ch, eng, status, cat, at in s.execute(
        select(
            ValidationResult.content_hash,
            ValidationResult.engine,
            ValidationResult.status,
            ValidationResult.category,
            ValidationResult.checked_at,
        )
    ):
        prev = out[ch].get(eng)
        if prev is None or at > prev[2]:
            out[ch][eng] = (status, cat, at)
    return {ch: {e: (st, c) for e, (st, c, _) in d.items()} for ch, d in out.items()}


@dataclass
class IndexReport:
    live_versions: int = 0
    logic_groups: int = 0
    semantic_groups: int = 0
    unique_indicators: int = 0
    near_duplicates: int = 0
    families: int = 0
    ioc_groups: int = 0
    behaviour_groups: int = 0
    rule_keys: int = 0
    ambiguous_keys: int = 0
    junk: int = 0
    missing_setters: int = 0

    def as_dict(self) -> dict[str, int]:
        return dict(self.__dict__)


def rebuild(s: Session) -> IndexReport:
    now = datetime.now(UTC)
    versions = load_live(s)
    rep = IndexReport(live_versions=len(versions))
    # global bit setters, for dependency flags
    set_bits: set[str] = set()
    for v in versions.values():
        set_bits.update(v.flowbits_set)
    validation = latest_validation(s)
    from suriharvest.majors import load_views, view_for

    # per-major copies (majors.py): an engine's result is the one of its major's canonical version
    views = load_views(s)
    engine_views = {}
    if views:
        # SQLite: the bare column of a max() aggregate comes from the row holding the max (the newest result)
        q = select(ValidationResult.engine, ValidationResult.engine_version, func.max(ValidationResult.checked_at)).group_by(
            ValidationResult.engine
        )
        engine_views = {eng: view_for(views, ver) for eng, ver, _ in s.execute(q)}

    def results(lh: str, c: V) -> dict[str, tuple[str, str | None]]:
        if not engine_views:
            return validation.get(c.content_hash, {})
        out = {}
        for eng, view in engine_views.items():
            p = view.canonical.get(lh) if view is not None else None
            if p is None or p.version_id not in versions:
                continue  # this engine's major does not see the rule: neither loads nor fails there
            r = validation.get(versions[p.version_id].content_hash, {}).get(eng)
            if r is not None:
                out[eng] = r
        return out

    verdicts = {(scope, key): verdict for scope, key, verdict in s.execute(select(Verdict.scope, Verdict.key, Verdict.verdict))}

    # rule keys
    clusters, n_logics = cluster_rule_keys(versions)
    key_rows = []
    for key, cl in clusters.items():
        n_versions = sum(len(c) for c in cl)
        key_rows.append(
            {"rule_key": key, "n_versions": n_versions, "n_logics": n_logics[key], "n_clusters": len(cl), "ambiguous": len(cl) > 1}
        )
    rep.rule_keys = len(key_rows)
    rep.ambiguous_keys = sum(r["ambiguous"] for r in key_rows)

    # logic groups
    by_logic: dict[str, list[V]] = defaultdict(list)
    for v in versions.values():
        by_logic[v.logic_hash].append(v)
    rows: list[dict[str, Any]] = []
    fts: list[dict[str, Any]] = []
    for gid_, (lh, vs) in enumerate(sorted(by_logic.items()), start=1):
        c = _canonical(vs)
        prio_of: dict[str, int] = {}
        for v in vs:
            prio_of.update(v.sources)
        # independent sources: a source counts unless every version it carries is also carried by a better source
        independent = set()
        for v in vs:
            best = min(v.sources.items(), key=lambda kv: (kv[1], kv[0]))[0]
            independent.add(best)
        val = results(lh, c)
        loads_in = sorted(e for e, (st, _) in val.items() if st == "ok")
        # A missing dataset/lua file is a packaging problem, not a broken rule: flagged needs_files, not failed.
        fails_in = sorted(e for e, (st, cat) in val.items() if st != "ok" and cat != "missing_file")
        flags = sorted({f for v in vs for f in v.flags} & {"foreign_syntax"} | set(c.flags))
        # does_not_load: no engine loads it and none was only missing a file (that engine might load it with the file)
        failed_cats = [cat for st, cat in val.values() if st != "ok"]
        if "unknown_keyword" in failed_cats and "missing_file" not in failed_cats and not loads_in:
            flags.append("does_not_load")
        if any(b not in set_bits for b in c.flowbits_check if not b.endswith(".noalert")):
            flags.append("missing_setter")
            rep.missing_setters += 1
        if c.files:
            flags.append("needs_files")
        if not any(len(x.split(":", 1)[1]) >= 4 for x in c.contents) and not c.ioc_type:
            flags.append("no_prefilter_content")
        flags = sorted(set(flags))
        # Junk = not Suricata at all. A rule that fails only in older engines is not junk (it may need 8.0).
        junk = "foreign_syntax" in flags or "dialect:snort" in flags
        meta = c.metadata
        mitre = sorted({x for k in ("mitre_technique_id", "mitre_tactic_id") for x in meta.get(k, [])})
        g: dict[str, Any] = {
            "id": gid_,
            "indicator_groups": 1,
            "category": category_of(c.msg),
            "logic_hash": lh,
            "semantic_hash": c.semantic_hash,
            "canonical_version_id": c.id,
            "canonical_source": c.best_source,
            "redistributable": any(v.redistributable for v in vs),
            "rule_key": c.rule_key,
            "gid": c.gid,
            "sid": c.sid,
            "rev": c.rev,
            "msg": c.msg,
            "classtype": c.classtype,
            "action": c.action,
            "protocol": c.protocol,
            "app_layer": c.app_layer,
            "buffers": c.buffers,
            "is_ioc": c.ioc_type is not None,
            "ioc_type": c.ioc_type,
            "ioc_value": c.ioc_value,
            "severity": (meta.get("signature_severity") or [None])[0],
            "confidence": (meta.get("confidence") or [None])[0],
            "performance_impact": (meta.get("performance_impact") or [None])[0],
            "mitre": mitre,
            "enabled_anywhere": any(v.enabled for v in vs),
            "copies": sum(v.copies for v in vs),
            "sources": sorted(prio_of, key=lambda n: (prio_of[n], n)),
            "n_sources": len(independent),
            "loads_in": loads_in,
            "fails_in": fails_in,
            "flags": flags,
            "junk": junk,
            "updated": _updated(meta),
            "family_id": gid_,
            "family_size": 1,
            "is_family_best": True,
        }
        md_fields = sum(bool(x) for x in (c.msg, c.classtype, c.references, c.metadata))
        g["score"], g["score_parts"] = _score(g, "no_prefilter_content" not in flags, md_fields, now)
        rows.append(g)
        fts.append(
            {
                "rowid": gid_,
                "msg": c.msg or "",
                "contents": " ".join(x.split(":", 1)[1] for x in c.contents) + " " + (c.ioc_value or ""),
                "metadata": " ".join(f"{k} {' '.join(v)}" for k, v in meta.items()) + f" {c.classtype or ''} {c.sid}",
                "refs": " ".join(c.references),
                "raw": c.raw,
            }
        )
    rep.logic_groups = len(rows)
    rep.semantic_groups = len({r["semantic_hash"] or r["logic_hash"] for r in rows})
    rep.ioc_groups = sum(r["is_ioc"] for r in rows)
    rep.behaviour_groups = rep.logic_groups - rep.ioc_groups
    rep.junk = sum(r["junk"] for r in rows)

    # families: trusted key clusters + semantic hash, bounded by app-layer route
    gid_of_logic = {r["logic_hash"]: r["id"] for r in rows}
    route = {r["id"]: r["app_layer"] for r in rows}
    uf = UnionFind()
    for r in rows:
        uf.find(r["id"])
    # every cluster of a rule key links its logics; an ambiguous key has several clusters that stay apart
    for cl in clusters.values():
        for c in cl:
            ids = sorted({gid_of_logic[versions[vid].logic_hash] for vid in c})
            for a in ids[1:]:
                if route[a] == route[ids[0]]:
                    uf.union(ids[0], a)
    # ET renumbering: metadata former_sid links the new rule to the old sid in the same namespace
    gid_of_key: dict[str, list[int]] = defaultdict(list)
    for r in rows:
        gid_of_key[r["rule_key"]].append(r["id"])
    for r in rows:
        v = versions[r["canonical_version_id"]]
        ns = r["rule_key"].split(":")[0]
        for old in v.metadata.get("former_sid", []):
            for other in gid_of_key.get(f"{ns}:{r['gid']}:{old.strip()}", []):
                if route[other] == route[r["id"]]:
                    uf.union(r["id"], other)
    # Same indicator on the same route (ET and another feed both flag evil.example in dns.query): one family,
    # whatever header, bsize or flow each publisher wrote around it.
    by_ioc: dict[tuple[str, str], list[int]] = defaultdict(list)
    for r in rows:
        if r["is_ioc"] and r["ioc_value"]:
            by_ioc[(r["ioc_type"], r["ioc_value"])].append(r["id"])
    for ids in by_ioc.values():
        for a in ids:
            if a != ids[0] and route[a] == route[ids[0]]:
                uf.union(ids[0], a)
            rows[a - 1]["indicator_groups"] = len(ids)
    rep.unique_indicators = len(by_ioc)
    by_sem: dict[str, list[int]] = defaultdict(list)
    for r in rows:
        if r["semantic_hash"]:
            by_sem[r["semantic_hash"]].append(r["id"])
    for ids in by_sem.values():
        for a in ids[1:]:
            uf.union(ids[0], a)
    fam: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        r["family_id"] = uf.find(r["id"])
        fam[r["family_id"]].append(r)
    for members in fam.values():
        best = max(members, key=lambda r: (r["score"], -r["id"]))
        for r in members:
            r["family_size"] = len(members)
            r["is_family_best"] = r is best
    rep.families = len(fam)
    near = near_duplicates(rows, {r["id"]: set(versions[r["canonical_version_id"]].features) for r in rows})
    rep.near_duplicates = len(near)

    # verdicts: logic > rule key > source
    for r in rows:
        r["verdict"] = verdicts.get(("logic", r["logic_hash"])) or verdicts.get(("rule", r["rule_key"]))
        if r["verdict"] is None:
            src_verdicts = [verdicts.get(("source", n)) for n in r["sources"]]
            if src_verdicts and all(v == "drop" for v in src_verdicts):
                r["verdict"] = "drop"

    s.execute(delete(LogicGroup))
    s.execute(delete(LogicGroupValue))
    s.execute(delete(RuleKey))
    s.execute(delete(NearDuplicate))
    for i in range(0, len(near), 5000):
        s.execute(insert(NearDuplicate), near[i : i + 5000])
    s.execute(text("DELETE FROM rules_fts"))
    for i in range(0, len(rows), 2000):
        s.execute(insert(LogicGroup), rows[i : i + 2000])
        s.execute(
            text(
                "INSERT INTO rules_fts(rowid, msg, contents, metadata, refs, raw) VALUES (:rowid, :msg, :contents, :metadata, :refs, :raw)"
            ),
            fts[i : i + 2000],
        )
    for i in range(0, len(key_rows), 2000):
        s.execute(insert(RuleKey), key_rows[i : i + 2000])
    fill_values(s)
    import json

    set_meta(s, "index_report", json.dumps(rep.as_dict()))
    set_meta(s, "indexed_at", now.isoformat(timespec="seconds"))
    s.commit()
    return rep


def fill_values(s: Session) -> None:
    """logic_group_values from logic_groups' list columns, element by element as json_each reads them (search
    filters and facets read this table; the lowercase copy is SQLite's lower(), as the filters compare)."""
    for kind in VALUE_KINDS:  # kind is a constant column name
        s.execute(
            text(
                "INSERT INTO logic_group_values(group_id, kind, pos, value, lvalue) "  # noqa: S608
                f"SELECT g.id, '{kind}', j.key, j.value, lower(j.value) FROM logic_groups g, json_each(g.{kind}) j"
            )
        )


def effective_verdict(verdicts: dict[tuple[str, str], str], logic_hash: str, rule_key: str, sources: list[str]) -> str | None:
    v = verdicts.get(("logic", logic_hash)) or verdicts.get(("rule", rule_key))
    if v is None and sources and all(verdicts.get(("source", n)) == "drop" for n in sources):
        v = "drop"
    return v


NEAR_JACCARD = 0.6
NEAR_MAX_DF = 300  # contents shared by more groups than this are too common to suggest similarity
NEAR_PER_GROUP = 10


def _distinctive(feature: str) -> bool:
    """A lone feature is enough to call two rules similar only if it is specific: 8+ content bytes or a pcre."""
    from suriharvest.identity import decode_content

    _buf, kind, value = feature.split(":", 2) if feature.count(":") >= 2 else ("", "", feature)
    if kind == "c":
        try:
            return len(decode_content(value.lstrip("!"))[0]) >= 8
        except ValueError:
            return False
    return kind == "pcre" and len(value) >= 12


def near_duplicates(rows: list[dict[str, Any]], contents: dict[int, set[str]] | None = None) -> list[dict[str, Any]]:
    """Pairs of behaviour logics on the same route, in different families, whose feature sets (distinctive
    contents and pcres per buffer, identity.features) have Jaccard >= NEAR_JACCARD. Single-feature rules need a
    feature of 12+ characters. Candidates come from an inverted
    index over contents, skipping very common ones, so the cost stays near linear."""
    sets = contents if contents is not None else {r["id"]: set(r.get("_contents", [])) for r in rows}
    by_id = {r["id"]: r for r in rows}
    postings: dict[str, list[int]] = defaultdict(list)
    for gid, cs in sets.items():
        if by_id[gid]["is_ioc"]:
            continue
        for c in cs:
            postings[c].append(gid)
    out: list[dict[str, Any]] = []
    for gid, cs in sets.items():
        r = by_id[gid]
        if r["is_ioc"] or not cs or (len(cs) == 1 and not _distinctive(next(iter(cs)))):
            continue
        shared: dict[int, int] = defaultdict(int)
        for c in cs:
            ids = postings.get(c, [])
            if len(ids) > NEAR_MAX_DF:
                continue
            for o in ids:
                if o > gid:
                    shared[o] += 1
        best = []
        for o, n in shared.items():
            other = by_id[o]
            if other["family_id"] == r["family_id"] or other["app_layer"] != r["app_layer"]:
                continue
            j = n / len(cs | sets[o])
            if j >= NEAR_JACCARD:
                best.append((j, o))
        for j, o in sorted(best, reverse=True)[:NEAR_PER_GROUP]:
            out.append({"a": r["logic_hash"], "b": by_id[o]["logic_hash"], "jaccard": round(j, 3)})
    return out


def apply_verdict_for(s: Session, scope: str, key: str) -> int:
    """Re-materialise the effective verdict only on the groups a verdict change can touch (fast, for the web)."""
    if scope == "logic":
        cond = LogicGroup.logic_hash == key
    elif scope == "rule":
        cond = LogicGroup.rule_key == key
    else:
        # the JSON list as text contains the quoted name (instr: no LIKE wildcards, no JSON-contains deprecation)
        cond = func.instr(cast(LogicGroup.sources, Text), json.dumps(key)) > 0
    groups = list(s.scalars(select(LogicGroup).where(cond)))
    if not groups:
        return 0
    verdicts = {(sc, k): v for sc, k, v in s.execute(select(Verdict.scope, Verdict.key, Verdict.verdict))}
    for g in groups:
        g.verdict = effective_verdict(verdicts, g.logic_hash, g.rule_key, g.sources)
    s.commit()
    return len(groups)


def apply_verdicts(s: Session) -> None:
    """Re-materialise effective verdicts on logic_groups after a verdict change (no full rebuild)."""
    verdicts = {(scope, key): verdict for scope, key, verdict in s.execute(select(Verdict.scope, Verdict.key, Verdict.verdict))}
    for g in s.scalars(select(LogicGroup)):
        v = verdicts.get(("logic", g.logic_hash)) or verdicts.get(("rule", g.rule_key))
        if v is None and g.sources and all(verdicts.get(("source", n)) == "drop" for n in g.sources):
            v = "drop"
        g.verdict = v
    s.commit()
