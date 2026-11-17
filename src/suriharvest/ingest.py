"""Turn synced files into rule versions, occurrences and quarantine rows. Nothing is deleted:
a rule that disappears keeps its version; its occurrence gets present = false."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from suriharvest.config import SourceConfig, Workspace
from suriharvest.identity import compute_facts, sha256_hex
from suriharvest.models import Occurrence, Quarantine, RuleVersion, Source, utcnow
from suriharvest.parser import ParseError, parse_text
from suriharvest.sync import MAX_FILE_BYTES, SyncResult, hash_tree, looks_like_rules, path_selected

CHUNK = 500


@dataclass
class IngestStats:
    files: int = 0
    rules: int = 0
    versions_new: int = 0
    quarantined: int = 0
    removed_files: int = 0
    per_file: dict[str, int] = field(default_factory=dict)


def manifest_path(ws: Workspace, name: str) -> Path:
    return ws.cache / "manifest" / f"{name}.json"


def load_manifest(ws: Workspace, name: str) -> dict[str, str]:
    p = manifest_path(ws, name)
    return json.loads(p.read_text()) if p.exists() else {}


def save_manifest(ws: Workspace, name: str, root: Path) -> None:
    p = manifest_path(ws, name)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(hash_tree(root)), newline="\n")


def ensure_source(s: Session, src: SourceConfig) -> Source:
    row = s.scalar(select(Source).where(Source.name == src.name))
    if row is None:
        row = Source(name=src.name, type=src.type, url=src.url, sid_namespace=src.namespace)
        s.add(row)
    row.type, row.url, row.licence = src.type, src.url, src.licence
    row.priority, row.enabled, row.redistribute, row.sid_namespace = src.priority, src.enabled, src.redistribute, src.namespace
    s.flush()
    return row


def _versions_by_hash(s: Session, hashes: list[str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for i in range(0, len(hashes), CHUNK):
        chunk = hashes[i : i + CHUNK]
        out.update(dict(s.execute(select(RuleVersion.content_hash, RuleVersion.id).where(RuleVersion.content_hash.in_(chunk))).all()))
    return out


def ingest_file(s: Session, source: Source, path: str, text: str, commit: str | None, stats: IngestStats) -> None:
    parsed = parse_text(text)
    facts = []
    bad: list[tuple[int, str, str]] = list(parsed.errors)
    for rule in parsed.rules:
        try:
            facts.append((rule, compute_facts(rule)))
        except (ParseError, ValueError, RecursionError) as e:
            bad.append((rule.line_no, rule.text, f"identity: {e}"))
    # versions
    known = _versions_by_hash(s, list({f.content_hash for _, f in facts}))
    new_rows = []
    for rule, f in facts:
        if f.content_hash in known:
            continue
        known[f.content_hash] = -1
        new_rows.append({"content_hash": f.content_hash, "raw": rule.text, **facts_row(f)})
    if new_rows:
        s.bulk_insert_mappings(RuleVersion, new_rows)  # type: ignore[arg-type]
        stats.versions_new += len(new_rows)
        known.update(_versions_by_hash(s, [r["content_hash"] for r in new_rows]))
    # occurrences: key (version, ordinal); line number and enabled state are attributes
    existing = {
        (o.version_id, o.ordinal): o
        for o in s.scalars(select(Occurrence).where(Occurrence.source_id == source.id, Occurrence.path == path))
    }
    seen: Counter[int] = Counter()
    now = utcnow()
    keep: set[tuple[int, int]] = set()
    for rule, f in facts:
        vid = known[f.content_hash]
        ordinal = seen[vid]
        seen[vid] += 1
        keep.add((vid, ordinal))
        occ = existing.get((vid, ordinal))
        if occ is None:
            s.add(
                Occurrence(
                    version_id=vid,
                    source_id=source.id,
                    path=path,
                    ordinal=ordinal,
                    line_no=rule.line_no,
                    enabled=rule.enabled,
                    commit=commit,
                )
            )
        else:
            occ.line_no, occ.enabled, occ.commit, occ.present, occ.last_seen = rule.line_no, rule.enabled, commit, True, now
    for key, occ in existing.items():
        if key not in keep and occ.present:
            occ.present = False
    # quarantine: replace the present rows of this file
    s.execute(update(Quarantine).where(Quarantine.source_id == source.id, Quarantine.path == path).values(present=False))
    for line_no, raw, err in bad:
        s.add(Quarantine(source_id=source.id, path=path, line_no=line_no, content_hash=sha256_hex(raw), raw=raw[:20000], error=err))
    stats.files += 1
    stats.rules += len(facts)
    stats.quarantined += len(bad)
    stats.per_file[path] = len(facts)


def facts_row(f) -> dict:  # type: ignore[no-untyped-def]
    return {
        "logic_hash": f.logic_hash,
        "semantic_hash": f.semantic_hash,
        "alerting_hash": f.alerting_hash,
        "gid": f.gid,
        "sid": f.sid,
        "rev": f.rev,
        "msg": f.msg,
        "action": f.action,
        "protocol": f.protocol,
        "app_layer": f.app_layer,
        "classtype": f.classtype,
        "buffers": f.buffers,
        "contents": f.contents,
        "rule_metadata": f.metadata,
        "references": f.references,
        "flowbits_set": f.flowbits_set,
        "flowbits_check": f.flowbits_check,
        "files": f.files,
        "ioc_type": f.ioc_type,
        "ioc_value": f.ioc_value,
        "flags": f.flags,
        "features": f.features,
    }


def refresh_facts(s: Session) -> int:
    """Recompute stored facts from each version's raw text when identity code changed (FACTS_VERSION).
    content_hash never changes (it is the text); every other column may. Returns the number of versions updated."""
    from suriharvest.db import get_meta, set_meta
    from suriharvest.identity import FACTS_VERSION
    from suriharvest.parser import parse_rule

    if get_meta(s, "facts_version") == FACTS_VERSION:
        return 0
    n = 0
    batch: list[dict] = []
    for vid, raw in s.execute(select(RuleVersion.id, RuleVersion.raw)).all():
        try:
            row = facts_row(compute_facts(parse_rule(raw)))
        except (ParseError, ValueError):
            continue
        batch.append({"id": vid, **row})
        if len(batch) >= 2000:
            s.bulk_update_mappings(RuleVersion, batch)  # type: ignore[arg-type]
            n += len(batch)
            batch = []
    if batch:
        s.bulk_update_mappings(RuleVersion, batch)  # type: ignore[arg-type]
        n += len(batch)
    set_meta(s, "facts_version", FACTS_VERSION)
    s.commit()
    return n


def mark_removed(s: Session, source: Source, paths: set[str]) -> int:
    n = 0
    for p in paths:
        r = s.execute(update(Occurrence).where(Occurrence.source_id == source.id, Occurrence.path == p).values(present=False))
        s.execute(update(Quarantine).where(Quarantine.source_id == source.id, Quarantine.path == p).values(present=False))
        n += r.rowcount or 0
    return n


def ingest(s: Session, ws: Workspace, src: SourceConfig, source: Source, result: SyncResult) -> IngestStats:
    from suriharvest.db import get_meta, set_meta
    from suriharvest.identity import FACTS_VERSION

    stats = IngestStats()
    if get_meta(s, "facts_version") is None and s.scalar(select(RuleVersion.id).limit(1)) is None:
        set_meta(s, "facts_version", FACTS_VERSION)  # empty corpus: everything is ingested by this code
    root = result.root
    if result.full_scan:
        files = sorted(hash_tree(root))
        present = set(s.scalars(select(Occurrence.path).where(Occurrence.source_id == source.id, Occurrence.present.is_(True)).distinct()))
        gone = present - set(files)
    else:
        files = sorted(result.added | result.changed)
        gone = set(result.removed)
    for path in files:
        if not path_selected(path, src):
            continue
        p = root / path
        if not p.is_file() or p.stat().st_size > MAX_FILE_BYTES:
            continue
        data = p.read_bytes()
        if not looks_like_rules(data):
            if path in result.changed:
                gone.add(path)
            continue
        ingest_file(s, source, path, data.decode("utf-8", "replace"), result.new_commit, stats)
    stats.removed_files = len(gone)
    mark_removed(s, source, gone)
    return stats
