"""Check that a new sid map is a valid successor of the old one (the nightly `state` job runs this file directly,
standard library only: `python3 -I sidmap_check.py OLD NEW [--manifest M --previous-manifest P --rules FILE...]`).
SidMap.retire imports `retirable` from here: the build and the check share one retirement rule.

A row keeps its sids for as long as its rule is published. The transitions allowed (see sidmap.py):
- new rows. A new remapped sid is above the old map's floor (`# floor=`, the highest remapped sid ever handed out),
  unless the same rule (source, rule key) already exports it; the floor never goes down;
- revision take-over: a row may change its logic hash only (same gid, sids, date, rule key, source and note), when
  the old hash is gone from the new map;
- retirement: a row without a note may disappear when its rule is in neither the new release manifest nor the
  previous published release's manifest (by logic hash or by source + rule key; rows left out as duplicates count
  as present). Without both manifests no row may disappear. With `--rules`, every gid:sid in the published rules
  files must be a published row of the new manifest (the manifest cannot hide a published rule);
- owner reclaim:
- a row that held its original sid (exported == original) and has no note may move to a fresh sid with the note
  `reclaimed_by=<source>`, when the new map has a row of <source> exporting that same gid:sid unchanged;
- a row of an owner that had been remapped (exported != original, no note) may move back to its original sid with
  the note `owner_reclaim=<its own source>`.
A fresh sid is one no row of the old map exports for that gid, outside the original sid. Rows with a note are final.
Rows that share an exported gid:sid must be one rule (one (source, rule key), or one logic hash).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROW = re.compile(
    r"^[0-9a-f]{16,64}\t\d+\t\d+\t\d+\t\d{4}-\d{2}-\d{2}(\t[^\t\s]+:\d+:\d+\t[^\t\s]+)?(\t(reclaimed_by|owner_reclaim)=[^\t\s]+)?$"
)
MAX_BYTES = 2 * 1024 * 1024
FLOOR_PREFIX = "# floor="


def floor_of(text: str) -> int:
    """Highest remapped sid the map ever handed out: its `# floor=` header, or its rows."""
    out = 0
    for ln in text.splitlines():
        if ln.startswith(FLOOR_PREFIX) and ln[len(FLOOR_PREFIX) :].strip().isdigit():
            out = max(out, int(ln[len(FLOOR_PREFIX) :].strip()))
        elif ln and not ln.startswith("#"):
            f = _fields(ln)
            if f["sid"].isdigit() and f["orig"].isdigit() and f["sid"] != f["orig"]:
                out = max(out, int(f["sid"]))
    return out


def published(manifest_text: str) -> tuple[set[str], set[tuple[str, str]]]:
    """Logic hashes and (source, rule key) pairs a release manifest names: published rows AND rows left out as
    duplicates (their rule is still out there under another gid:sid; its row must stay)."""
    import json

    hashes, keys = set(), set()
    for ln in manifest_text.splitlines():
        if not ln.strip():
            continue
        r = json.loads(ln)
        if r.get("logic_hash"):
            hashes.add(r["logic_hash"])
        if r.get("source") and r.get("rule_key"):
            keys.add((r["source"], r["rule_key"]))
    return hashes, keys


def retirable(logic_hash: str, source: str, key: str, note: str, present: tuple[set[str], set[tuple[str, str]]]) -> bool:
    """May this sid map row be retired? Never a row with a note (an owner reclaim is final); otherwise only when
    neither its logic hash nor its (source, rule key) is in `present` (the union of the new and the previous
    release manifests, see `published`)."""
    hashes, keys = present
    return not note and logic_hash not in hashes and not (key and (source, key) in keys)


def _ruleopts():  # type: ignore[no-untyped-def]
    """ruleopts.py (the option splitter parser.py uses): from the package, or next to this file when it runs as a
    standalone script (`python3 -I sidmap_check.py`, the package not installed)."""
    try:
        from suriharvest import ruleopts

        return ruleopts
    except ImportError:
        import importlib.util

        spec = importlib.util.spec_from_file_location("_suriharvest_ruleopts", Path(__file__).with_name("ruleopts.py"))
        mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        return mod


def rules_gid_sids(rules_texts: list[str]) -> tuple[set[tuple[int, int]], list[str]]:
    """gid:sid of every rule line in the published files, enabled or commented out, read with the parser's own
    option splitter; plus the rule lines whose gid/sid cannot be read (several sids, no numeric sid ...)."""
    ro = _ruleopts()
    found: set[tuple[int, int]] = set()
    bad: list[str] = []
    for text in rules_texts:
        for ln in text.split("\n"):
            if not ro.is_rule_line(ln):
                continue
            try:
                found.add(ro.gid_sid(ln))
            except ro.OptionError:
                bad.append(ln.strip()[:80])
    return found, bad


def _manifest_rows(manifest_text: str) -> list[dict]:
    import json

    return [json.loads(ln) for ln in manifest_text.splitlines() if ln.strip()]


def unlisted_rules(manifest_text: str, rules_texts: list[str]) -> list[str]:
    """gid:sid of rules in the published files (enabled or commented out) that the manifest does not publish, and
    rule lines whose gid/sid cannot be read."""
    listed = {
        (int(r.get("gid") or 1), int(r["exported_sid"]))
        for r in _manifest_rows(manifest_text)
        if not r.get("excluded_reason") and r.get("exported_sid") is not None
    }
    found, bad = rules_gid_sids(rules_texts)
    return [f"{g}:{s}" for g, s in sorted(found - listed)] + [f"unreadable: {x}" for x in bad]


def _rows(text: str) -> list[str]:
    return [ln for ln in text.splitlines() if ln and not ln.startswith("#")]


def _fields(ln: str) -> dict[str, str]:
    f = ln.split("\t")
    note = f.pop() if len(f) > 5 and f[-1].startswith(("reclaimed_by=", "owner_reclaim=")) else ""
    f += [""] * (7 - len(f))
    return {"hash": f[0], "gid": f[1], "orig": f[2], "sid": f[3], "since": f[4], "key": f[5], "source": f[6], "note": note}


def _reclaimer_holds(row: dict[str, str], holders: set[str]) -> bool:
    """The source named in reclaimed_by= exports the original gid:sid unchanged in the new map (a holder row
    written without a source column, i.e. without a rule key, cannot be matched by name: any holder then counts)."""
    who = row["note"].split("=", 1)[1]
    return bool(holders) and (who in holders - {row["source"]} or "" in holders)


def check(
    old_text: str,
    new_text: str,
    manifest_text: str | None = None,
    previous_manifest_text: str | None = None,
    rules_texts: list[str] | None = None,
) -> list[str]:
    """Problems (empty when `new_text` is a valid successor of `old_text`). `manifest_text` (the new release's
    manifest, JSON lines) and `previous_manifest_text` (the previous published release's): both are needed for a
    row to be retired. `rules_texts`: the published rules files, checked against `manifest_text`."""
    errors: list[str] = []
    if len(new_text.encode()) > MAX_BYTES:
        errors.append(f"sid map is {len(new_text.encode())} bytes: it should hold clash rows only")
    old, new = _rows(old_text), _rows(new_text)
    bad = [ln for ln in new if not ROW.match(ln)]
    if bad:
        return [*errors, f"malformed rows: {bad[:5]}"]
    o = {x["hash"]: x for x in map(_fields, old)}
    n = {x["hash"]: x for x in map(_fields, new)}
    old_floor, new_floor = floor_of(old_text), floor_of(new_text)
    if new_floor < old_floor:
        errors.append(f"sid map floor went down: {old_floor} -> {new_floor} (remapped sids must never be handed out twice)")
    # revision take-over: a lost row whose rule continues under a new logic hash, everything else identical
    same_rule = ("gid", "orig", "sid", "since", "key", "source", "note")
    fresh = {h: x for h, x in n.items() if h not in o}
    successors: dict[tuple[str, ...], list[str]] = {}
    for h, x in fresh.items():
        if x["key"]:
            successors.setdefault(tuple(x[k] for k in same_rule), []).append(h)
    taken_over: set[str] = set()
    lost = []
    for h in [h for h in o if h not in n]:
        a = o[h]
        cands = successors.get(tuple(a[k] for k in same_rule), []) if a["key"] else []
        if cands:
            taken_over.add(cands.pop())
        else:
            lost.append(h)
    in_files: set[tuple[int, int]] = set()
    if rules_texts is not None and manifest_text is not None:
        hidden = unlisted_rules(manifest_text, rules_texts)
        if hidden:
            errors.append(f"published rules missing from the manifest: {hidden[:5]}")
        in_files = rules_gid_sids(rules_texts)[0]
        # each published gid:sid that the map exports belongs to a rule the manifest publishes (by logic hash or by
        # source + rule key): a row cannot claim a published sid for a rule the release does not carry
        pub = {r.get("logic_hash") for r in _manifest_rows(manifest_text) if not r.get("excluded_reason")}
        pub_keys = {(r.get("source"), r.get("rule_key")) for r in _manifest_rows(manifest_text) if not r.get("excluded_reason")}
        foreign = [
            h
            for h, x in n.items()
            if (int(x["gid"]), int(x["sid"])) in in_files and h not in pub and not (x["key"] and (x["source"], x["key"]) in pub_keys)
        ]
        if foreign:
            errors.append(f"rows exporting a published gid:sid for a rule the manifest does not publish: {foreign[:5]}")
    if lost:
        if manifest_text is None or previous_manifest_text is None:
            errors.append(f"sid map rows disappeared (retirement needs the new and the previous release manifest): {lost[:5]}")
        else:
            a, b = published(manifest_text), published(previous_manifest_text)
            present = (a[0] | b[0], a[1] | b[1])
            live = [
                h
                for h in lost
                if not retirable(h, o[h]["source"], o[h]["key"], o[h]["note"], present)
                or (int(o[h]["gid"]), int(o[h]["sid"])) in in_files  # its sid is still published
            ]
            if live:
                errors.append(f"sid map retired rows that may not go (a noted row, or a rule in either manifest): {live[:5]}")
    old_keys = {(x["gid"], x["sid"], x["source"], x["key"]) for x in o.values() if x["key"]}
    jumped = [
        h
        for h, x in fresh.items()
        if h not in taken_over
        and x["sid"] != x["orig"]
        and int(x["sid"]) <= old_floor
        and not (x["key"] and (x["gid"], x["sid"], x["source"], x["key"]) in old_keys)
    ]
    if jumped:
        errors.append(f"new remapped sids at or below the floor {old_floor} (handed out before): {jumped[:5]}")
    old_exported = {(x["gid"], x["sid"]) for x in o.values()}
    kept_by = {}  # (gid, sid) exported unchanged in the new map -> sources
    for x in n.values():
        if x["sid"] == x["orig"]:
            kept_by.setdefault((x["gid"], x["sid"]), set()).add(x["source"])
    moved = []
    for h, a in o.items():
        b = n.get(h)
        if b is None or b == a:
            continue
        same = all(a[k] == b[k] for k in ("gid", "orig", "key", "source"))
        reclaimed = (
            same
            and not a["note"]
            and a["sid"] == a["orig"]
            and b["sid"] != b["orig"]
            and (b["gid"], b["sid"]) not in old_exported
            and int(b["sid"]) > old_floor
            and b["note"].startswith("reclaimed_by=")
            and _reclaimer_holds(b, kept_by.get((b["gid"], b["orig"]), set()))
        )
        back = (
            same
            and not a["note"]
            and a["sid"] != a["orig"]
            and b["sid"] == b["orig"]
            and b["note"] == f"owner_reclaim={b['source']}"
            and b["source"] != ""
        )
        if not (reclaimed or back):
            moved.append(h)
    if moved:
        errors.append(f"sid map is append-only (only an owner reclaim may move a row): changed {moved[:5]}")
    owners: dict[tuple[str, str], set] = {}
    for x in n.values():
        owners.setdefault((x["gid"], x["sid"]), set()).add((x["source"], x["key"]) if x["key"] else x["hash"])
    shared = [k for k, v in owners.items() if len(v) > 1]
    if shared:
        errors.append(f"different rules share an exported gid:sid: {shared[:5]}")
    return errors


def reclaims(old_text: str, new_text: str) -> list[dict[str, str]]:
    """The rows an owner reclaim moved (for logs and release notes)."""
    o = {x["hash"]: x for x in map(_fields, _rows(old_text))}
    out = []
    for x in map(_fields, _rows(new_text)):
        a = o.get(x["hash"])
        if a is not None and a["sid"] != x["sid"] and x["note"]:
            out.append({"logic_hash": x["hash"], "gid": x["gid"], "from": a["sid"], "to": x["sid"], "note": x["note"]})
    return out


def _read_text(p: str | None) -> str | None:
    if not p:
        return None
    import gzip

    raw = Path(p).read_bytes()
    return (gzip.decompress(raw) if raw[:2] == b"\x1f\x8b" else raw).decode("utf-8")


def main(argv: list[str]) -> int:
    import argparse

    ap = argparse.ArgumentParser(prog="sidmap_check.py")
    ap.add_argument("old")
    ap.add_argument("new")
    ap.add_argument("--manifest", help="the new release's manifest.jsonl(.gz)")
    ap.add_argument("--previous-manifest", help="the previous PUBLISHED release's manifest (trusted copy)")
    ap.add_argument("--rules", nargs="*", default=None, help="published .rules files, checked against --manifest")
    try:
        a = ap.parse_args(argv[1:])
    except SystemExit:
        return 2
    old_p, new_p = Path(a.old), Path(a.new)
    old_text = old_p.read_text(encoding="utf-8") if old_p.exists() else ""
    new_text = new_p.read_text(encoding="utf-8")
    rules = [Path(f).read_text(encoding="utf-8", errors="replace") for f in a.rules] if a.rules is not None else None
    errors = check(old_text, new_text, _read_text(a.manifest), _read_text(a.previous_manifest), rules)
    for e in errors:
        print(f"::error::{e}")
    if errors:
        return 1
    for r in reclaims(old_text, new_text):
        print(f"owner reclaim: {r['gid']}:{r['from']} -> {r['to']} ({r['note']}, {r['logic_hash'][:16]})")
    print(f"sid map ok: {len(_rows(old_text))} -> {len(_rows(new_text))} rows")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
