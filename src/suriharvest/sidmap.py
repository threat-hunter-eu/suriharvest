"""Stable sid remapping across builds.

Suricata loads one rule per gid:sid. When two different rules (different logic) use the same gid:sid, one keeps
the sid and the others need a new one. Those new sids must not move between builds: alerts, suppressions,
thresholds and build diffs are keyed by sid. So every clash decision is written to a persistent map:

    state/sid-map.tsv     logic_hash <TAB> gid <TAB> original sid <TAB> exported sid <TAB> date <TAB> rule key
                          <TAB> source [<TAB> note]   (note: reclaimed_by=<source> | owner_reclaim=<source>)

Rules (policy: once a rule has been published under a sid, it keeps that sid):
- only rules that took part in a clash are recorded: the one that kept the sid (holder) and the remapped ones. A
  rule alone on its sid needs no row, so the map stays small (hundreds of rows, not one per rule);
- a rule in the map is exported with the sid recorded there (whether it kept its original sid or got a new one),
  as long as nobody else in the same export already uses that sid. It is found by logic hash, or else by rule
  key AND supplying source: a new revision of the same publisher rule keeps the decision (and adds a row with the same sids);
- in a clash, the recorded holder (the incumbent) keeps the original sid, whatever its rank: a newcomer with the
  same gid:sid is remapped even when its source has a better priority (otherwise an upstream could renumber
  a rule that sensors, suppressions and thresholds already know by its sid);
- a clash seen for the first time: the rule that had the sid unchanged in the previous build or release
  (`previous`, read from its manifest) is the incumbent; without one, the sid goes to the best-ranked member
  (source priority, then score, then logic hash: deterministic); the rest get new sids;
- owner reclaim: when the sidallocation.org owner of a sid publishes a rule with it, the owner takes the sid even
  from a rule that already held (and published) it. The displaced rule is remapped ONCE: its row gets a fresh sid
  and the note `reclaimed_by=<owner source>`; an owner rule that had been remapped and moves back to its own sid gets
  `owner_reclaim=<owner source>`. A row with a note never changes again. These are the only row changes the
  nightly append-only check accepts (sidmap_check.py); releases list them in changes.json (`reclaimed`);
- new sids are allocated above everything the map ever handed out (never reused), from `base` up, skipping any sid
  used by an exported rule and every range allocated at sidallocation.org (sidalloc.py). The highest remapped sid
  ever handed out is kept in the header (`# floor=<sid>`), so it survives the retirement of its row;
- one row per rule, not per revision: a new revision of a recorded rule (same supplying source and rule key) whose
  old revision is no longer present takes over the old row (new logic hash, same sids, date and note), so a source
  whose clashing rules change every night does not grow the map;
- retirement (`retire`, run by `release build --previous` only): rows of rules that are in neither this release nor
  the previous one are removed. Their sids stay used (floor), a rule that comes back later is a new clash.
Row changes the nightly check accepts (sidmap_check.py): new rows, owner reclaim notes, revision take-over, and
retirement of rules absent from the release manifest.
The file is plain text so it can be committed next to published builds.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from suriharvest.sidalloc import next_unallocated

DEFAULT_BASE = 1_900_000_000  # same as config.DEFAULT_REMAP_BASE: outside every allocated range


@dataclass
class Entry:
    logic_hash: str
    gid: int
    original: int
    sid: int
    since: str
    rule_key: str = ""
    source: str = ""  # the feed that supplied the rule (canonical source), not the sid-range owner
    note: str = ""  # reclaimed_by=<owner source> / owner_reclaim=<owner source> (see the module docstring)


NOTE_PREFIXES = ("reclaimed_by=", "owner_reclaim=")
FLOOR_PREFIX = "# floor="


def header_floor(text: str) -> int:
    """The `# floor=<sid>` header value (0 when absent)."""
    for line in text.splitlines():
        if line.startswith(FLOOR_PREFIX) and line[len(FLOOR_PREFIX) :].strip().isdigit():
            return int(line[len(FLOOR_PREFIX) :].strip())
    return 0


def parse_row(line: str) -> Entry:
    f = line.rstrip("\n").split("\t")
    note = f.pop() if len(f) > 5 and f[-1].startswith(NOTE_PREFIXES) else ""
    h, gid, orig, sid, since, key, src = (f + [""] * 7)[:7]
    return Entry(h, int(gid), int(orig), int(sid), since, key, src, note)


def _source(g: Any) -> str:
    return getattr(g, "canonical_source", None) or getattr(g, "source", None) or ""


@dataclass
class Previous:
    """Who had each gid:sid unchanged in the previous build: logic hashes, and (source, rule key) pairs."""

    hashes: dict[tuple[int, int], set[str]]
    keys: dict[tuple[int, int], set[tuple[str, str]]]

    def had(self, g: Any, gid: int, sid: int) -> bool:
        if g.logic_hash in self.hashes.get((gid, sid), set()):
            return True
        key, src = getattr(g, "rule_key", None), _source(g)
        return bool(key and src) and (src, key) in self.keys.get((gid, sid), set())


def holders_from_manifest(rows: Iterable[dict[str, Any]]) -> Previous:
    """The rules exported with their sid unchanged (a build's or a release's manifest rows): the incumbents for
    clashes that are new in the next build. A rule key counts only together with the source that supplied it."""
    prev = Previous({}, {})
    for r in rows:
        if r.get("enabled") is False or r.get("exported_sid", r.get("sid")) != r.get("sid"):
            continue
        k = (int(r.get("gid") or 1), int(r["sid"]))
        if r.get("logic_hash"):
            prev.hashes.setdefault(k, set()).add(r["logic_hash"])
        if r.get("rule_key") and r.get("source"):
            prev.keys.setdefault(k, set()).add((r["source"], r["rule_key"]))
    return prev


def build_date() -> str:
    """The date written on new sid map rows: the day of SOURCE_DATE_EPOCH when it is set (reproducible builds, the
    same rule as `release build`), else the system date."""
    epoch = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
    if epoch.isdigit():
        return datetime.fromtimestamp(int(epoch), UTC).date().isoformat()
    return date.today().isoformat()


class SidMap:
    def __init__(self, path: Path | None = None, today: str | None = None) -> None:
        """`today`: the date written on new rows (default: build_date(); release builds pass --build-epoch)."""
        self.path = path
        self.today = today or build_date()
        self.entries: dict[str, Entry] = {}
        self.changed = False
        self.floor = 0  # highest remapped sid ever handed out (rows may have been retired since)
        self._present: set[str] = set()  # logic hashes of the groups of the current assign()
        if path is not None and path.exists():
            text = path.read_text(encoding="utf-8")
            self.floor = header_floor(text)
            for line in text.splitlines():
                if not line.strip() or line.startswith("#"):
                    continue
                e = parse_row(line)
                self.entries[e.logic_hash] = e
        self.floor = max([self.floor, *(e.sid for e in self.entries.values() if e.sid != e.original)])
        self.by_key: dict[tuple[str, str, int, int], Entry] = {}
        for e in sorted(self.entries.values(), key=lambda e: e.since):
            if e.rule_key and e.source:
                self.by_key[(e.source, e.rule_key, e.gid, e.original)] = e

    def save(self) -> None:
        if self.path is None or not self.changed:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.floor = max([self.floor, *(e.sid for e in self.entries.values() if e.sid != e.original)])
        lines = [
            "# suriharvest sid map: logic_hash\tgid\toriginal_sid\texported_sid\tsince\trule_key\tsource\tnote (do not edit by hand)\n"
        ]
        if self.floor:
            lines.append(f"{FLOOR_PREFIX}{self.floor}\n")
        for e in sorted(self.entries.values(), key=lambda e: (e.gid, e.original, e.sid, e.logic_hash)):
            lines.append(
                f"{e.logic_hash}\t{e.gid}\t{e.original}\t{e.sid}\t{e.since}"
                + (f"\t{e.rule_key}\t{e.source}" if e.rule_key and e.source else "")
                + (f"\t{e.note}" if e.note else "")
                + "\n"
            )
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text("".join(lines), encoding="utf-8", newline="\n")
        tmp.replace(self.path)
        self.changed = False

    def _record(self, g: Any, gid: int, original: int, sid: int, note: str = "") -> None:
        h, key, src = g.logic_hash, getattr(g, "rule_key", "") or "", _source(g)
        old = self.entries.get(h)
        prev = self.by_key.get((src, key, gid, original)) if old is None and key and src else None
        if prev is not None and prev.logic_hash not in self._present and prev.sid == sid and prev.logic_hash in self.entries:
            # a new revision of a recorded rule whose old revision is gone: it takes over the row
            del self.entries[prev.logic_hash]
            e = Entry(h, gid, original, sid, prev.since, key, src, prev.note)
            self.entries[h] = self.by_key[(src, key, gid, original)] = e
            self.changed = True
            return
        if old is None or old.sid != sid or old.gid != gid:
            e = Entry(h, gid, original, sid, self.today, key, src, note)
            self.entries[h] = e
            if key and src:
                self.by_key[(src, key, gid, original)] = e
            self.changed = True

    def lookup(self, g: Any) -> Entry | None:
        """The entry of this rule: by logic hash, else by (supplying source, rule key): a new revision of a recorded
        rule from the SAME feed. Another source with the same rule key never inherits an entry."""
        e = self.entries.get(g.logic_hash)
        if e is None and getattr(g, "rule_key", None) and _source(g):
            e = self.by_key.get((_source(g), g.rule_key, g.gid, g.sid))
        return e

    def _would_hold(self, g: Any, gid: int, sid: int) -> bool:
        """Does g hold gid:sid in the map, or would it compete for it (no row for this sid yet)?"""
        e = self.lookup(g)
        return e is None or e.gid != gid or e.original != sid or e.sid == sid

    def assign(
        self,
        groups: Iterable[Any],
        rank: Callable[[Any], tuple],
        base: int = DEFAULT_BASE,
        owner: Callable[[Any], bool] | None = None,
        previous: Previous | None = None,
    ) -> dict[str, int]:
        """groups: objects with logic_hash, gid, sid. Returns logic_hash -> exported sid for every group whose
        exported sid differs from its own sid. Records the decisions of every clash (see the module docstring).

        `owner(g)`: does g come from the publisher that sidallocation.org assigns this sid to? In a clash the owner
        always keeps (or takes back) its sid, so a source cannot squat a sid first and push the publisher into
        remapping. Without an owner in the clash, the incumbent (the rule that held the sid before) keeps it."""
        groups = list(groups)
        self._present = {g.logic_hash for g in groups}
        is_owner = owner or (lambda g: False)
        by_key: dict[tuple[int, int], list[Any]] = {}
        for g in groups:
            by_key.setdefault((g.gid, g.sid), []).append(g)
        used: set[tuple[int, int]] = set(by_key)  # (gid, sid) values exported as-is so far
        out: dict[str, int] = {}
        floor = max([base - 1, self.floor, *(e.sid for e in self.entries.values() if e.sid != e.original)])

        def allocate(gid: int) -> int:
            nonlocal floor
            floor = next_unallocated(floor + 1)
            while (gid, floor) in used:
                floor = next_unallocated(floor + 1)
            return floor

        # 1. groups with an entry keep their recorded sid (a remapped one, or the original they won before)
        taken: dict[tuple[int, int], str] = {}
        for (gid, sid), gs in sorted(by_key.items()):
            holders = []
            for g in gs:
                e = self.lookup(g)
                if e is None or e.gid != gid or e.original != sid:
                    continue
                if e.sid == sid:
                    holders.append((e.since, rank(g), g.logic_hash))
                elif (
                    len(gs) > 1
                    and is_owner(g)
                    and not any(is_owner(x) for x in gs if x is not g)
                    and any(self._would_hold(x, gid, sid) for x in gs if x is not g)
                ):
                    # the range owner takes its sid back from a squatter that holds it, or would take it (step 2).
                    # Between two rules of the owner (it ships two rules with one sid, or two sources share its
                    # namespace) the recorded decision stands: otherwise the remapped one would get a fresh sid at
                    # every build. A squatter already remapped holds nothing: the owner's rule stays where it is,
                    # also when the owner's holder of the sid is gone (its row is retired later, and
                    # moving this one back would leave two rows exporting the sid).
                    continue
                elif (gid, e.sid) not in used:
                    out[g.logic_hash] = e.sid
                    used.add((gid, e.sid))
                    if e.logic_hash != g.logic_hash:
                        self._record(g, gid, sid, e.sid)  # new revision of a remapped rule: same new sid
            if holders:  # two builds with different selections can both have recorded a holder: the oldest wins
                taken[(gid, sid)] = min(holders)[2]
        # 2. clashes: original sid to a mapped holder or the best-ranked member, new sids to the rest
        for (gid, sid), gs in sorted(by_key.items()):
            pending = [g for g in gs if g.logic_hash not in out]
            holder = taken.get((gid, sid))
            owners = [g for g in pending if is_owner(g)] if len(gs) > 1 else []
            was = {g.logic_hash for g in pending if previous is not None and previous.had(g, gid, sid)}
            displaced: set[str] = set()  # non-owner rules that held (published) the sid: the owner reclaims it
            if owners and holder not in {g.logic_hash for g in owners}:
                displaced = ({holder} if holder else set()) | {h for h in was if h not in {g.logic_hash for g in owners}}
                holder = min(owners, key=rank).logic_hash
            if holder is None and pending:
                holder = min([g for g in pending if g.logic_hash in was] or pending, key=rank).logic_hash
            clash = len(gs) > 1
            reclaimer = next((_source(g) for g in pending if g.logic_hash == holder), "") if displaced else ""
            for g in sorted(pending, key=rank):
                if g.logic_hash == holder:
                    if clash or self.lookup(g) is not None:
                        e = self.lookup(g)
                        back = e is not None and e.gid == gid and e.original == sid and e.sid != sid and is_owner(g)
                        self._record(g, gid, sid, sid, f"owner_reclaim={_source(g) or '-'}" if back else "")
                    continue
                new = allocate(gid)
                self.floor = max(self.floor, new)
                used.add((gid, new))
                out[g.logic_hash] = new
                self._record(g, gid, sid, new, f"reclaimed_by={reclaimer or '-'}" if g.logic_hash in displaced else "")
        return out

    def retire(self, keep_hashes: set[str], keep_keys: set[tuple[str, str]]) -> list[Entry]:
        """Remove the rows of rules that are not published any more: neither their logic hash nor their (supplying
        source, rule key) is in `keep_*` (every row, duplicates included, of this release's manifest and of the
        previous one). Rows with a note are never removed. Their sids stay used (floor). Returns the removed rows."""
        from suriharvest.sidmap_check import retirable  # the nightly check applies the same rule

        present = (keep_hashes, keep_keys)
        gone = [e for e in self.entries.values() if retirable(e.logic_hash, e.source, e.rule_key, e.note, present)]
        if gone:
            self.floor = max([self.floor, *(e.sid for e in self.entries.values() if e.sid != e.original)])
            for e in gone:
                del self.entries[e.logic_hash]
                if self.by_key.get((e.source, e.rule_key, e.gid, e.original)) is e:
                    del self.by_key[(e.source, e.rule_key, e.gid, e.original)]
            self.changed = True
        return gone
