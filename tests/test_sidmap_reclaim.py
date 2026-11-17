"""Owner reclaim: the sid map stays append-only except for the one transition an owner reclaim makes."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from suriharvest import sidmap_check
from suriharvest.release import _changes, _notes
from suriharvest.sidmap import SidMap

SID = 2000001


def g(h: str, prio: int, src: str) -> SimpleNamespace:
    return SimpleNamespace(logic_hash=h * 8, gid=1, sid=SID, prio=prio, canonical_source=src, rule_key=f"{src}:1:{SID}")


def rank(x):
    return (x.prio, x.logic_hash)


def is_et(x):
    return x.canonical_source == "et"


def step(path: Path, groups, owner=is_et) -> tuple[str, str, dict[str, int]]:
    before = path.read_text() if path.exists() else ""
    m = SidMap(path)
    out = m.assign(groups, rank, owner=owner)
    m.save()
    return before, path.read_text() if path.exists() else "", out


def test_owner_reclaims_a_published_sid_and_the_check_accepts_exactly_that(tmp_path: Path):
    path = tmp_path / "sid-map.tsv"
    squat, fork, et = g("aa", 5, "squatter"), g("cc", 50, "fork"), g("bb", 10, "et")
    _, first, out = step(path, [squat, fork])  # no owner: the squatter wins and is published with 2000001
    assert squat.logic_hash not in out and fork.logic_hash in out
    assert sidmap_check.check("", first) == []
    old, new, out = step(path, [squat, fork, et])  # the owner publishes its rule: it takes the sid back
    assert et.logic_hash not in out and squat.logic_hash in out
    row = next(x for x in new.splitlines() if x.startswith(squat.logic_hash))
    assert row.endswith("\treclaimed_by=et") and f"\t{SID}\t{out[squat.logic_hash]}\t" in row
    assert sidmap_check.check(old, new) == []
    assert [r["note"] for r in sidmap_check.reclaims(old, new)] == ["reclaimed_by=et"]
    # remapped once: the next builds keep it where it is, even without the owner
    old2, new2, out2 = step(path, [squat, fork, et])
    assert old2 == new2 and out2 == out
    _, _, out3 = step(path, [squat, fork])
    assert out3[squat.logic_hash] == out[squat.logic_hash]


def test_check_refuses_other_moves(tmp_path: Path):
    path = tmp_path / "sid-map.tsv"
    squat, fork, et = g("aa", 5, "squatter"), g("cc", 50, "fork"), g("bb", 10, "et")
    _, first, _ = step(path, [squat, fork])
    old, new, _ = step(path, [squat, fork, et])
    srow = next(x for x in new.splitlines() if x.startswith(squat.logic_hash))
    # a move without the note
    plain = new.replace(srow, srow.rsplit("\t", 1)[0])
    assert any("append-only" in e for e in sidmap_check.check(old, plain))
    # a reclaim naming a source that does not hold the sid
    assert any("append-only" in e for e in sidmap_check.check(old, new.replace("reclaimed_by=et", "reclaimed_by=fork")))
    # without the owner row holding the original sid
    erow = next(x for x in new.splitlines() if x.startswith(et.logic_hash))
    assert sidmap_check.check(old, new.replace(erow + "\n", ""))
    # a lost row
    assert any("disappeared" in e for e in sidmap_check.check(old, new.replace(srow + "\n", "")))
    # a reclaimed row is final: it never moves again
    moved = new.replace(srow, srow.replace(srow.split("\t")[3], str(int(srow.split("\t")[3]) + 7)))
    assert any("append-only" in e for e in sidmap_check.check(new, moved))
    # a remapped row moved back without being the owner
    frow = next(x for x in first.splitlines() if x.startswith(fork.logic_hash))
    f = frow.split("\t")
    back = first.replace(frow, "\t".join([*f[:3], f[2], *f[4:], "owner_reclaim=squatter"]))
    assert sidmap_check.check(first, back)


def test_owner_moves_back_from_an_old_remap(tmp_path: Path):
    path = tmp_path / "sid-map.tsv"
    squat, et = g("aa", 5, "squatter"), g("bb", 10, "et")
    _, _, out = step(path, [squat, et], owner=lambda x: False)  # an older build that did not know the owner
    assert et.logic_hash in out
    old, new, out = step(path, [squat, et])
    assert et.logic_hash not in out and squat.logic_hash in out
    assert next(x for x in new.splitlines() if x.startswith(et.logic_hash)).endswith("\towner_reclaim=et")
    assert sidmap_check.check(old, new) == []


def test_main_exit_codes(tmp_path: Path):
    path = tmp_path / "sid-map.tsv"
    step(path, [g("aa", 5, "squatter"), g("cc", 50, "fork")])
    old = tmp_path / "old.tsv"
    old.write_text(path.read_text())
    step(path, [g("aa", 5, "squatter"), g("cc", 50, "fork"), g("bb", 10, "et")])
    assert sidmap_check.main(["x", str(old), str(path)]) == 0
    assert sidmap_check.main(["x", str(path), str(old)]) == 1


def test_release_changes_list_reclaims():
    h = "aa" * 8
    prev = [{"engine": "suricata-8", "logic_hash": h, "gid": 1, "exported_sid": SID, "rev": 1, "source": "squatter"}]
    now = [{**prev[0], "exported_sid": 1900000000}]
    ch = _changes(prev, now, {h: "reclaimed_by=et"})
    assert ch["reclaimed"] == [
        {
            "engine": "suricata-8",
            "logic_hash": h,
            "exported_sid": 1900000000,
            "rev": 1,
            "source": "squatter",
            "gid": 1,
            "previous_sid": SID,
            "reason": "reclaimed_by=et",
        }
    ]
    summary = {"generated_at": "2026-11-14T00:00:00Z", "content_id": "0" * 64, "engines": {}, "gates": []}
    assert f"1:{SID} -> 1:1900000000 (squatter, reclaimed_by=et)" in _notes(summary, ch)
    assert ch["moved"] == []
    # a move without a note (a clash in another major's ruleset) is announced too
    plain = _changes(prev, now)
    assert plain["reclaimed"] == [] and [(m["previous_sid"], m["exported_sid"]) for m in plain["moved"]] == [(SID, 1900000000)]
    assert "Other published sids that moved" in _notes(summary, plain)


def test_two_owner_rules_on_one_sid_keep_their_sids_across_builds(tmp_path: Path):
    """The owner ships two different rules with one sid (or two sources share its namespace). The
    remapped one keeps its new sid in every later build, and the map passes the append-only check."""
    path = tmp_path / "sid-map.tsv"
    a, b = g("aa", 10, "et"), g("bb", 10, "et")
    b.rule_key = a.rule_key = f"et:1:{SID}"
    ja3 = g("cc", 10, "et")  # a second source of the same owner namespace
    ja3.canonical_source = "et-ja3"

    def owner(x):
        return x.canonical_source.startswith("et")

    _, prev, first = step(path, [a, b, ja3], owner=owner)
    assert len(first) == 2 and sidmap_check.check("", prev) == []
    for _ in range(3):
        old, new, out = step(path, [a, b, ja3], owner=owner)
        assert out == first and old == new
        assert sidmap_check.check(old, new) == []


def test_sid_map_stays_small_over_30_nightly_runs(tmp_path: Path):
    """A source whose rules clash with ET's and change content every night. One row per rule (a new
    revision takes over its row), rules that left the release are retired, the floor keeps retired sids used,
    and every night passes the check with the release manifest."""
    import json

    path = tmp_path / "sid-map.tsv"

    def is_owner(x):
        return x.canonical_source == "et"

    n = 200

    def night(i: int) -> list[SimpleNamespace]:
        et = [
            SimpleNamespace(
                logic_hash=f"e{k:07d}".ljust(16, "0"), gid=1, sid=2050000 + k, canonical_source="et", rule_key=f"et:1:{2050000 + k}"
            )
            for k in range(n)
        ]
        hunt = [  # same sids and rule keys, new text every night; the last 20 rules disappear after night 10
            SimpleNamespace(
                logic_hash=f"{i:04x}{k:06x}".ljust(16, "f"), gid=1, sid=2050000 + k, canonical_source="hunt", rule_key=f"et:1:{2050000 + k}"
            )
            for k in range(n if i <= 10 else n - 20)
        ]
        return et + hunt

    sizes, previous_rows, seen_sids = [], [], set()
    for i in range(30):
        groups = night(i)
        before = path.read_text() if path.exists() else ""
        m = SidMap(path, today="2026-11-14")
        out = m.assign(groups, lambda x: (x.canonical_source != "et", x.logic_hash), owner=is_owner)
        rows = [
            {
                "logic_hash": x.logic_hash,
                "source": x.canonical_source,
                "rule_key": x.rule_key,
                "gid": 1,
                "sid": x.sid,
                "exported_sid": out.get(x.logic_hash, x.sid),
            }
            for x in groups
        ]
        keep = rows + previous_rows
        m.retire({r["logic_hash"] for r in keep}, {(r["source"], r["rule_key"]) for r in keep})
        m.save()
        after = path.read_text()
        manifest = "".join(json.dumps(r) + "\n" for r in rows)
        prev_manifest = "".join(json.dumps(r) + "\n" for r in previous_rows)
        assert sidmap_check.check(before, after, manifest, prev_manifest) == [], i
        # retirement needs both manifests: without them, a night that removed rows is refused
        assert (sidmap_check.check(before, after) == []) == (i != 12), i
        assert (sidmap_check.check(before, after, manifest) == []) == (i != 12), i
        sizes.append(len([x for x in after.splitlines() if not x.startswith("#")]))
        assert len({out[x.logic_hash] for x in groups if x.canonical_source == "hunt"}) == len(
            [x for x in groups if x.canonical_source == "hunt"]
        )
        if i == 1:
            stable = {x.rule_key: out[x.logic_hash] for x in groups if x.canonical_source == "hunt"}
        if i > 1:
            assert all(out[x.logic_hash] == stable[x.rule_key] for x in groups if x.canonical_source == "hunt")  # sids never move
        seen_sids |= set(out.values())
        previous_rows = rows
    assert all("\t2026-11-14\t" in x for x in after.splitlines() if not x.startswith("#"))  # given date, not the clock
    assert sizes[0] == 2 * n and max(sizes) == 2 * n and sizes[-1] == 2 * n - 20  # the 20 gone rules retired (two nights later)
    # a rule that comes back after retirement gets a sid above everything handed out before (never reused)
    m = SidMap(path)
    back = SimpleNamespace(logic_hash="b" * 16, gid=1, sid=2050000 + n - 1, canonical_source="hunt", rule_key=f"et:1:{2050000 + n - 1}")
    owner_rule = night(0)[n - 1]
    out = m.assign([owner_rule, back], lambda x: (x.canonical_source != "et", x.logic_hash), owner=is_owner)
    assert out[back.logic_hash] > max(seen_sids)


def test_retirement_refuses_live_duplicate_and_noted_rows(tmp_path: Path):
    """A row may be retired only when its rule is in neither the new nor the previous manifest
    (rows left out as duplicates count as present), and never when it carries a note. SidMap.retire and the
    nightly check share that predicate."""
    import json

    from suriharvest.sidmap_check import retirable

    path = tmp_path / "sid-map.tsv"
    squat, fork, et = g("aa", 5, "squatter"), g("cc", 50, "fork"), g("bb", 10, "et")
    step(path, [squat, fork])
    old, noted, _ = step(path, [squat, fork, et])  # squat's row now carries reclaimed_by=et
    rows = {x.split("\t")[0]: x for x in noted.splitlines() if not x.startswith("#")}

    def without(*hashes: str) -> str:
        return "".join(x + "\n" for x in noted.splitlines() if x.split("\t")[0] not in hashes)

    def manifest(*gs, excluded=()) -> str:
        out = [
            {"logic_hash": x.logic_hash, "source": x.canonical_source, "rule_key": x.rule_key, "gid": 1, "exported_sid": SID} for x in gs
        ]
        out += [
            {"logic_hash": x.logic_hash, "source": x.canonical_source, "rule_key": x.rule_key, "excluded_reason": "duplicate"}
            for x in excluded
        ]
        return "".join(json.dumps(r) + "\n" for r in out)

    empty = ""
    # fork's row: gone from both manifests -> may be retired
    assert sidmap_check.check(noted, without(fork.logic_hash), manifest(et), empty) == []
    # live in the new manifest, or only in the previous one, or left out as a duplicate: refused
    assert sidmap_check.check(noted, without(fork.logic_hash), manifest(et, fork), empty)
    assert sidmap_check.check(noted, without(fork.logic_hash), manifest(et), manifest(fork))
    assert sidmap_check.check(noted, without(fork.logic_hash), manifest(et, excluded=[fork]), empty)
    # a noted row (owner reclaim) is final, even when its rule is gone
    assert squat.logic_hash in rows and "reclaimed_by=" in rows[squat.logic_hash]
    assert sidmap_check.check(noted, without(squat.logic_hash), manifest(et), empty)
    assert not retirable(squat.logic_hash, "squatter", squat.rule_key, "reclaimed_by=et", (set(), set()))
    # SidMap.retire applies the same rule
    m = SidMap(path)
    gone = {e.logic_hash for e in m.retire({et.logic_hash}, set())}
    assert gone == {fork.logic_hash}
    # a published rule hidden from the manifest is caught against the rules files
    rules = [f'alert tcp any any -> any any (msg:"x"; sid:{SID}; rev:1;)\nalert tcp any any -> any any (msg:"y"; sid:42; rev:1;)\n']
    assert any("missing from the manifest" in e for e in sidmap_check.check(noted, noted, manifest(et), empty, rules))
    assert old != noted


def test_rules_check_reads_sids_like_the_parser_and_binds_them_to_the_manifest(tmp_path: Path):
    """The check reads gid:sid with the parser's own option splitter (ruleopts.py: escaped ';',
    case-insensitive names, quotes do not protect ';'), counts commented-out rule lines, refuses unreadable sid/gid,
    binds every published gid:sid to a manifest identity and never retires a row whose sid is still published."""
    import json
    import subprocess
    import sys

    path = tmp_path / "sid-map.tsv"
    squat, fork, et = g("aa", 5, "squatter"), g("cc", 50, "fork"), g("bb", 10, "et")
    step(path, [squat, fork])
    _, cur, out = step(path, [squat, fork, et])
    fork_sid = out[fork.logic_hash]

    def manifest(*rows) -> str:
        return "".join(json.dumps(r) + "\n" for r in rows)

    et_row = {"logic_hash": et.logic_hash, "source": "et", "rule_key": et.rule_key, "gid": 1, "exported_sid": SID}
    ok_rules = f'alert tcp any any -> any any (msg:"a"; sid:{SID}; rev:1;)\n'
    assert sidmap_check.check(cur, cur, manifest(et_row), "", [ok_rules]) == []
    hidden = [
        'alert tcp any any -> any any (msg:"x"; SID:77; rev:1;)\n',  # upper-case option name
        '# alert tcp any any -> any any (msg:"x"; sid:78; rev:1;)\n',  # commented out
        'alert tcp any any -> any any (msg:"a\\; sid:1"; sid:79; rev:1;)\n',  # escaped ';' inside a value
        'alert tcp any any -> any any (msg:"x"; gid:3; sid:80; rev:1;)\n',  # other gid
    ]
    for text, want in zip(hidden, ("1:77", "1:78", "1:79", "3:80"), strict=True):
        errs = sidmap_check.check(cur, cur, manifest(et_row), "", [ok_rules + text])
        assert any(want in e for e in errs), (text, errs)
    for text in (
        'alert tcp any any -> any any (msg:"x"; sid:81; sid:82;)\n',
        'alert tcp any any -> any any (msg:"x"; rev:1;)\n',
        'alert tcp any any -> any any (msg:"x"; sid:"83"; rev:1;)\n',  # quoted: Suricata refuses it
    ):
        assert any("unreadable" in e for e in sidmap_check.check(cur, cur, manifest(et_row), "", [ok_rules + text]))
    # a published remapped sid whose map row belongs to a rule the manifest does not carry
    other = {"logic_hash": "ff" * 8, "source": "x", "rule_key": "x:1:5", "gid": 1, "exported_sid": fork_sid}
    rules = ok_rules + f'alert tcp any any -> any any (msg:"f"; sid:{fork_sid}; rev:1;)\n'
    assert any("does not publish" in e for e in sidmap_check.check(cur, cur, manifest(et_row, other), "", [rules]))
    # a row whose sid is still in the published files is never retired
    gone = "".join(x + "\n" for x in cur.splitlines() if not x.startswith(fork.logic_hash))
    assert any("may not go" in e for e in sidmap_check.check(cur, gone, manifest(et_row, other), "", [rules]))
    # the standalone script (python3 -I, package not importable) loads the same splitter
    (tmp_path / "old.tsv").write_text(cur)
    (tmp_path / "m.jsonl").write_text(manifest(et_row))
    (tmp_path / "r.rules").write_text(ok_rules + hidden[0])
    script = Path(__file__).parents[1] / "src" / "suriharvest" / "sidmap_check.py"
    r = subprocess.run(
        [
            sys.executable,
            "-I",
            str(script),
            str(tmp_path / "old.tsv"),
            str(tmp_path / "old.tsv"),
            "--manifest",
            str(tmp_path / "m.jsonl"),
            "--rules",
            str(tmp_path / "r.rules"),
        ],
        capture_output=True,
        text=True,
        cwd=tmp_path,
        check=False,
    )
    assert r.returncode == 1 and "1:77" in r.stdout, r.stdout + r.stderr


def test_shared_namespace_holder_gone_with_squatter_stays_stable(tmp_path: Path):
    """Two sources share the owner namespace and ship sid S (a holds it, b is remapped), a squatter c is
    remapped too. The publisher drops a: b must not move back onto S while a's row is still in the map (two rows
    would export S and the nightly check would fail every night). Three nights, then a's row retires; still stable."""
    path = tmp_path / "sid-map.tsv"
    a, b, c = g("aa", 10, "et"), g("bb", 10, "et-dup"), g("cc", 50, "zz")

    def owner(x):
        return x.canonical_source.startswith("et")

    _, night0, first = step(path, [a, b, c], owner=owner)
    assert set(first) == {b.logic_hash, c.logic_hash} and sidmap_check.check("", night0) == []
    for _ in range(3):  # a is gone; its row stays until a release without it is published
        old, new, out = step(path, [b, c], owner=owner)
        assert out == first, out
        assert sidmap_check.check(old, new) == []
    m = SidMap(path)
    gone = m.retire({b.logic_hash, c.logic_hash}, set())
    m.save()
    assert [e.logic_hash for e in gone] == [a.logic_hash]
    old, new, out = step(path, [b, c], owner=owner)
    assert out == first and sidmap_check.check(old, new) == []
    # a newcomer squatter on S: the owner's rule takes S back, the newcomer is remapped
    d = g("dd", 1, "newcomer")
    old, new, out = step(path, [b, c, d], owner=owner)
    assert b.logic_hash not in out and d.logic_hash in out and sidmap_check.check(old, new) == []
