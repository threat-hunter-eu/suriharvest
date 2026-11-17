"""Regression tests: sid rewriting, duplicate sids on export, corrupt archives, per-source isolation, stable sids."""

from __future__ import annotations

import gzip
import io
import json
import shutil
import tarfile
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from typer.testing import CliRunner

from suriharvest.cli import app
from suriharvest.parser import parse_rule, parse_text, replace_sid
from suriharvest.sidmap import SidMap
from tests.test_pipeline import DISABLED, ET_V3, run, write, ws  # noqa: F401 - fixture

runner = CliRunner()

LEGIT = 'alert tcp any any -> any 1 (msg:"LEGIT detection of bad thing"; flow:established,to_server; content:"bad"; sid:2000001; rev:3;)'
DECOY = (
    'alert tcp any any -> any 1 (msg:"evil decoy"; flow:established,to_server; content:"evil"; '
    "reference:url,example.com/a-sid:2000001; sid:2000001; rev:99;)"
)


def _workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sources: list[dict]) -> Path:
    root = tmp_path / "ws"
    root.mkdir()
    (root / "sources.yaml").write_text(yaml.safe_dump({"sources": sources}))
    monkeypatch.setenv("SURIHARVEST_HOME", str(root))
    monkeypatch.chdir(root)
    run("doctor")
    return root


# ---------------------------------------------------------------------------------------------------------------
# the sid is rewritten through the option tokenizer, never inside another option's value


def test_replace_sid_ignores_sid_inside_other_options():
    out = replace_sid(DECOY, 1_900_000_000)
    assert "reference:url,example.com/a-sid:2000001;" in out
    r = parse_rule(out)
    assert r.sid == 1_900_000_000 and r.rev == 99
    assert replace_sid('alert tcp any any -> any 1 (msg:"a\\;sid:5\\;"; sid : 7 ; rev:1;)', 9).endswith("sid:9; rev:1;)")


def test_decoy_rule_cannot_knock_out_the_legit_rule(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    write(tmp_path / "et" / "et.rules", LEGIT)
    write(tmp_path / "evil" / "evil.rules", DECOY)
    _workspace(
        tmp_path,
        monkeypatch,
        [
            {"name": "et", "type": "local", "url": str(tmp_path / "et"), "priority": 10, "sid_namespace": "et"},
            {"name": "evil", "type": "local", "url": str(tmp_path / "evil"), "priority": 50},
        ],
    )
    run("sync")
    out_dir = tmp_path / "out"
    run("export", "--out", str(out_dir), "--unit", "logic", "--remap-colliding-sids")
    rules_file = out_dir / "suricata.rules"
    rules = [parse_rule(x) for x in rules_file.read_text().splitlines() if x and not x.startswith("#")]
    assert len(rules) == 2
    assert len({(r.gid, r.sid) for r in rules}) == 2  # no duplicate signature
    by_msg = {r.msg: r for r in rules}
    assert by_msg["LEGIT detection of bad thing"].sid == 2000001
    assert by_msg["evil decoy"].sid != 2000001
    assert "reference:url,example.com/a-sid:2000001;" in rules_file.read_text()  # the decoy text is left alone
    manifest = {m["msg"]: m for m in map(json.loads, (out_dir / "manifest.jsonl").read_text().splitlines())}
    assert manifest["evil decoy"]["exported_sid"] == by_msg["evil decoy"].sid  # the manifest tells the truth

    if shutil.which("suricata") is not None:
        from suriharvest.config import EngineConfig
        from suriharvest.validate import probe

        engine = probe(EngineConfig("suricata-7"))
        work = tmp_path / "suri"
        work.mkdir()
        rc, output = engine.run(rules_file, work)
        assert rc == 0, output
        assert "Duplicate signature" not in output
        assert "rules failed" not in output or "0 rules failed" in output


def test_export_refuses_a_file_with_duplicate_sids(tmp_path: Path):
    from suriharvest.export import SidCollision, check_unique_sids

    f = tmp_path / "x.rules"
    f.write_text(LEGIT + "\n" + DECOY + "\n# " + LEGIT + "\n")
    with pytest.raises(SidCollision, match="1:2000001"):
        check_unique_sids(f)


# ---------------------------------------------------------------------------------------------------------------
# the "looks like rules" pre-filter and the parser are linear


@pytest.mark.parametrize(
    "data",
    [b" " * (4 * 1024 * 1024), b" \t#" * (1400 * 1024), b"alert " + b"x" * (4 * 1024 * 1024), b"#" * (4 * 1024 * 1024)],
    ids=["blanks", "blanks-and-hashes", "long-token", "hashes"],
)
def test_pathological_4mib_line_is_fast(data: bytes):
    from suriharvest.sync import looks_like_rules

    t0 = time.monotonic()
    assert looks_like_rules(data) is False
    parse_text(data.decode())
    assert time.monotonic() - t0 < 1.0


def test_overlong_rule_line_is_reported_not_parsed():
    from suriharvest.parser import MAX_RULE_LINE

    long_rule = 'alert tcp any any -> any any (msg:"' + "a" * MAX_RULE_LINE + '"; sid:1;)'
    pf = parse_text(long_rule + "\n" + LEGIT + "\n")
    assert [r.sid for r in pf.rules] == [2000001]
    assert len(pf.errors) == 1 and "longer than" in pf.errors[0][2]


# ---------------------------------------------------------------------------------------------------------------
# a corrupt archive fails one source only, and its validators are not saved


def _tarball(*lines: str) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tf:
        data = ("\n".join(lines) + "\n").encode()
        info = tarfile.TarInfo("rules/x.rules")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    return gzip.compress(raw.getvalue())


def test_extract_archive_wraps_corrupt_archives(tmp_path: Path):
    from suriharvest.sync import SyncError, extract_archive

    good = _tarball(LEGIT)
    for name, data in [("a.tar.gz", b"garbage-not-gzip"), ("b.tar.gz", good[: len(good) // 2]), ("c.zip", b"PK\x03\x04junk")]:
        with pytest.raises(SyncError, match="corrupt archive"):
            extract_archive(data, name, tmp_path / name)


def test_corrupt_archive_does_not_abort_update_and_is_retried(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from suriharvest import sync

    write(tmp_path / "good" / "g.rules", ET_V3)
    root = _workspace(
        tmp_path,
        monkeypatch,
        [
            {"name": "broken", "type": "http-tarball", "url": "https://example.invalid/r.tar.gz"},
            {"name": "good", "type": "local", "url": str(tmp_path / "good")},
        ],
    )
    upstream = {"data": _tarball(LEGIT), "lm": "Mon, 01 Jan 2024 00:00:00 GMT"}
    calls: list[dict | None] = []

    def fake_download(url, token=None, validators=None, allow_private=False):
        calls.append(validators)
        if validators and validators.get("last-modified") == upstream["lm"]:
            return None, validators  # 304
        return upstream["data"], {"last-modified": upstream["lm"]}

    monkeypatch.setattr(sync, "download", fake_download)
    state = root / "data" / "cache" / "http" / "broken.json"

    first = runner.invoke(app, ["update", "--no-validate"])
    assert first.exit_code == 0, first.output
    assert state.exists()

    # upstream now serves a broken archive with a new Last-Modified
    upstream.update(data=b"garbage-not-gzip", lm="Tue, 02 Jan 2024 00:00:00 GMT")
    write(tmp_path / "good" / "g.rules", ET_V3, LEGIT)
    second = runner.invoke(app, ["update", "--no-validate"])
    assert "update crashed" not in second.output
    assert "failed broken" in second.output.replace("[red]", "") or "broken: corrupt archive" in second.output
    assert second.exit_code == 1  # a failed source makes the exit code 1 ...
    assert "ok good" in second.output.replace("[green]", "")  # ... but the other sources were synced
    assert not state.exists()  # validators of the failed download were not kept

    # the next run downloads again (no conditional request -> no 304 "unchanged"), and fails again
    third = runner.invoke(app, ["update", "--no-validate", "--allow-failures"])
    assert calls[-1] is None
    assert "corrupt archive" in third.output
    assert third.exit_code == 0, third.output  # --allow-failures (and within --max-failed-sources)
    gated = runner.invoke(app, ["update", "--no-validate", "--allow-failures", "--max-failed-sources", "0"])
    assert "corrupt archive" in gated.output  # one failure is always allowed by the floor: still reported

    # upstream fixed: synced again, validators stored
    upstream.update(data=_tarball(LEGIT, DECOY), lm="Wed, 03 Jan 2024 00:00:00 GMT")
    fourth = runner.invoke(app, ["update", "--no-validate"])
    assert fourth.exit_code in (0, 1), fourth.output
    assert "ok broken" in fourth.output.replace("[green]", "")
    assert json.loads(state.read_text())["validators"]["last-modified"] == upstream["lm"]


def test_unexpected_exception_in_one_source_is_isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from suriharvest import sync

    write(tmp_path / "a" / "a.rules", LEGIT)
    write(tmp_path / "b" / "b.rules", ET_V3)
    _workspace(
        tmp_path,
        monkeypatch,
        [
            {"name": "a", "type": "local", "url": str(tmp_path / "a")},
            {"name": "b", "type": "local", "url": str(tmp_path / "b")},
        ],
    )
    real = sync.fetch

    def flaky(src, *a, **k):
        if src.name == "a":
            raise RuntimeError("boom")
        return real(src, *a, **k)

    monkeypatch.setattr(sync, "fetch", flaky)
    r = runner.invoke(app, ["update", "--no-validate", "--allow-failures"])
    assert "update crashed" not in r.output
    assert "RuntimeError: boom" in r.output and "ok b" in r.output.replace("[green]", "")


# ---------------------------------------------------------------------------------------------------------------
# once published under a sid, a rule keeps it


def test_incumbent_keeps_its_sid_when_a_better_ranked_newcomer_arrives(tmp_path: Path):
    prio = {"community": 50, "vendor": 10}

    def g(h: str, src: str) -> SimpleNamespace:
        return SimpleNamespace(logic_hash=h, gid=1, sid=100, src=src)

    def rank(x: SimpleNamespace) -> tuple:
        return (prio[x.src], x.logic_hash)

    from suriharvest.sidmap import holders_from_manifest

    path = tmp_path / "sid-map.tsv"
    m = SidMap(path)
    assert m.assign([g("d" * 8, "community")], rank, 9_000_000) == {}  # D exported as sid 100
    m.save()
    assert not path.exists() or "d" * 8 not in path.read_text()  # alone on its sid: no row needed
    # what the previous build published (its manifest) names the incumbent
    prev = holders_from_manifest([{"logic_hash": "d" * 8, "rule_key": "community:1:100", "gid": 1, "sid": 100, "exported_sid": 100}])
    m = SidMap(path)
    out = m.assign([g("d" * 8, "community"), g("e" * 8, "vendor")], rank, 9_000_000, previous=prev)
    assert "d" * 8 not in out  # D keeps sid 100 ...
    assert out["e" * 8] >= 9_000_000  # ... the newcomer is remapped, despite its better priority
    m.save()
    again = SidMap(path).assign([g("e" * 8, "vendor"), g("d" * 8, "community")], rank, 9_000_000)
    assert again == out  # and the decision is stable (now from the map, without `previous`)


def test_new_revisions_keep_the_clash_decision_and_the_map_stays_small(tmp_path: Path):
    def g(h: str, key: str, sid: int, prio: int) -> SimpleNamespace:
        return SimpleNamespace(logic_hash=h, rule_key=key, gid=1, sid=sid, prio=prio, canonical_source=key.split(":")[0])

    def rank(x: SimpleNamespace) -> tuple:
        return (x.prio, x.logic_hash)

    path = tmp_path / "sid-map.tsv"
    alone = [g(f"{i:016x}", f"et:1:{i}", i, 10) for i in range(1, 2001)]  # 2,000 rules without a clash
    a1, b1 = g("a" * 16, "et:1:5000", 5000, 10), g("b" * 16, "fork:1:5000", 5000, 50)
    m = SidMap(path)
    first = m.assign([*alone, a1, b1], rank, 9_000_000)
    m.save()
    rows = [x for x in path.read_text().splitlines() if not x.startswith("#")]
    assert first == {"b" * 16: 9_000_000} and len(rows) == 2  # the 2 clash rows (plus the header and floor lines)
    # both rules get a new revision (new logic hashes, same rule keys): same decision, same sids
    a2, b2 = g("c" * 16, "et:1:5000", 5000, 10), g("d" * 16, "fork:1:5000", 5000, 50)
    m = SidMap(path)
    second = m.assign([*alone, b2, a2], rank, 9_000_000)
    m.save()
    assert second == {"d" * 16: 9_000_000}
    # the nightly check: rows sharing an exported gid:sid must be one rule (one rule key)
    by_sid: dict[tuple[str, str], set[str]] = {}
    rows = [x for x in path.read_text().splitlines() if not x.startswith("#")]
    assert len(rows) == 2  # the new revisions took over the rows: one row per rule
    for ln in rows:
        f = ln.split("\t")
        by_sid.setdefault((f[1], f[3]), set()).add((f[6], f[5]))
    assert all(len(v) == 1 for v in by_sid.values()) and len(by_sid) == 2


def test_another_source_with_the_same_rule_key_does_not_inherit_a_sid(tmp_path: Path):
    """Revisions are matched within one supplying source: a copy of ET's rule key in another feed (same gid:sid,
    higher rev, new logic) is a different rule, never 'the next revision' of the recorded one."""
    from suriharvest.sidmap import holders_from_manifest

    def g(h: str, src: str, prio: int, key: str = "et:1:2050001") -> SimpleNamespace:
        return SimpleNamespace(logic_hash=h, rule_key=key, gid=1, sid=2050001, prio=prio, canonical_source=src)

    def rank(x: SimpleNamespace) -> tuple:
        return (x.prio, x.logic_hash)

    path = tmp_path / "sid-map.tsv"
    et1, fork1 = g("e1" * 8, "et-open", 50), g("f1" * 8, "fork", 10)
    m = SidMap(path)
    prev = holders_from_manifest(
        [{"logic_hash": "e1" * 8, "rule_key": "et:1:2050001", "source": "et-open", "gid": 1, "sid": 2050001, "exported_sid": 2050001}]
    )
    first = m.assign([et1, fork1], rank, 9_000_000, previous=prev)
    m.save()
    assert first == {"f1" * 8: 9_000_000}  # ET held the sid before: the fork is remapped despite its priority
    # the fork ships a "new revision" under ET's rule key, ET ships its own new revision
    et2, fork2 = g("e2" * 8, "et-open", 50), g("f2" * 8, "fork", 10)
    m = SidMap(path)
    second = m.assign([fork2, et2], rank, 9_000_000)
    m.save()
    assert second == {"f2" * 8: 9_000_000}  # each follows its own source's row: ET keeps 2050001
    # a third feed with the same rule key and no row of its own inherits nothing
    m = SidMap(path)
    third = m.assign([et2, g("aa" * 8, "evil", 1)], rank, 9_000_000)
    assert "e2" * 8 not in third and third["aa" * 8] > 9_000_000
    # previous holders: a rule key from another source does not count
    prev = holders_from_manifest(
        [{"logic_hash": "x" * 16, "rule_key": "et:1:7", "source": "et-open", "gid": 1, "sid": 7, "exported_sid": 7}]
    )
    assert not prev.had(g("y" * 16, "evil", 1, "et:1:7"), 1, 7) and prev.had(g("z" * 16, "et-open", 1, "et:1:7"), 1, 7)


# ---------------------------------------------------------------------------------------------------------------
# rules disabled upstream stay disabled in a query export


def test_export_keeps_upstream_disabled_state(ws: Path, tmp_path: Path):  # noqa: F811
    deleted = '# alert http any any -> any any (msg:"ET DELETED old thing"; http.uri; content:"/old"; sid:2000099; rev:2;)'
    write(tmp_path / "et" / "rules" / "emerging-deleted.rules", deleted)
    run("sync")
    out = tmp_path / "e1"
    text = run("export", "source:et", "--out", str(out), "--unit", "logic")
    rules = (out / "suricata.rules").read_text()
    assert "2 rules disabled upstream written commented out" in text
    assert "# " + DISABLED.lstrip("# ") in rules
    enabled = [x for x in rules.splitlines() if x and not x.startswith("#")]
    assert not any("sid:2000005;" in x or "sid:2000099;" in x for x in enabled)
    m = {r["sid"]: r for r in map(json.loads, (out / "manifest.jsonl").read_text().splitlines())}
    assert m[2000005]["enabled"] is False and m[2000001]["enabled"] is True

    out2 = tmp_path / "e2"
    run("export", "source:et", "--out", str(out2), "--unit", "logic", "--disabled", "omit")
    assert "2000005" not in (out2 / "suricata.rules").read_text()

    out3 = tmp_path / "e3"
    run("export", "source:et", "--out", str(out3), "--unit", "logic", "--include-disabled")
    enabled = [x for x in (out3 / "suricata.rules").read_text().splitlines() if x and not x.startswith("#")]
    assert any("sid:2000005;" in x for x in enabled) and any("sid:2000099;" in x for x in enabled)


# ---------------------------------------------------------------------------------------------------------------
# copyright notices and licence texts travel with a release

ET_HEADER = [
    "# Emerging Threats",
    "#",
    "# This distribution may contain rules under two different licenses.",
    "#",
    "#  Rules with sids 1 through 3464, and 100000000 through 100000908 are under the GPLv2.",
    "#  A copy of that license is available at http://www.gnu.org/licenses/gpl-2.0.html",
    "#",
    "#  Rules with sids 2000000 through 2799999 are from Emerging Threats and are covered under the BSD License",
    "#  as follows:",
    "#",
    "#*************************************************************",
    "#  Copyright (c) 2003-2026, Emerging Threats",
    "#  All rights reserved.",
    "#",
    "#  Redistribution and use in source and binary forms, with or without modification, are permitted provided that the",
    "#  following conditions are met:",
    "",
]


def test_release_keeps_copyright_notices_and_licence_texts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from tests.fakes import ACCEPT_ALL, python_script

    fake = python_script(tmp_path / "fake-suricata", ACCEPT_ALL)
    write(tmp_path / "et" / "emerging-malware.rules", *ET_HEADER, ET_V3)
    write(tmp_path / "gpl" / "g.rules", LEGIT.replace("2000001", "1000001"))
    root = tmp_path / "ws"
    monkeypatch.setenv("SURIHARVEST_HOME", str(root))
    monkeypatch.chdir(tmp_path)
    run("init", str(root), "--refresh", "--engine", f"suricata-7={fake}")
    monkeypatch.chdir(root)
    srcs = [
        {
            "name": "et",
            "type": "local",
            "url": str(tmp_path / "et"),
            "priority": 10,
            "licence": "BSD-3-Clause AND GPL-2.0-only",
            "sid_namespace": "et",
            "redistribute": "yes",
        },
        {"name": "gpl", "type": "local", "url": str(tmp_path / "gpl"), "licence": "GPL-3.0-only", "redistribute": "yes"},
    ]
    (root / "sources.yaml").write_text(yaml.safe_dump({"sources": srcs}))
    run("update")
    out = tmp_path / "rel"
    # a source whose licence asks for a copyright notice and that has none fails the build
    r = CliRunner().invoke(app, ["release", "build", str(out), "--engine", "suricata-7", "--build-epoch", "1763100000"])
    assert r.exit_code != 0 and "no copyright line for gpl" in r.output, r.output
    srcs[1]["copyright"] = "Copyright (c) 2025 GPL Rules Author"
    (root / "sources.yaml").write_text(yaml.safe_dump({"sources": srcs}))
    run("release", "build", str(out), "--engine", "suricata-7", "--build-epoch", "1763100000")
    notice = (out / "NOTICE.md").read_text()
    assert "Copyright (c) 2003-2026, Emerging Threats" in notice
    # the source ships no licence file: its BSD text is the template with its own copyright line filled in
    assert "LICENSES/et/LICENSE.BSD-3-Clause.txt" in notice and "LICENSES/texts/GPL-2.0-only.txt" in notice
    assert "- Copyright (c) 2025 GPL Rules Author" in notice
    assert "Copyright (c) 2025 GPL Rules Author" in (out / "suricata-7.rules").read_text()
    by_et = (out / "suricata-7.by-source.et.rules").read_text()
    assert "# Copyright (c) 2003-2026, Emerging Threats" in by_et and "Redistribution and use" in by_et
    assert "Copyright (c) 2003-2026, Emerging Threats" in (out / "suricata-7.rules").read_text()
    for tarname in ("LICENSES.tar.gz", "suriharvest-7.tar.gz"):
        with tarfile.open(out / tarname) as tf:
            names = set(tf.getnames())
            texts = {n: tf.extractfile(n).read().decode() for n in names if n.startswith("LICENSES/texts/")}  # type: ignore[union-attr]
        assert {"LICENSES/texts/BSD-3-Clause.txt", "LICENSES/texts/GPL-2.0-only.txt", "LICENSES/texts/GPL-3.0-only.txt"} <= set(texts)
        assert "GNU GENERAL PUBLIC LICENSE" in texts["LICENSES/texts/GPL-2.0-only.txt"]
        assert "Redistributions of source code must retain" in texts["LICENSES/texts/BSD-3-Clause.txt"]
        with tarfile.open(out / tarname) as tf:
            filled = tf.extractfile("LICENSES/et/LICENSE.BSD-3-Clause.txt").read().decode()  # type: ignore[union-attr]
        assert filled.startswith("Copyright (c) 2003-2026, Emerging Threats") and "<owner>" not in filled


def test_sid_and_gid_values_are_read_like_suricata():
    """Suricata refuses `_`, quotes, non-ASCII digits, values above 2^32-1 and gid:0; so do the
    parser and the sid map check (ruleopts.option_int)."""
    import pytest

    from suriharvest.parser import ParseError, parse_rule
    from suriharvest.ruleopts import OptionError, gid_sid, option_int

    assert option_int("42") == 42 and option_int(" +7 ") == 7 and option_int("4294967295") == 4294967295
    for bad in ("1_000", '"6"', "٢٤", "4294967296", "-1", "0x10", ""):
        assert option_int(bad) is None, bad
    rule = 'alert tcp any any -> any 1 (msg:"x"; content:"a"; {}rev:1;)'
    assert parse_rule(rule.format("sid:12; ")).sid == 12
    for opts in ("sid:1_000; ", 'sid:"6"; ', "sid:٢٤; ", "sid:4294967296; ", "gid:0; sid:5; ", "gid:1; gid:2; sid:5; "):
        with pytest.raises(ParseError):
            parse_rule(rule.format(opts))
        with pytest.raises(OptionError):
            gid_sid(rule.format(opts))
    assert gid_sid(rule.format("gid:3; sid:5; ")) == (3, 5)


def test_huge_sid_or_gid_is_one_bad_line_not_a_failed_source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """A sid with more than 4,300 digits reached int() (Python's conversion limit) and failed
    the whole source; it is now just a rule Suricata refuses, and the good rule next to it is still ingested."""
    from suriharvest.overrides import OverrideError, normalise
    from suriharvest.parser import ParseError
    from suriharvest.profiles import ProfileError, _check
    from suriharvest.ruleopts import OptionError, gid_sid, option_int
    from suriharvest.suricata_update_conf import Unsupported, selectors

    huge = "9" * 5000
    assert option_int(huge) is None and option_int("0" * 5000) == 0 and option_int("0000000042") == 42
    rule = 'alert tcp any any -> any 1 (msg:"x"; content:"a"; {}rev:1;)'
    for opts in (f"sid:{huge}; ", f"gid:{huge}; sid:5; "):
        with pytest.raises(ParseError):
            parse_rule(rule.format(opts))
        with pytest.raises(OptionError):
            gid_sid(rule.format(opts))
    for bad in (huge, "\u00b2", "\u0662"):  # superscript two and Arabic-Indic two pass str.isdigit()
        with pytest.raises(ProfileError):
            _check("sid", bad)
    with pytest.raises(OverrideError):
        normalise(
            "thresholds",
            {"kind": "sid", "value": "1", "filter": "threshold", "type": "limit", "track": "by_src", "count": huge, "seconds": 60},
        )
    with pytest.raises(Unsupported):
        selectors(huge)

    write(tmp_path / "mine" / "mine.rules", LEGIT, rule.format(f"sid:{huge}; "))
    _workspace(tmp_path, monkeypatch, [{"name": "mine", "type": "local", "url": str(tmp_path / "mine")}])
    r = runner.invoke(app, ["update", "--no-validate"])
    assert r.exit_code == 0, r.output
    assert "ValueError" not in r.output and "failed mine" not in r.output
    assert "LEGIT detection" in run("search", "sid:2000001")


def test_rules_files_split_on_newline_only():
    """Ingest and the release count read lines as Suricata does ("\\n" only)."""
    from suriharvest.parser import logical_lines
    from suriharvest.release import loaded_rule_count

    rule = 'alert tcp any any -> any 1 (msg:"a\x85b c\x0cd"; content:"x"; sid:1; rev:1;)'
    text = rule + "\r\n# comment\n" + rule.replace("sid:1", "sid:2") + "\n"
    lines = [x.text for x in logical_lines(text)]
    assert lines == [rule, "# comment", rule.replace("sid:1", "sid:2")]
    assert loaded_rule_count(text) == 2


def test_rules_suricata_cannot_load_for_length_are_refused_at_ingest():
    """Suricata 7.0.3 refuses a rule of 8192 bytes or more; ingest refuses it too, so user regexes
    never scan more than MAX_SURICATA_RULE bytes of one rule."""
    import pytest

    from suriharvest.parser import MAX_SURICATA_RULE, ParseError, parse_rule

    base = 'alert tcp any any -> any 1 (msg:""; content:"a"; sid:1; rev:1;)'

    def sized(n: int) -> str:
        return base.replace('msg:""', 'msg:"' + "x" * (n - len(base)) + '"')

    assert parse_rule(sized(MAX_SURICATA_RULE)).sid == 1
    assert parse_rule("# " + sized(MAX_SURICATA_RULE)).enabled is False
    with pytest.raises(ParseError, match="never loads"):
        parse_rule(sized(MAX_SURICATA_RULE + 1))


# ---------------------------------------------------------------------------------------------------------------
# an update that updated nothing fails, even with --allow-failures


def test_only_source_failing_fails_the_update(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from suriharvest import sync

    write(tmp_path / "a" / "a.rules", LEGIT)
    _workspace(tmp_path, monkeypatch, [{"name": "a", "type": "local", "url": str(tmp_path / "a")}])
    real = sync.fetch
    broken = {"on": True}

    def flaky(src, *a, **k):
        if broken["on"]:
            raise RuntimeError("down")
        return real(src, *a, **k)

    monkeypatch.setattr(sync, "fetch", flaky)
    # first run: the only source fails, the corpus is empty
    r = runner.invoke(app, ["update", "--no-validate", "--allow-failures"])
    assert r.exit_code == 1, r.output
    assert "every enabled source failed: nothing was updated" in r.output
    assert "the corpus has no rules" in r.output
    # once it worked, the same failure keeps the old rules but still fails the run (all of 1 source failed)
    broken["on"] = False
    assert runner.invoke(app, ["update", "--no-validate"]).exit_code == 0
    broken["on"] = True
    r = runner.invoke(app, ["update", "--no-validate", "--allow-failures"])
    assert r.exit_code == 1 and "every enabled source failed" in r.output and "the corpus has no rules" not in r.output


def test_one_of_several_sources_failing_is_still_allowed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from suriharvest import sync

    write(tmp_path / "a" / "a.rules", LEGIT)
    write(tmp_path / "b" / "b.rules", ET_V3)
    _workspace(tmp_path, monkeypatch, [{"name": n, "type": "local", "url": str(tmp_path / n)} for n in ("a", "b")])
    real = sync.fetch
    monkeypatch.setattr(
        sync, "fetch", lambda src, *a, **k: (_ for _ in ()).throw(RuntimeError("down")) if src.name == "a" else real(src, *a, **k)
    )
    r = runner.invoke(app, ["update", "--no-validate", "--allow-failures"])
    assert r.exit_code == 0, r.output  # 1 of 2 failed: the floor allows one, unchanged behaviour
    assert "every enabled source failed" not in r.output
