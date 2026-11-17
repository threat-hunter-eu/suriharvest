"""Import-conf and modify/thresholds behave like suricata-update and Suricata.

Golden expectations were produced with suricata-update 1.3.3 on the same rules and configuration files; when
suricata-update is installed the comparison also runs live."""

from __future__ import annotations

import json
import os
import re
import shutil
import struct
import subprocess
import tarfile
import time
from pathlib import Path

import pytest
import yaml

from suriharvest.overrides import OverrideError, normalise
from suriharvest.suricata_update_conf import convert, selectors
from suriharvest.userregex import MAX_SCAN, compile_user
from tests.test_pipeline import CHECKER, SETTER, run, with_fake_engine, write, ws  # noqa: F401 - fixture

MARK = " metadata:suriharvest_modified true;"


def build_dir(out: str) -> Path:
    return Path(out.split("-> ")[1].split("\n")[0].strip())


def enabled_rules(text: str) -> dict[int, str]:
    out = {}
    for x in text.splitlines():
        if x.startswith(("alert ", "drop ", "reject ", "pass ")):
            out[int(re.search(r"sid:(\d+);", x).group(1))] = x.replace(MARK, "")
    return out


def edit_profile_file(root: Path, name: str, **sections) -> None:  # type: ignore[no-untyped-def]
    f = root / "exclusions" / f"{name}.yaml"
    data = yaml.safe_load(f.read_text()) or {}
    data.update(sections)
    time.sleep(0.01)
    f.write_text(yaml.safe_dump(data, sort_keys=False))


# --------------------------------------------------------------------------------------------------------------
# a migration that exercises precedence, trailing comments, group: without .rules, a bare *.rules line and
# a noalert flowbit setter under drop.conf

CONFS = {
    "disable.conf": "# migrate test\nemerging-malware.rules # all of ET malware\n",
    "enable.conf": "2000001\n2000002 # the setter\n1:2000005 # turn on dns\n",
    "drop.conf": "group:emerging-malware\nre:gate\\.php # noisy rule\n",
    "modify.conf": '2000001 "FooBot" "FooBot9" # tweak\n',
}
# suricata-update 1.3.3 output for these files over tests/test_pipeline's ET fixture (enabled rules only)
GOLDEN = {
    2000001: 'drop http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE Foo CnC Checkin"; flow:established,to_server; '
    'http.uri; content:"/gate.php"; http.user_agent; content:"FooBot9"; sid:2000001; rev:3;)',
    2000002: SETTER,  # enabled again by enable.conf, and not dropped: noalert
    2000005: 'drop dns any any -> any any (msg:"ET DNS evil"; dns.query; content:"evil.example"; nocase; sid:2000005; rev:1;)',
}


def write_confs(d: Path) -> Path:
    d.mkdir(parents=True, exist_ok=True)
    for name, text in CONFS.items():
        (d / name).write_text(text)
    return d


def test_lines_are_read_like_suricata_update(tmp_path: Path):
    d = write_confs(tmp_path / "c")
    res = convert({n: d / n for n in CONFS})
    assert not res.unsupported, res.unsupported
    assert res.exclusions == [("file", "emerging-malware.rules", "disable.conf:2")]  # comment stripped, bare name = group
    assert [e["value"] for e in res.enable] == ["2000001", "2000002", "2000005"]
    assert all(e["beats_exclusions"] for e in res.enable)
    drops = [(e["kind"], e["value"]) for e in res.modify if "action" in e]
    assert drops == [("file", "emerging-malware"), ("rule_regex", "gate\\.php")]
    rw = next(e for e in res.modify if "from" in e)
    assert (rw["from"], rw["to"]) == ("FooBot", "FooBot9")
    # parse_rule_match order and case-sensitive prefixes
    assert selectors("*") == [("file", "*")]
    assert selectors("foo-*.rules") == [("file", "foo-*.rules")]
    assert selectors("re:x.rules") == [("rule_regex", "x.rules")]
    for bad in ("RE:x", "Group:x", "filename:rules/x.rules", "2000001,re:x"):
        with pytest.raises(ValueError):
            selectors(bad)


def test_import_conf_matches_suricata_update_golden(ws: Path, tmp_path: Path):  # noqa: F811
    run("profile", "create", "su", "--query", "source:et")
    with_fake_engine(ws, "su")
    d = write_confs(tmp_path / "etc")
    run("profile", "import-conf", "su", str(d))
    out = run("profile", "build", "su")
    got = enabled_rules((build_dir(out) / "suricata.rules").read_text())
    assert got == GOLDEN, out
    assert "1 noalert rule(s) (flowbit setters) not changed" in out
    assert "matched no rule: enable" not in out


@pytest.mark.skipif(shutil.which("suricata-update") is None, reason="suricata-update not installed")
def test_golden_against_live_suricata_update(ws: Path, tmp_path: Path):  # noqa: F811
    up = tmp_path / "et.tar.gz"
    with tarfile.open(up, "w:gz") as tf:
        tf.add(ws.parent / "et" / "rules", arcname="rules")
    c = write_confs(tmp_path / "conf")
    o = tmp_path / "o"
    cmd = ["suricata-update", "-q", "-D", str(tmp_path / "d"), "-o", str(o), "--url", up.as_uri(), "--no-test", "--no-reload"]
    for n in CONFS:
        cmd += [f"--{n.split('.')[0]}-conf", str(c / n)]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
    assert r.returncode == 0, r.stderr[-2000:]
    theirs = {k: v for k, v in enabled_rules((o / "suricata.rules").read_text()).items() if 2000000 <= k < 2000100}
    assert theirs == GOLDEN


def test_enable_without_the_flag_reports_the_exclusion_that_wins(ws: Path):  # noqa: F811
    run("profile", "create", "p", "--query", "source:et")
    run("profile", "exclusions", "p")
    edit_profile_file(ws, "p", enable=[{"kind": "sid", "value": "2000003"}])
    run("profile", "exclude", "p", "emerging-malware", "--kind", "file")  # stem matches emerging-malware.rules
    out = run("profile", "build", "p")
    assert "exclusion wins over: enable #1 (sid: 2000003): et:1:2000003 excluded by file: emerging-malware" in out
    assert "matched no rule" not in out
    assert "sid:2000003;" not in (build_dir(out) / "suricata.rules").read_text()


def test_drop_never_turns_a_noalert_setter_into_a_silent_drop(ws: Path):  # noqa: F811
    run("profile", "create", "ips", "--query", "source:et")
    with_fake_engine(ws, "ips")
    run("profile", "exclusions", "ips")
    edit_profile_file(ws, "ips", modify=[{"kind": "file", "value": "emerging-malware.rules", "action": "drop"}])
    out = run("profile", "build", "ips")
    rules = enabled_rules((build_dir(out) / "suricata.rules").read_text())
    assert rules[2000002] == SETTER and rules[2000001].startswith("drop ")
    assert not [x for x in rules.values() if x.startswith("drop ") and "noalert" in x]


# --------------------------------------------------------------------------------------------------------------
# modify that breaks a rule, or removes a flowbit setter


@pytest.mark.parametrize("to", ['msg:"x\nalert', "a\rb", "x\x85y", "x y", "x\x00"])
def test_replacement_with_line_breaks_is_refused(to: str):
    with pytest.raises(OverrideError, match="line breaks"):
        normalise("modify", {"kind": "sid", "value": "1", "from": "msg:", "to": to})


def test_rewrites_that_break_rules_are_refused_per_rule(ws: Path, monkeypatch: pytest.MonkeyPatch):  # noqa: F811
    from suriharvest import validate

    seen: list[dict] = []

    def fake_checker(ws_, cfg, note):  # type: ignore[no-untyped-def]
        def check(todo: dict) -> dict:
            seen.append(todo)
            return {h: "unknown rule keyword 'foobarkw'" for h, (_, _, t) in todo.items() if "foobarkw" in t}

        return check

    monkeypatch.setattr(validate, "modified_checker", fake_checker)
    run("profile", "create", "m", "--query", "source:et", "--engine", "local")
    run("profile", "exclusions", "m")
    edit_profile_file(
        ws,
        "m",
        modify=[
            {"kind": "sid", "value": "2000001", "from": "http\\.uri;", "to": "http.uri; foobarkw;"},  # engine refuses
            {"kind": "sid", "value": "2000003", "from": 'msg:"', "to": 'msg:"\\n'},  # template newline: two lines
            {"kind": "sid", "value": "2000002", "from": "flowbits:set,ET\\.login; ", "to": ""},  # 2000003 needs it
            {"kind": "sid", "value": "2000004", "from": "/x", "to": "/y"},  # fine
        ],
    )
    out = run("profile", "build", "m")
    d = build_dir(out)
    text = (d / "suricata.rules").read_text()
    assert len(text.splitlines()) == 1 + len(enabled_rules(text))  # header + one line per rule
    rules = enabled_rules(text)
    assert "foobarkw" not in rules[2000001] and "suriharvest_modified" not in text.split("sid:2000001;")[0].splitlines()[-1]
    assert rules[2000002] == SETTER  # the setter stays: 2000003 checks ET.login
    assert rules[2000003] == CHECKER
    assert 'content:"/y"' in rules[2000004]
    assert "modify refused: et:1:2000001: the modified rule does not load (unknown rule keyword 'foobarkw')" in out
    assert "et:1:2000003: modify #2: the rewrite adds a line break" in out
    assert "modify refused: et:1:2000002: it removes the setter of flowbits:ET.login" in out
    assert "1 flowbits have no setter" in out  # only the fixture's orphan (never.set)
    man = {json.loads(x)["sid"]: json.loads(x) for x in (d / "manifest.jsonl").read_text().splitlines()}
    assert man[2000004].get("modified") and not man[2000001].get("modified") and not man[2000002].get("modified")
    assert "overrides: 1 rules modified" in out
    assert any("foobarkw" in t for todo in seen for _, _, t in todo.values())


def test_profile_without_a_working_engine_ships_the_original_rules(ws: Path, tmp_path: Path):  # noqa: F811
    """Fail-safe: a modify entry is applied only after the profile's engine validated the rewritten rule. Without
    an engine, or when it cannot run, the rule ships unmodified and the build says why."""
    run("profile", "create", "n", "--query", "source:et")
    run("profile", "exclusions", "n")
    edit_profile_file(ws, "n", modify=[{"kind": "sid", "value": "2000001", "from": "gate\\.php", "to": "gate2.php"}])
    out = run("profile", "build", "n")
    assert "not applied: the profile has no engine" in out
    prof = ws / "data" / "profiles" / "n"

    def built_rules() -> str:  # the newest build, through the LATEST pointer (no symlink on Windows)
        return (prof / (prof / "LATEST").read_text().strip() / "suricata.rules").read_text()

    built = prof / (prof / "LATEST").read_text().strip()
    text = (built / "suricata.rules").read_text()
    assert 'content:"/gate.php"' in text and "gate2.php" not in text and "suriharvest_modified" not in text
    # an engine that cannot run: same
    settings = ws / "suriharvest.yaml"
    settings.write_text(yaml.safe_dump({"engines": [{"name": "broken", "binary": str(tmp_path / "no-such-suricata")}]}))
    run("profile", "set", "n", "--engine", "broken")
    out = run("profile", "build", "n")
    assert "engine cannot run" in out
    text = built_rules()
    assert "gate2.php" not in text
    # with a working engine the rewrite is applied
    with_fake_engine(ws, "n")
    run("profile", "build", "n")
    assert "gate2.php" in built_rules()


# --------------------------------------------------------------------------------------------------------------
# the best flowbit setter cannot be used -> the next one


def test_next_flowbit_setter_is_used_when_the_best_one_is_not_allowed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root, a, b = tmp_path / "ws", tmp_path / "a", tmp_path / "b"
    write(a / "a.rules", SETTER, CHECKER)
    other = SETTER.replace('content:"/login"', 'content:"/signin"').replace("sid:2000002;", "sid:3000002;")
    write(b / "b.rules", other)
    root.mkdir()
    src = [
        {"name": "a", "type": "local", "url": str(a), "priority": 50, "licence": "MIT", "redistribute": "yes"},
        {"name": "b", "type": "local", "url": str(b), "priority": 10, "licence": "MIT", "redistribute": "no"},
    ]
    (root / "sources.yaml").write_text(yaml.safe_dump({"sources": src}))
    monkeypatch.setenv("SURIHARVEST_HOME", str(root))
    monkeypatch.chdir(root)
    run("doctor")
    run("sync")
    o = tmp_path / "o"
    out = run("export", "sid:2000003", "--out", str(o), "--redistributable-only")
    rules = enabled_rules((o / "suricata.rules").read_text())
    assert set(rules) == {2000002, 2000003}, out  # b's setter is preferred but may not be shared: a's is used
    assert "have no setter" not in out
    o2 = tmp_path / "o2"
    out = run("export", "sid:2000003", "--out", str(o2))
    assert set(enabled_rules((o2 / "suricata.rules").read_text())) == {3000002, 2000003}  # the best one when allowed


# --------------------------------------------------------------------------------------------------------------
# thresholds Suricata refuses


@pytest.mark.parametrize(
    ("entry", "msg"),
    [
        ({"filter": "threshold", "type": "limit", "track": "by_src", "count": 0, "seconds": 60}, "count must be"),
        ({"filter": "threshold", "type": "limit", "track": "by_src", "count": 1, "seconds": 0}, "seconds must be"),
        ({"filter": "event_filter", "type": "limit", "track": "by_src", "count": "²", "seconds": 1}, "count must be"),
        ({"filter": "event_filter", "type": "limit", "track": "by_src", "count": "١", "seconds": 1}, "count must be"),
        ({"filter": "threshold", "type": "limit", "track": "by_src", "count": 4294967296, "seconds": 1}, "count must be"),
        ({"filter": "threshold", "type": "limit", "track": "by_src", "count": True, "seconds": 1}, "count must be"),
        (
            {"filter": "rate_filter", "track": "by_src", "count": 1, "seconds": 1, "new_action": "drop", "timeout": 0},
            "timeout must be",
        ),
        ({"filter": "suppress", "track": "by_src", "ip": "!10.0.0.0/8"}, "negation"),
        ({"filter": "suppress", "track": "by_src", "ip": "[10.0.0.0/8,!10.1.0.0/16]"}, "negation"),
        ({"filter": "suppress", "track": "by_src", "ip": "$UNDEFINED_VAR"}, "default address variables"),
        ({"filter": "suppress", "track": "by_src", "ip": "$HTTP_PORTS"}, "default address variables"),
        ({"filter": "suppress", "track": "by_src", "ip": "[10.0.0.1,[10.0.0.2]]"}, "not an address"),
        ({"filter": "suppress", "track": "by_src", "ip": "10.0.0.1/33"}, "not an address"),
        ({"filter": "suppress", "track": "by_src", "ip": "１０.0.0.1"}, "not an address"),
        ({"filter": "suppress", "track": "by_src", "ip": "[10.0.0.1,]"}, "empty item"),
        # Suricata 7.0.3 "no addresses left after merging addresses and negated addresses"
        ({"filter": "suppress", "track": "by_src", "ip": "[$HOME_NET,$EXTERNAL_NET]"}, "cannot share a list"),
        ({"filter": "suppress", "track": "by_src", "ip": "[$EXTERNAL_NET,10.0.0.1]"}, "cannot share a list"),
        ({"filter": "suppress", "track": "by_src", "ip": "[$EXTERNAL_NET,$HTTP_SERVERS]"}, "cannot share a list"),
    ],
)
def test_thresholds_suricata_refuses_are_rejected(entry: dict, msg: str):
    with pytest.raises(OverrideError, match=msg):
        normalise("thresholds", {"kind": "sid", "value": "1", **entry})


def test_threshold_lists_are_written_without_spaces():
    e = normalise("thresholds", {"kind": "sid", "value": "1", "filter": "suppress", "track": "by_src", "ip": "[ $HOME_NET , 10.0.0.1 ]"})
    assert e["ip"] == "[$HOME_NET,10.0.0.1]"  # Suricata 7 fails on "10.0.0.2 " inside a list
    e = normalise(
        "thresholds",
        {"kind": "sid", "value": "1", "filter": "threshold", "type": "both", "track": "by_rule", "count": "5", "seconds": " 60"},
    )
    assert (e["count"], e["seconds"]) == (5, 60)


# --------------------------------------------------------------------------------------------------------------
# user regexes over hostile rule text


def test_user_regex_cost_is_bounded():
    rx = compile_user(r"ET.*trojan.*cnc")
    hostile = 'alert http any any -> any any (msg:"x"; content:"' + "ET " * 90_000 + '"; sid:1;)'
    t0 = time.monotonic()
    for _ in range(5):
        assert not rx.search(hostile)
    assert time.monotonic() - t0 < 5
    assert compile_user("needle").search("x" * (MAX_SCAN - 3) + "needle") is False  # beyond the cap: never matched
    assert compile_user("(a)\\1").search("xaa")  # RE2 cannot do back-references: Python's re on the capped text
    with pytest.raises(re.error):
        compile_user("[unclosed")


def test_hostile_long_rule_does_not_stall_a_build(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root, a = tmp_path / "ws", tmp_path / "a"
    big = 'alert http any any -> any any (msg:"big"; http.uri; content:"' + "ET " * 80_000 + '"; sid:4000001; rev:1;)'
    write(a / "a.rules", *[big.replace("4000001", str(4000001 + i)) for i in range(3)], CHECKER)
    root.mkdir()
    (root / "sources.yaml").write_text(yaml.safe_dump({"sources": [{"name": "a", "type": "local", "url": str(a), "licence": "MIT"}]}))
    monkeypatch.setenv("SURIHARVEST_HOME", str(root))
    monkeypatch.chdir(root)
    run("doctor")
    run("sync")
    run("profile", "create", "r", "--query", "source:a")
    t0 = time.monotonic()
    run("profile", "exclude", "r", "ET.*trojan.*cnc", "--kind", "rule_regex")
    out = run("profile", "build", "r")
    assert time.monotonic() - t0 < 20, out


# --------------------------------------------------------------------------------------------------------------
# on a real Suricata: the build must not drop a packet without an alert


def _pcap(path: Path, payload: bytes) -> None:
    def csum(b: bytes) -> int:
        b += b"\0" * (len(b) % 2)
        s = sum(struct.unpack(f"!{len(b) // 2}H", b))
        s = (s >> 16) + (s & 0xFFFF)
        return ~(s + (s >> 16)) & 0xFFFF

    udp = struct.pack("!HHHH", 40000, 9999, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    pkt = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00" + ip + udp
    path.write_bytes(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + struct.pack("<IIII", 1, 0, len(pkt), len(pkt)) + pkt)


@pytest.mark.engine
@pytest.mark.skipif(
    shutil.which("suricata") is None or bool(os.environ.get("SURIHARVEST_TEST_ENGINE_IMAGE")), reason="needs a local suricata"
)
def test_imported_drop_conf_produces_no_silent_drop_in_suricata(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    root, a = tmp_path / "ws", tmp_path / "a"
    setter = (
        'alert udp any any -> any any (msg:"set login bit"; content:"LOGIN"; flowbits:set,t.login; flowbits:noalert; sid:4100001; rev:1;)'
    )
    write(a / "rules" / "emerging-ips.rules", setter)
    root.mkdir()
    (root / "sources.yaml").write_text(yaml.safe_dump({"sources": [{"name": "a", "type": "local", "url": str(a), "licence": "MIT"}]}))
    monkeypatch.setenv("SURIHARVEST_HOME", str(root))
    monkeypatch.chdir(root)
    run("doctor")
    run("sync")
    run("profile", "create", "ips", "--query", "source:a")
    (tmp_path / "drop.conf").write_text("group:emerging-ips\n")
    run("profile", "import-conf", "ips", "--drop", str(tmp_path / "drop.conf"))
    d = build_dir(run("profile", "build", "ips"))
    _pcap(tmp_path / "t.pcap", b"LOGIN user")
    logs = tmp_path / "logs"
    logs.mkdir()
    cmd = ["suricata", "-r", str(tmp_path / "t.pcap"), "--simulate-ips", "-k", "none", "-S", str(d / "suricata.rules"), "-l", str(logs)]
    cmd += ["--set", "outputs.1.eve-log.enabled=yes"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
    assert r.returncode == 0, r.stderr[-2000:]
    events = [json.loads(x) for x in (logs / "eve.json").read_text().splitlines()]
    stats = [e["stats"] for e in events if e.get("event_type") == "stats"]
    alerts = [e for e in events if e.get("event_type") == "alert"]
    assert stats and "ips" in stats[-1], events  # without the counters the test would prove nothing
    blocked = stats[-1]["ips"]["blocked"]
    assert blocked <= len(alerts), (blocked, alerts)
    assert blocked == 0


@pytest.mark.engine
@pytest.mark.skipif(
    shutil.which("suricata") is None or bool(os.environ.get("SURIHARVEST_TEST_ENGINE_IMAGE")), reason="needs a local suricata"
)
def test_modify_with_an_unknown_keyword_is_refused_by_the_engine(ws: Path, tmp_path: Path):  # noqa: F811
    run("profile", "create", "e", "--query", "source:et", "--engine", "local")
    run("profile", "exclusions", "e")
    edit_profile_file(
        ws,
        "e",
        modify=[
            {"kind": "sid", "value": "2000001", "from": "http\\.uri;", "to": "http.uri; foobarkw;"},
            {"kind": "sid", "value": "2000004", "from": "/x", "to": "/y"},
        ],
    )
    out = run("profile", "build", "e")
    assert "modify refused: et:1:2000001: the modified rule does not load" in out and "foobarkw" in out
    d = build_dir(out)
    assert "foobarkw" not in (d / "suricata.rules").read_text()
    assert 'content:"/y"' in (d / "suricata.rules").read_text()
    r = subprocess.run(
        ["suricata", "-T", "-S", str(d / "suricata.rules"), "-l", str(tmp_path)], capture_output=True, text=True, timeout=300, check=False
    )
    assert r.returncode == 0, (r.stdout + r.stderr)[-2000:]
    cache = json.loads((ws / "data" / "modified-rules-validation.json").read_text())
    assert sorted(len(v) for v in cache.values()) == [2]  # both rewritten texts, one engine config
    assert "modify refused: et:1:2000001" in run("profile", "build", "e")  # second build: from the cache
