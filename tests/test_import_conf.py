"""suricata-update configuration import (profile import-conf): real-world style files, unsupported lines reported."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tarfile
import time
from pathlib import Path

import pytest
import yaml

from suriharvest.suricata_update_conf import convert, selectors
from tests.test_pipeline import run, with_fake_engine, ws  # noqa: F401 - fixture

DISABLE = """\
# disable.conf - rules we never want
# (comments and blank lines are ignored)

1:2000004
2000003,1:2000099
re:needs a bit nobody
group:b.rules
metadata: deployment perimeter
2:12345
filename:emerging-icmp.rules
re:[unclosed
"""
ENABLE = """\
# turn on the DNS rule ET ships commented out
2000005
"""
DROP = """\
# IPS: drop what is clearly malicious
re:MALWARE Foo
group:emerging-malware*.rules
1:9999999
"""
MODIFY = r"""
# modify.conf
2000003 "content:\"/admin\"" "content:\"/admin\"; nocase"
re:after\s+login "flowbits:isset,ET\.login;" "flowbits:isset,ET.login; flow:established;"
modifysid 2000002 "rev:(\d+)" | "rev:${1}"
2000002 "a" "\2"
2000002 "only-two-tokens"
"""


def write_confs(d: Path) -> Path:
    d.mkdir(parents=True, exist_ok=True)
    for name, text in (("disable.conf", DISABLE), ("enable.conf", ENABLE), ("drop.conf", DROP), ("modify.conf", MODIFY)):
        (d / name).write_text(text)
    return d


def test_selectors():
    assert selectors("1:2019401") == [("sid", "2019401")]
    assert selectors("2019401, 1:2019402") == [("sid", "2019401"), ("sid", "2019402")]
    assert selectors("re:heartbleed") == [("rule_regex", "heartbleed")]
    assert selectors("group:emerging-icmp.rules") == [("file", "emerging-icmp.rules")]
    assert selectors("metadata: deployment  perimeter") == [("metadata", "deployment perimeter")]


def test_convert_reports_every_unsupported_line(tmp_path: Path):
    d = write_confs(tmp_path / "conf")
    res = convert({n: d / n for n in ("enable.conf", "disable.conf", "drop.conf", "modify.conf")})
    assert res.counts == {"enable.conf": 1, "disable.conf": 5, "drop.conf": 3, "modify.conf": 3}
    bad = "\n".join(res.unsupported)
    assert len(res.unsupported) == 5, bad
    assert "disable.conf:9: 2:12345 -> gid 2" in bad
    assert "disable.conf:10: filename:emerging-icmp.rules -> filename: (a path inside the source archive) is not supported" in bad
    assert "disable.conf:11: re:[unclosed -> bad regular expression" in bad
    assert "modify.conf:6:" in bad and "back-reference" in bad
    assert "modify.conf:7:" in bad and "expected" in bad
    assert ("sid", "2000099", "disable.conf:5") in res.exclusions
    assert {"kind": "sid", "value": "2000002", "from": r"rev:(\d+)", "to": r"rev:\1", "reason": "modify.conf:5"} in res.modify


@pytest.mark.parametrize("encoding", ["utf-8-sig", "utf-16", "utf-16-be", "utf-8"])
def test_conf_files_saved_by_windows_editors_are_read(tmp_path: Path, encoding: str):
    """PowerShell 5.1 `>` writes UTF-16 (with a BOM), `Out-File -Encoding utf8` and Notepad UTF-8 with a BOM."""
    text = "# disable.conf\r\n9000002\r\n1:9000003 # noisy\r\nre:heartbleed\r\n"
    raw = text.encode(encoding)
    if encoding == "utf-16-be":
        raw = b"\xfe\xff" + raw  # the codec writes no BOM itself
    (tmp_path / "disable.conf").write_bytes(raw)
    res = convert({"disable.conf": tmp_path / "disable.conf"})
    assert res.unsupported == [] and res.counts == {"disable.conf": 3}
    assert ("sid", "9000002", "disable.conf:2") in res.exclusions and ("sid", "9000003", "disable.conf:3") in res.exclusions


def test_renamed_conf_files_are_named_in_reasons_and_messages(ws: Path, tmp_path: Path):  # noqa: F811
    """A sensor's `disable-sensor1.conf` is reported and stored under that name, not as `disable.conf`."""
    f = tmp_path / "disable-sensor1.conf"
    f.write_text("9000002\n2:12345\n")
    res = convert({"disable.conf": f})
    assert ("sid", "9000002", "disable-sensor1.conf:1") in res.exclusions
    assert res.unsupported and res.unsupported[0].startswith("disable-sensor1.conf:2: 2:12345")
    run("profile", "create", "s1", "--query", "source:et")
    out = run("profile", "import-conf", "s1", "--disable", str(f))
    assert "disable-sensor1.conf (as disable.conf): 1 line converted" in out
    assert "not imported: disable-sensor1.conf:2" in out and "disable.conf:" not in out
    saved = yaml.safe_load((ws / "exclusions" / "s1.yaml").read_text())
    assert any(e.get("reason") == "imported from disable-sensor1.conf:1" for e in saved["exclusions"])


def test_import_conf_into_a_profile_and_build(ws: Path, tmp_path: Path):  # noqa: F811
    run("profile", "create", "su", "--query", "source:et")
    with_fake_engine(ws, "su")
    d = write_confs(tmp_path / "etc-suricata")
    dry = run("profile", "import-conf", "su", str(d), "--dry-run")
    assert "5 line(s) not imported" in dry and "dry run" in dry
    assert (
        "modify" not in (yaml.safe_load((ws / "exclusions" / "su.yaml").read_text()) or {})
        if (ws / "exclusions" / "su.yaml").exists()
        else True
    )
    out = run("profile", "import-conf", "su", str(d))
    assert "not imported: disable.conf:9: 2:12345" in out
    saved = yaml.safe_load((ws / "exclusions" / "su.yaml").read_text())
    kinds = {(e["kind"], e["value"]) for e in saved["exclusions"]}
    assert {("sid", "2000004"), ("rule_regex", "needs a bit nobody"), ("file", "b.rules")} <= kinds
    assert saved["enable"] == [{"kind": "sid", "value": "2000005", "beats_exclusions": True, "reason": "enable.conf:2"}]
    b = run("profile", "build", "su")
    built = Path(b.split("-> ")[1].split("\n")[0].strip())
    rules = {int(x.split("sid:")[1].split(";")[0]): x for x in (built / "suricata.rules").read_text().splitlines() if "sid:" in x}
    assert 2000004 not in rules and 2000003 not in rules  # disable.conf
    assert rules[2000005].startswith("drop dns")  # enable.conf (shipped commented out), then drop.conf (group:)
    assert rules[2000001].startswith("drop http")  # drop.conf (re:MALWARE Foo)
    assert rules[2000002].startswith("alert http")  # a noalert flowbit setter: drop.conf leaves it (as suricata-update)
    excluded = [json.loads(x) for x in (built / "excluded.jsonl").read_text().splitlines()]
    assert any("imported from disable.conf:4" in e["reason"] for e in excluded)
    # importing again adds nothing new (entries are compared, exclusions are unique)
    again = run("profile", "import-conf", "su", "--disable", str(d / "disable.conf"), "--drop", str(d / "drop.conf"))
    assert "profile su: 0 new entries (0 exclusions, 0 enable, 0 modify)" in again and "already present" in again


def test_import_conf_brings_excluded_flowbit_setters_back_like_suricata_update(ws: Path, tmp_path: Path):  # noqa: F811
    """Suricata-update re-enables (noalert) a setter disable.conf turned off when an enabled rule checks
    its bit; an import-conf profile does the same and says which; `--flowbit-setters strict` keeps them out."""
    run("profile", "create", "su", "--query", "source:et")
    conf = tmp_path / "c"
    conf.mkdir()
    (conf / "disable.conf").write_text("2000002\n")  # the ET.login setter; 2000003 checks ET.login
    run("profile", "import-conf", "su", str(conf))
    out = run("profile", "build", "su")
    built = Path(out.split("-> ")[1].split("\n")[0].strip())
    rules = (built / "suricata.rules").read_text()
    assert "sid:2000002;" in rules and "sid:2000003;" in rules
    assert "1 excluded flowbit setter(s) kept, with noalert" in out and "et:1:2000002" in out
    assert not any(json.loads(x)["sid"] == 2000002 for x in (built / "excluded.jsonl").read_text().splitlines())
    run("profile", "set", "su", "--flowbit-setters", "strict")
    out = run("profile", "build", "su")
    rules = (Path(out.split("-> ")[1].split("\n")[0].strip()) / "suricata.rules").read_text()
    assert "sid:2000002;" not in rules
    assert "flowbits have no setter in this build: flowbits:ET.login" in " ".join(out.split())  # the bit is named


def test_noalert_is_inserted_like_suricata_update():
    from suriharvest.parser import add_noalert

    r = 'alert http any any -> any any (msg:"x"; flowbits:set,a; sid:5; rev:1;)'
    assert add_noalert(r) == 'alert http any any -> any any (msg:"x"; flowbits:set,a; noalert; sid:5; rev:1;)'
    assert (
        add_noalert('alert tcp any any -> any any (msg:"x";sid:5; rev:1;)')
        == 'alert tcp any any -> any any (msg:"x"; noalert; sid:5; rev:1;)'
    )


def test_noalert_goes_before_the_sid_option_not_into_a_value():
    from suriharvest.parser import ParseError, add_noalert

    # a "sid:1;" inside content (escaped ";") and inside a reference URL is not the sid option
    r = r'alert tcp any any -> any any (msg:"x"; content:"sid:1\;"; reference:url,example.com/a-sid:2; flowbits:set,a; sid:7; rev:1;)'
    out = add_noalert(r)
    assert out == r.replace("flowbits:set,a; sid:7;", "flowbits:set,a; noalert; sid:7;")
    assert r'content:"sid:1\;";' in out
    # "noalert;" inside a value does not count as the option; the real option or flowbits:noalert does
    r2 = r'alert tcp any any -> any any (msg:"noalert\; here"; flowbits:set,a; sid:8; rev:1;)'
    assert add_noalert(r2) == r2.replace("; sid:8;", "; noalert; sid:8;")
    for done in (
        'alert tcp any any -> any any (msg:"x"; flowbits:set,a; flowbits:noalert; sid:9; rev:1;)',
        'alert tcp any any -> any any (msg:"x"; flowbits:set,a; noalert; sid:9; rev:1;)',
    ):
        assert add_noalert(done) == done
    with pytest.raises(ParseError):
        add_noalert('alert tcp any any -> any any (msg:"x"; content:"sid:3;"; rev:1;)')


def test_five_thousand_sid_exclusions_stay_fast(ws: Path, tmp_path: Path):  # noqa: F811
    run("profile", "create", "big", "--query", "source:et")
    conf = tmp_path / "disable.conf"
    conf.write_text("".join(f"1:{3_000_000 + i}\n" for i in range(5000)) + "1:2000004\n")
    t0 = time.monotonic()
    run("profile", "import-conf", "big", "--disable", str(conf))
    t1 = time.monotonic()
    out = run("profile", "build", "big")
    t2 = time.monotonic()
    assert "excluded by" in out and t1 - t0 < 60 and t2 - t1 < 20, (t1 - t0, t2 - t1)


def test_suricata_update_variant_b_keeps_exclusions_for_sources_it_fetches_itself(ws: Path, tmp_path: Path):  # noqa: F811
    """et has no OISF name here (like a catalog entry without oisf_name): its rules go to suriharvest-local.rules,
    and suricata-update also fetches et/open by default. The profile's exclusions must still be in disable.conf."""
    run("profile", "create", "su", "--query", "source:et")
    run("profile", "exclude", "su", "2000004", "--kind", "sid")
    out_dir = tmp_path / "su"
    out = run("export", "--out", str(out_dir), "--format", "suricata-update", "--profile", "su")
    assert "ET Open is in suriharvest-local.rules" in out and "no suricata-update (OISF) name" in out
    disabled = {x.split()[0] for x in (out_dir / "disable.conf").read_text().splitlines() if x and not x.startswith("#")}
    assert "1:2000004" in disabled
    assert "disable-source et/open" in (out_dir / "README.txt").read_text()
    # simulated suricata-update merge: its own et/open copy + our local file, then disable.conf
    upstream = (ws.parent / "et" / "rules" / "emerging-malware.rules").read_text().splitlines()
    local = (out_dir / "suriharvest-local.rules").read_text().splitlines()
    enabled = [x for x in upstream + local if x.startswith("alert")]
    final = {int(x.split("sid:")[1].split(";")[0]) for x in enabled if f"1:{x.split('sid:')[1].split(';')[0]}" not in disabled}
    assert 2000004 not in final and 2000001 in final


@pytest.mark.skipif(shutil.which("suricata-update") is None, reason="suricata-update not installed")
def test_suricata_update_end_to_end_with_et_open_fetched_twice(ws: Path, tmp_path: Path):  # noqa: F811
    run("profile", "create", "su", "--query", "source:et")
    run("profile", "exclude", "su", "2000004", "--kind", "sid")
    su = tmp_path / "su"
    run("export", "--out", str(su), "--format", "suricata-update", "--profile", "su")
    up = tmp_path / "etopen.tar.gz"  # stands in for suricata-update's own et/open download
    with tarfile.open(up, "w:gz") as tf:
        tf.add(ws.parent / "et" / "rules", arcname="rules")
    d, o = tmp_path / "d", tmp_path / "o"
    cmd = ["suricata-update", "-D", str(d), "-o", str(o), "--url", up.as_uri(), "--local", str(su / "suriharvest-local.rules")]
    cmd += ["--disable-conf", str(su / "disable.conf"), "--enable-conf", str(su / "enable.conf"), "--no-test", "--no-reload"]
    cmd += ["--modify-conf", os.devnull, "--drop-conf", os.devnull]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=False)
    assert r.returncode == 0, r.stderr[-2000:]
    enabled = [x for x in (o / "suricata.rules").read_text().splitlines() if x.startswith("alert")]
    assert not any("sid:2000004;" in x for x in enabled)  # the exclusion holds although et/open was fetched too
    assert any("sid:2000001;" in x for x in enabled)
