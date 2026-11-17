"""Rule-key ownership across sources (a source cannot replace a publisher's rule with a higher rev), dataset rules in
merged files (names kept apart, files shipped with every written ruleset, file contents in content_id and in the
validation cache key), classtype definitions across sources, and dataset paths that must never be opened on the
build host. Offline: a scripted fake Suricata (tests/test_engine_offline.py); the same layout runs against a real
engine in tests/test_engine.py."""

from __future__ import annotations

import gzip
import io
import json
import tarfile
from pathlib import Path

import pytest
import yaml

from tests.test_engine_offline import fake_engine
from tests.test_pipeline import run, write

REAL = (
    'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE Lumma Stealer CnC Checkin"; flow:established,to_server; '
    'http.uri; content:"/api/lumma"; classtype:et-own-class; sid:2050001; rev:3;)'
)
SQUAT = REAL.replace('content:"/api/lumma"', 'content:"/api/lumma-never-matches-9f8e7d"').replace("rev:3;", "rev:99;")
ET_DS = 'alert dns any any -> any any (msg:"ET DNS bad domain list"; dns.query; dataset:isset,baddomains,type string,load datasets/bad.lst; sid:2000002; rev:1;)'
EVIL_DS = 'alert dns any any -> any any (msg:"evil domains"; dns.query; dataset:isset,baddomains,type string,load datasets/mine.lst; sid:9000003; rev:1;)'
MISSING_DS = 'alert dns any any -> any any (msg:"needs a file nobody ships"; dns.query; dataset:isset,gone,type string,load datasets/gone.lst; sid:9000004; rev:1;)'
ABS_DS = (
    'alert dns any any -> any any (msg:"absolute path"; dns.query; dataset:isset,host,type string,load /etc/hostname; sid:9000005; rev:1;)'
)


def _sources(tmp_path: Path, evil_redistribute: str = "yes") -> list[dict]:
    return [
        {
            "name": "et",
            "type": "local",
            "url": str(tmp_path / "et"),
            "priority": 10,
            "licence": "MIT",
            "copyright": "Copyright (c) 2026 Test Publisher",
            "sid_namespace": "et",
            "redistribute": "yes",
        },
        {
            "name": "aaa-evil",
            "type": "local",
            "url": str(tmp_path / "evil"),
            "priority": 80,
            "licence": "MIT",
            "copyright": "Copyright (c) 2026 Test Publisher",
            "redistribute": evil_redistribute,
        },
    ]


@pytest.fixture
def wsp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "ws"
    monkeypatch.setenv("SURIHARVEST_HOME", str(root))
    monkeypatch.chdir(tmp_path)
    run("init", str(root), "--engine", f"suricata-7={fake_engine(tmp_path, '7.0.17')}")
    write(tmp_path / "et" / "rules" / "emerging-malware.rules", REAL, ET_DS)
    write(tmp_path / "et" / "rules" / "datasets" / "bad.lst", "ZXZpbC5leGFtcGxl")
    write(tmp_path / "et" / "rules" / "classification.config", "config classification: et-own-class,ET own class,2")
    write(tmp_path / "evil" / "hunting.rules", SQUAT, EVIL_DS, MISSING_DS, ABS_DS)
    write(tmp_path / "evil" / "datasets" / "mine.lst", "bWluZS5leGFtcGxl")
    write(tmp_path / "evil" / "classification.config", "config classification: et-own-class,Hijacked by evil,1")
    (root / "sources.yaml").write_text(yaml.safe_dump({"sources": _sources(tmp_path)}))
    monkeypatch.chdir(root)
    run("update")
    return root


def _release(root: Path, out: Path, *args: str) -> dict:
    run("release", "build", str(out), "--engine", "suricata-7", "--build-epoch", "0", *args)
    return json.loads((out / "summary.json").read_text())


def _rules(text: str) -> list[str]:
    return [x for x in text.splitlines() if x and not x.startswith("#")]


# ---------------------------------------------------------------------------------------------------------------
# squatting a publisher's sid + msg with a higher rev


def test_squatter_with_higher_rev_does_not_replace_the_publisher_rule(wsp: Path, tmp_path: Path):
    out = tmp_path / "rel"
    _release(wsp, out)
    rules = _rules((out / "suricata-7.rules").read_text())
    real = [x for x in rules if 'content:"/api/lumma";' in x]
    squat = [x for x in rules if "lumma-never-matches" in x]
    assert len(real) == 1 and "sid:2050001;" in real[0]  # the publisher keeps its rule and its sid
    assert len(squat) == 1 and "sid:2050001;" not in squat[0]  # the other copy is a different rule: remapped
    collisions = json.loads((out / "collisions.json").read_text())
    c = next(x for x in collisions if x["sid"] == 2050001)
    assert c["source"] == "aaa-evil" and c["sid_kept_by"] == "et" and c["exported_sid"] != 2050001
    # profile builds follow the same rule
    run("profile", "create", "every", "--query", "")
    run("profile", "build", "every")
    d = max(p for p in (wsp / "data" / "profiles" / "every").iterdir() if p.name[:1].isdigit())  # build folders, not latest/LATEST
    text = (d / "suricata.rules").read_text()
    assert 'content:"/api/lumma"; classtype:et-own-class; sid:2050001;' in text


def test_non_redistributable_squatter_cannot_remove_the_rule_from_a_shared_release(wsp: Path, tmp_path: Path):
    (wsp / "sources.yaml").write_text(yaml.safe_dump({"sources": _sources(tmp_path, evil_redistribute="no")}))
    run("update")
    out = tmp_path / "rel"
    _release(wsp, out)  # redistributable-only by default
    text = (out / "suricata-7.rules").read_text()
    assert 'content:"/api/lumma"; classtype:et-own-class; sid:2050001;' in text
    assert (
        "lumma-never-matches" not in text
        and "aaa-evil" not in json.loads((out / "summary.json").read_text())["engines"]["suricata-7"]["by_source"]
    )


def test_squatter_cannot_take_the_sid_of_a_rule_the_owner_ships_disabled(wsp: Path, tmp_path: Path):
    """ET ships its rule commented out; a squatter's enabled copy with ET's sid and msg is alone in the
    et: key. It is never published under ET's sid and key."""
    f = tmp_path / "et" / "rules" / "emerging-malware.rules"
    f.write_text(f.read_text().replace(REAL, "# " + REAL))
    run("update")
    out = tmp_path / "rel"
    _release(wsp, out)
    text = (out / "suricata-7.rules").read_text()
    assert "lumma-never-matches" not in text
    assert not any(" sid:2050001;" in x for x in _rules(text))
    manifest = [json.loads(x) for x in gzip.decompress((out / "manifest.jsonl.gz").read_bytes()).splitlines()]
    assert not any(m.get("rule_key", "").startswith("et:") and m["source"] != "et" for m in manifest)
    # an exact mirror of ET's text from another source is still published (ET carried that text, even disabled)
    evil = tmp_path / "evil" / "hunting.rules"
    evil.write_text(evil.read_text().replace(SQUAT, REAL))
    from typer.testing import CliRunner

    from suriharvest.cli import app

    CliRunner().invoke(app, ["update"])  # the corpus gate flags the shrink (one logic fewer); the index is rebuilt
    out2 = tmp_path / "rel2"
    _release(wsp, out2, "--no-gates")
    assert 'content:"/api/lumma"; classtype:et-own-class; sid:2050001;' in (out2 / "suricata-7.rules").read_text()


def test_publisher_new_revision_still_replaces_the_old_one(wsp: Path, tmp_path: Path):
    f = tmp_path / "et" / "rules" / "emerging-malware.rules"
    f.write_text(
        f.read_text().replace(
            'content:"/api/lumma"; classtype:et-own-class; sid:2050001; rev:3;',
            'content:"/api/lumma/v2"; classtype:et-own-class; sid:2050001; rev:4;',
        )
    )
    run("update")
    out = tmp_path / "rel"
    _release(wsp, out)
    rules = _rules((out / "suricata-7.rules").read_text())
    assert any("/api/lumma/v2" in x and "sid:2050001;" in x for x in rules)
    assert not any('content:"/api/lumma";' in x for x in rules)  # rev 3 is an older revision of the same lineage


# ---------------------------------------------------------------------------------------------------------------
# dataset names, files shipped with every written ruleset, unsafe paths


def _ds_names(rules: list[str]) -> dict[int, str]:
    import re

    out = {}
    for x in rules:
        m = re.search(r"dataset:isset,([^,]+),type string,load ([^;]+);.*sid:(\d+);", x)
        if m:
            out[int(m.group(3))] = (m.group(1), m.group(2))
    return out


def test_same_dataset_name_in_two_sources_is_kept_apart_and_files_ship(wsp: Path, tmp_path: Path):
    out = tmp_path / "rel"
    summary = _release(wsp, out)
    rules = _rules((out / "suricata-7.rules").read_text())
    names = _ds_names(rules)
    assert names[2000002] == ("baddomains", "datasets/et/datasets/bad.lst")  # et: better priority keeps the name
    evil_name, evil_file = names[9000003]
    assert evil_name.startswith("baddomains-") and evil_file == "datasets/aaa-evil/datasets/mine.lst"
    eng = summary["engines"]["suricata-7"]
    assert [r["dataset"] for r in eng["dataset_renames"]] == ["baddomains"]
    assert 9000004 not in names  # its file is missing: it never loaded, so it is not published
    assert 9000005 not in names  # absolute path: never validated as loading
    with tarfile.open(out / "suriharvest-7.tar.gz") as tf:
        got = set(tf.getnames())
    assert {"rules/datasets/et/datasets/bad.lst", "rules/datasets/aaa-evil/datasets/mine.lst"} <= got


def test_absolute_dataset_path_is_not_validated_on_the_build_host(wsp: Path):
    import sqlite3

    c = sqlite3.connect(wsp / "data" / "suriharvest.db")
    rows = c.execute(
        "select v.status, v.category from validation_results v join rule_versions r on r.content_hash = v.content_hash where r.sid = 9000005"
    ).fetchall()
    assert rows == [("error", "unsafe_path")]


def test_profile_build_export_and_feed_ship_dataset_files(wsp: Path, tmp_path: Path):
    run("profile", "create", "every", "--query", "")
    run("profile", "build", "every")
    d = max(p for p in (wsp / "data" / "profiles" / "every").iterdir() if p.name[:1].isdigit())  # build folders, not latest/LATEST
    for base in (d, d / "by-source"):
        assert (base / "datasets" / "et" / "datasets" / "bad.lst").read_text() == "ZXZpbC5leGFtcGxl\n"
        assert (base / "datasets" / "aaa-evil" / "datasets" / "mine.lst").is_file()
    names = _ds_names(_rules((d / "suricata.rules").read_text()))
    assert names[2000002][1] == "datasets/et/datasets/bad.lst" and names[9000003][0] != "baddomains"
    excluded = {json.loads(x)["sid"]: json.loads(x)["reason"] for x in (d / "excluded.jsonl").read_text().splitlines()}
    assert "not shipped" in excluded[9000004]
    # export: same layout
    out = tmp_path / "exp"
    text = run("export", "--out", str(out), "--profile", "every", "--remap-colliding-sids")
    assert "left out: 1 dataset rules" in text or "left out: 2 dataset rules" in text
    assert (out / "datasets" / "aaa-evil" / "datasets" / "mine.lst").is_file()
    assert "load datasets/et/datasets/bad.lst;" in (out / "suricata.rules").read_text()
    # the web feed: rules + their files where the relative paths point
    from fastapi.testclient import TestClient

    from suriharvest.config import Workspace
    from suriharvest.web.app import create_app

    client = TestClient(create_app(Workspace(wsp), allowed_hosts={"testserver"}))
    r = client.get("/feed/every/all.tar.gz")
    assert r.status_code == 200, r.text
    with tarfile.open(fileobj=io.BytesIO(r.content)) as tf:
        names_in = set(tf.getnames())
        rules = tf.extractfile("rules/suricata.rules").read().decode()  # type: ignore[union-attr]
    assert "rules/datasets/et/datasets/bad.lst" in names_in and "load datasets/et/datasets/bad.lst;" in rules
    # a single .rules download cannot carry files: dataset rules are left out with a note
    r = client.get("/export/download", params={"profile": "every", "format": "rules"})
    assert r.status_code == 200, r.text
    assert "dataset:" not in "\n".join(_rules(r.text)) and "left out of this single file" in r.text


# ---------------------------------------------------------------------------------------------------------------
# dataset file contents in content_id and in the validation cache key


def test_dataset_file_change_changes_content_id_and_revalidates(wsp: Path, tmp_path: Path):
    import sqlite3

    a = _release(wsp, tmp_path / "a")["content_id"]
    c = sqlite3.connect(wsp / "data" / "suriharvest.db")
    q = "select count(*) from validation_results v join rule_versions r on r.content_hash = v.content_hash where r.sid = 2000002"
    before = c.execute(q).fetchone()[0]
    write(tmp_path / "et" / "rules" / "datasets" / "bad.lst", "ZXZpbC5leGFtcGxl", "bW9yZS5leGFtcGxl")
    run("update")
    assert c.execute(q).fetchone()[0] == before + 1  # checked again with the new file
    b = _release(wsp, tmp_path / "b")["content_id"]
    assert a != b
    with gzip.open(tmp_path / "b" / "manifest.jsonl.gz") as fh:
        assert fh.read()  # still a valid manifest


# ---------------------------------------------------------------------------------------------------------------
# classtype redefinition across sources


def test_lower_priority_source_cannot_redefine_a_classtype(wsp: Path, tmp_path: Path):
    out = tmp_path / "rel"
    summary = _release(wsp, out)
    with tarfile.open(out / "suriharvest-7.tar.gz") as tf:
        cls = tf.extractfile("rules/classification.config").read().decode()  # type: ignore[union-attr]
    assert "config classification: et-own-class,ET own class,2" in cls and "Hijacked" not in cls
    conflicts = summary["engines"]["suricata-7"]["classtype_conflicts"]
    assert conflicts == [
        {
            "classtype": "et-own-class",
            "kept": "et",
            "kept_definition": "ET own class,2",
            "ignored": "aaa-evil",
            "ignored_definition": "Hijacked by evil,1",
        }
    ]


@pytest.mark.parametrize(
    "opt",
    [
        "dataset:isset,up,type string,LOAD /etc/hostname",  # uppercase keyword
        "DataSet:isset,up,type string,Load ../../../etc/hostname",  # uppercase option name, ".." path
        "dataset:set,up,type string,Save /tmp/suriharvest-must-not-write.lst",  # writes on the build host
        "datarep:up,>,5,type string,STATE /var/tmp/x.csv",
    ],
)
def test_unsafe_dataset_path_gate_reads_the_rule_text(wsp: Path, tmp_path: Path, opt: str):
    """The gate must not depend on the stored file list (case-sensitive extraction once missed these)."""
    import sqlite3

    from suriharvest.identity import _files
    from suriharvest.parser import parse_rule

    r = f'alert dns any any -> any any (msg:"unsafe variant"; dns.query; {opt}; sid:9000077; rev:1;)'
    assert _files(parse_rule(r))  # extraction now sees it as well
    with (tmp_path / "evil" / "hunting.rules").open("a") as fh:
        fh.write(r + "\n")
    run("update")
    c = sqlite3.connect(wsp / "data" / "suriharvest.db")
    rows = c.execute(
        "select v.status, v.category from validation_results v join rule_versions r on r.content_hash = v.content_hash where r.sid = 9000077"
    ).fetchall()
    assert rows == [("error", "unsafe_path")]
    assert not Path("/tmp/suriharvest-must-not-write.lst").exists()
    out = tmp_path / "rel"
    _release(wsp, out)
    assert "9000077" not in (out / "suricata-7.rules").read_text()


def test_unsafe_gate_does_not_need_the_stored_file_list(wsp: Path):
    """A version whose stored `files` is empty (older ingest) is still gated on its text."""
    import sqlite3

    c = sqlite3.connect(wsp / "data" / "suriharvest.db")
    c.execute("update rule_versions set files = '[]' where sid = 9000005")
    c.execute("delete from validation_results")
    c.commit()
    run("validate")
    rows = c.execute(
        "select v.status, v.category from validation_results v join rule_versions r on r.content_hash = v.content_hash where r.sid = 9000005"
    ).fetchall()
    assert rows == [("error", "unsafe_path")]


def test_release_retires_sid_map_rows_of_rules_gone_for_two_releases(wsp: Path, tmp_path: Path):
    """Rows of rules that left the corpus are retired once neither the new release
    nor the previous one publishes them; the nightly check accepts it with the manifest."""
    from suriharvest import sidmap_check

    smap = wsp / "state" / "sid-map.tsv"
    epoch = ["--build-epoch", "1763100000", "--no-gates"]
    _release(wsp, tmp_path / "r0", *epoch)
    m0 = smap.read_text()
    assert "lumma-never" not in m0 and len([x for x in m0.splitlines() if not x.startswith("#")]) == 2
    evil = tmp_path / "evil" / "hunting.rules"
    evil.write_text(evil.read_text().replace(SQUAT + "\n", ""))
    from typer.testing import CliRunner

    from suriharvest.cli import app

    CliRunner().invoke(app, ["update"])  # the corpus gate flags the shrink
    s1 = _release(wsp, tmp_path / "r1", *epoch, "--previous", str(tmp_path / "r0"))
    assert s1["sid_map_retired"] == 0 and smap.read_text() == m0  # still in the previous release
    s2 = _release(wsp, tmp_path / "r2", *epoch, "--previous", str(tmp_path / "r1"))
    m2 = smap.read_text()
    assert s2["sid_map_retired"] == 1 and len([x for x in m2.splitlines() if not x.startswith("#")]) == 1
    manifest = gzip.decompress((tmp_path / "r2" / "manifest.jsonl.gz").read_bytes()).decode()
    previous = gzip.decompress((tmp_path / "r1" / "manifest.jsonl.gz").read_bytes()).decode()
    rules = [p.read_text() for p in (tmp_path / "r2").glob("*.rules")]
    assert sidmap_check.check(m0, m2, manifest, previous, rules) == []
    assert sidmap_check.check(m0, m2, manifest)  # retirement without the previous manifest is refused
    assert "# floor=" in m2
