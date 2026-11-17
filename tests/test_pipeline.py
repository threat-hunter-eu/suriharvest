"""End-to-end on local sources (offline): sync -> ingest -> index -> search/show -> triage -> export."""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from suriharvest.cli import app

runner = CliRunner()

ET_V3 = (
    'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE Foo CnC Checkin"; flow:established,to_server; '
    'http.uri; content:"/gate.php"; http.user_agent; content:"FooBot"; sid:2000001; rev:3;)'
)
ET_V4 = (
    'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE Foo CnC Checkin"; flow:established,to_server; '
    'http.uri; content:"/gate.php"; http.user_agent; content:"FooBot/2"; sid:2000001; rev:4;)'
)
SETTER = 'alert http any any -> any any (msg:"ET INFO set bit"; http.uri; content:"/login"; flowbits:set,ET.login; flowbits:noalert; sid:2000002; rev:1;)'
CHECKER = (
    'alert http any any -> any any (msg:"ET INFO after login"; flowbits:isset,ET.login; http.uri; content:"/admin"; sid:2000003; rev:1;)'
)
ORPHAN = (
    'alert http any any -> any any (msg:"needs a bit nobody sets"; flowbits:isset,never.set; http.uri; content:"/x"; sid:2000004; rev:1;)'
)
DISABLED = '# alert dns any any -> any any (msg:"ET DNS evil"; dns.query; content:"evil.example"; nocase; sid:2000005; rev:1;)'
LOCAL_A = 'alert tcp any any -> any 4444 (msg:"repo A shell"; content:"meterpreter"; sid:1000001; rev:1;)'
LOCAL_B = 'alert udp any any -> any 53 (msg:"repo B something else"; content:"|00 01|"; sid:1000001; rev:1;)'
LOCAL_B2 = 'alert icmp any any -> any any (msg:"repo B unrelated ping"; itype:8; content:"PINGME"; sid:1000001; rev:2;)'
LEGACY_COPY = 'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"copy of foo"; flow:established,to_server; content:"/gate.php"; http_uri; content:"FooBot"; http_user_agent; sid:9000001; rev:1;)'


def write(p: Path, *lines: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def run(*args: str) -> str:
    r = runner.invoke(app, list(args), catch_exceptions=False)
    assert r.exit_code == 0, r.output
    return r.output


@pytest.fixture
def ws(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "ws"
    et, a, b = tmp_path / "et", tmp_path / "repoA", tmp_path / "repoB"
    write(et / "rules" / "emerging-malware.rules", "# ET header comment", ET_V3, SETTER, CHECKER, ORPHAN, DISABLED)
    write(a / "local.rules", LOCAL_A, ET_V3)  # carries an exact ET copy -> mirror
    write(b / "rules" / "b.rules", LOCAL_B, LOCAL_B2, LEGACY_COPY, "alert tcp any any -> (broken; sid:5;)")
    root.mkdir()
    sources = {
        "sources": [
            {
                "name": "et",
                "type": "local",
                "url": str(et),
                "priority": 10,
                "licence": "MIT",
                "copyright": "Copyright (c) 2026 Test Publisher",
                "sid_namespace": "et",
            },
            {"name": "repoA", "type": "local", "url": str(a), "priority": 50, "licence": "MIT", "copyright": "Copyright (c) 2026 Repo A"},
            {
                "name": "repoB",
                "type": "local",
                "url": str(b),
                "priority": 50,
                "licence": "GPL-3.0",
                "copyright": "Copyright (c) 2026 Repo B",
            },
        ]
    }
    (root / "sources.yaml").write_text(yaml.safe_dump(sources))
    monkeypatch.setenv("SURIHARVEST_HOME", str(root))
    monkeypatch.chdir(root)
    run("doctor")
    run("sync")
    return root


def db(root: Path) -> sqlite3.Connection:
    return sqlite3.connect(root / "data" / "suriharvest.db")


def group(c: sqlite3.Connection, sid: int, source: str | None = None) -> dict:
    c.row_factory = sqlite3.Row
    q = "select * from logic_groups where sid = ?" + (" and canonical_source = ?" if source else "")
    rows = c.execute(q, (sid, source) if source else (sid,)).fetchall()
    assert len(rows) == 1, rows
    return dict(rows[0])


def test_counts_mirror_and_quarantine(ws: Path):
    c = db(ws)
    g = group(c, 2000001)
    assert json.loads(g["sources"]) == ["et", "repoA"]
    assert g["n_sources"] == 1  # repoA carries an identical copy: a mirror, not an independent source
    assert g["canonical_source"] == "et"
    assert c.execute("select count(*) from quarantine where present").fetchone()[0] == 1
    off = group(c, 2000005)
    assert off["enabled_anywhere"] == 0 and off["is_ioc"] == 1


def test_same_sid_in_two_repos_is_not_a_family(ws: Path):
    c = db(ws)
    a = group(c, 1000001, "repoA")
    assert a["rule_key"] == "repoA:1:1000001"
    assert a["family_size"] == 1


def test_ambiguous_sid_inside_one_repo(ws: Path):
    c = db(ws)
    amb = c.execute("select ambiguous, n_clusters from rule_keys where rule_key = 'repoB:1:1000001'").fetchone()
    assert amb == (1, 2)


def test_legacy_copy_joins_family_by_semantic_hash(ws: Path):
    c = db(ws)
    et, copy = group(c, 2000001), group(c, 9000001)
    assert et["logic_hash"] != copy["logic_hash"]
    assert et["semantic_hash"] == copy["semantic_hash"]
    assert et["family_id"] == copy["family_id"]


def test_new_rev_joins_family_and_incremental_sync(ws: Path, tmp_path: Path):
    f = tmp_path / "et" / "rules" / "emerging-malware.rules"
    f.write_text(f.read_text().replace(ET_V3, ET_V4))
    out = run("sync")
    assert "et: +0 ~1 -0 files" in out
    assert "repoA: unchanged" in out
    c = db(ws)
    # repoA still carries rev 3, et now rev 4: same rule key cluster -> one family
    rows = c.execute("select rev, family_id, canonical_source from logic_groups where sid = 2000001 order by rev").fetchall()
    assert [r[0] for r in rows] == [3, 4]
    assert rows[0][1] == rows[1][1]
    assert rows[0][2] == "repoA"
    # nothing deleted: the rev 3 version still exists, its et occurrence is no longer present
    assert (
        c.execute(
            "select count(*) from occurrences o join rule_versions v on v.id=o.version_id where v.rev=3 and not o.present"
        ).fetchone()[0]
        == 1
    )


def test_search_show_triage(ws: Path):
    out = run("search", "gate.php", "--per-logic", "--json")
    data = json.loads(out)
    assert {r["sid"] for r in data["results"]} == {2000001, 9000001}
    assert "ET MALWARE Foo" in run("show", "2000001")
    lh = data["results"][0]["logic_hash"]
    run("triage", lh[:12], "drop")
    data = json.loads(run("search", "gate.php", "--per-logic", "--json"))
    assert lh not in {r["logic_hash"] for r in data["results"]}
    # verdicts survive a rebuild (user data)
    run("index")
    data = json.loads(run("search", "verdict:drop", "--per-logic", "--json"))
    assert [r["logic_hash"] for r in data["results"]] == [lh]


def test_export_adds_setters_and_refuses_sid_collisions(ws: Path, tmp_path: Path):
    out_dir = tmp_path / "out"
    out = run("export", "sid:2000003", "--out", str(out_dir), "--unit", "logic")
    text = (out_dir / "suricata.rules").read_text()
    assert "sid:2000003" in text and "sid:2000002" in text  # setter added
    assert "1 flowbit setters added" in out
    run("export", "sid:2000004", "--out", str(out_dir))
    # repoB's two 1000001 rules collide
    r = runner.invoke(app, ["export", "source:repoB", "--out", str(out_dir), "--unit", "logic"])
    assert r.exit_code == 2 and "1:1000001" in r.output
    manifest = [json.loads(line) for line in (out_dir / "manifest.jsonl").read_text().splitlines()]
    assert manifest and all("licence" in m for m in manifest)


def test_schema_guard(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    (tmp_path / "sources.yaml").write_text("sources: []\n")
    monkeypatch.setenv("SURIHARVEST_HOME", str(tmp_path))
    r = runner.invoke(app, ["search", "x"])
    assert r.exit_code == 2 and "doctor" in r.output


def test_git_source_incremental(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    import subprocess

    repo = tmp_path / "upstream"
    write(repo / "rules" / "a.rules", LOCAL_A)
    write(repo / "README.md", "not rules")
    git = ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t"]
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run([*git, "add", "."], check=True)
    subprocess.run([*git, "commit", "-qm", "one"], check=True)
    root = tmp_path / "ws"
    root.mkdir()
    (root / "sources.yaml").write_text(
        yaml.safe_dump({"sources": [{"name": "up", "type": "git", "url": f"file://{repo}", "licence": "MIT"}]})
    )
    monkeypatch.setenv("SURIHARVEST_HOME", str(root))
    run("doctor")
    assert "+1 ~0 -0 files" in run("sync")
    assert not (root / "corpus" / "up" / "README.md").exists()  # only rule files are kept
    write(repo / "rules" / "b.rules", LOCAL_B)
    subprocess.run([*git, "add", "."], check=True)
    subprocess.run([*git, "commit", "-qm", "two"], check=True)
    out = run("sync")
    assert "+1 ~0 -0 files; 1 rules read" in out
    assert "unchanged" in run("sync")


def test_update_gates_and_accept(ws: Path, tmp_path: Path):
    first = runner.invoke(app, ["update", "--no-validate"])
    assert first.exit_code == 0, first.output
    assert "passed" in first.output and "no previous passed run" in first.output
    # ET loses most of its rules: the unique-logic gate must fail
    write(tmp_path / "et" / "rules" / "emerging-malware.rules", ET_V3)
    second = runner.invoke(app, ["update", "--no-validate"])
    assert second.exit_code == 1, second.output
    assert "fail" in second.output and "unique logic" in second.output
    report = run("runs", "show", "latest")
    assert "## What changed" in report and "Rules that left the corpus" in report
    assert "failed" in run("runs", "list")
    # a failed run is not the baseline: the next update still compares with run 1 and fails again
    assert runner.invoke(app, ["update", "--no-validate"]).exit_code == 1
    run("runs", "accept", "latest")
    third = runner.invoke(app, ["update", "--no-validate"])
    assert third.exit_code == 0, third.output


def test_run_reports_move_to_reports_runs(ws: Path):
    """Reports are written to reports/runs/<stamp>.md and .json (as in sigharvest); a workspace that still has
    reports/update-*.md keeps reading them, and the next update moves them (and the run rows) to reports/runs."""
    run("update", "--no-validate")
    runs = ws / "reports" / "runs"
    (md,) = runs.glob("*.md")
    assert re.fullmatch(r"\d{8}T\d{6}Z", md.stem) and md.with_suffix(".json").is_file()
    # put it back where an older suriharvest wrote it
    legacy = ws / "reports" / f"update-{md.stem[:8]}-{md.stem[9:15]}-1.md"
    md.rename(legacy)
    md.with_suffix(".json").rename(legacy.with_suffix(".json"))
    c = db(ws)
    c.execute("update update_runs set report_path = ? where id = 1", (str(legacy),))
    c.commit()
    assert "## Steps" in run("runs", "show", "1")  # read from the old place
    run("update", "--no-validate")
    assert not list((ws / "reports").glob("update-*"))
    moved = runs / f"{md.stem}-1.md"
    assert moved.is_file() and moved.with_suffix(".json").is_file()
    assert db(ws).execute("select report_path from update_runs where id = 1").fetchone()[0] == str(moved)
    assert "## Steps" in run("runs", "show", "1") and "## Steps" in run("runs", "show", "latest")
    assert len(list(runs.glob("*.md"))) == 2


def test_disabled_source_leaves_index(ws: Path):
    run("sources", "disable", "repoA")
    run("sync")
    c = db(ws)
    assert c.execute("select count(*) from logic_groups where sources like '%repoA%'").fetchone()[0] == 0


def test_export_ioc_datasets(ws: Path, tmp_path: Path):
    import base64

    out_dir = tmp_path / "ds"
    out = run(
        "export",
        str(out_dir),
        "--query",
        "source:et",
        "--unit",
        "logic",
        "--iocs-as-datasets",
        "--sid-base",
        "9100000",
        "--include-disabled",
    )
    assert "1 rules replaced by 1 dataset rules" in out
    lst = (out_dir / "datasets" / "suriharvest-dns-query.lst").read_text().split()
    assert [base64.b64decode(x).decode() for x in lst] == ["evil.example"]
    rule = (out_dir / "datasets.rules").read_text()
    assert "dns.query; to_lowercase; dataset:isset,suriharvest-dns-query,type string,load datasets/suriharvest-dns-query.lst; " in rule
    assert "sid:9100000" in rule
    assert "evil.example" not in (out_dir / "suricata.rules").read_text()
    mapping = [json.loads(x) for x in (out_dir / "datasets" / "iocs.jsonl").read_text().splitlines()]
    assert mapping[0]["rules"][0]["sid"] == 2000005


def test_export_suricata_update(ws: Path, tmp_path: Path):
    # pretend "et" came from the OISF index: suricata-update fetches it, so only verdicts are exported for it
    data = yaml.safe_load((ws / "sources.yaml").read_text())
    data["sources"][0]["oisf_name"] = "et/open"
    (ws / "sources.yaml").write_text(yaml.safe_dump(data))
    run("triage", "et:1:2000005", "keep", "--scope", "rule")  # disabled upstream -> enable.conf
    run("triage", "et:1:2000004", "drop", "--scope", "rule")  # -> disable.conf
    run("triage", "repoB", "drop", "--scope", "source")  # its two sid 1000001 rules would collide
    out_dir = tmp_path / "su"
    run("export", "--out", str(out_dir), "--format", "suricata-update", "--unit", "logic")
    assert (out_dir / "enable.conf").read_text().count("1:2000005") == 1
    assert "1:2000004" in (out_dir / "disable.conf").read_text()
    local = (out_dir / "suriharvest-local.rules").read_text()
    assert "sid:2000001" not in local  # et's rules are left to suricata-update
    assert "sid:1000001" in local
    readme = (out_dir / "README.txt").read_text()
    assert "--enable-conf enable.conf" in readme and "et (suricata-update name et/open)" in readme


def test_same_indicator_joins_family_and_near_duplicates(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    a, b = tmp_path / "a", tmp_path / "b"
    write(
        a / "a.rules",
        'alert dns $HOME_NET any -> any any (msg:"ET MALWARE Foo domain"; dns.query; bsize:15; content:"print-vexer.biz"; nocase; sid:2000100; rev:1;)',
        'alert http $HOME_NET any -> any any (msg:"ET MALWARE Foo checkin"; flow:established,to_server; http.method; content:"POST"; '
        'http.uri; content:"/api/v1/gate"; http.host; content:"upd.example"; http.header; content:"X-Foo-Id|3a|"; '
        'http.user_agent; content:"FooAgent/1.0"; sid:2000101; rev:1;)',
    )
    write(
        b / "b.rules",
        'alert dns any any -> any any (msg:"feed: print-vexer.biz"; flow:to_server, stateless; dns_query; content:"print-vexer.biz"; nocase; sid:3000100; rev:1;)',
        'alert http any any -> any any (msg:"feed: Foo checkin"; flow:established,to_server; http.method; content:"POST"; '
        'http.uri; content:"/api/v1/gate"; http.host; content:"upd.example"; http.header; content:"X-Foo-Id|3a|"; '
        'http.user_agent; content:"FooAgent/2.0"; sid:3000101; rev:1;)',
    )
    root = tmp_path / "ws"
    root.mkdir()
    (root / "sources.yaml").write_text(
        yaml.safe_dump(
            {"sources": [{"name": "a", "type": "local", "url": str(a), "priority": 10}, {"name": "b", "type": "local", "url": str(b)}]}
        )
    )
    monkeypatch.setenv("SURIHARVEST_HOME", str(root))
    run("doctor")
    run("sync")
    c = db(root)
    fam = c.execute("select family_id, indicator_groups from logic_groups where sid in (2000100, 3000100)").fetchall()
    assert fam[0] == fam[1] and fam[0][1] == 2  # same indicator, same route -> one family
    near = c.execute("select a, b, jaccard from near_duplicates").fetchall()
    assert len(near) == 1 and near[0][2] >= 0.6  # 4 of 6 contents shared (user agent differs): similar, not merged
    fams = c.execute("select count(distinct family_id) from logic_groups where sid in (2000101, 3000101)").fetchone()[0]
    assert fams == 2


def test_export_remaps_colliding_sids(ws: Path, tmp_path: Path):
    out_dir = tmp_path / "remap"
    out = run("export", "source:repoB", "--out", str(out_dir), "--unit", "logic", "--remap-colliding-sids", "--remap-base", "9000000")
    assert "1 rules shared a sid" in out
    text = (out_dir / "suricata.rules").read_text()
    assert text.count("sid:1000001;") == 1 and text.count("sid:9000000;") == 1
    m = [json.loads(x) for x in (out_dir / "manifest.jsonl").read_text().splitlines()]
    assert sorted(x["exported_sid"] for x in m if x["sid"] == 1000001) == [1000001, 9000000]


def test_namespace_comes_from_the_sid_allocation_table(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    a = tmp_path / "vendor"
    tgreen = 'alert http any any -> any any (msg:"TGI HUNT odd agent"; http.user_agent; content:"odd"; sid:2610001; rev:1;)'
    not_et = 'alert http any any -> any any (msg:"local thing in the ET range"; http.uri; content:"/zz"; sid:2050000; rev:1;)'
    write(a / "bundle.rules", ET_V3, tgreen, not_et)
    root = tmp_path / "ws"
    root.mkdir()
    (root / "sources.yaml").write_text(yaml.safe_dump({"sources": [{"name": "vendor", "type": "local", "url": str(a), "priority": 5}]}))
    monkeypatch.setenv("SURIHARVEST_HOME", str(root))
    run("doctor")
    run("sync")
    keys = {r[0] for r in db(root).execute("select rule_key from logic_groups")}
    # ET name + ET range -> et; tgreen's allocated range (inside 2M-3M) -> tgreen; ET range without ET name -> the source
    assert keys == {"et:1:2000001", "tgreen:1:2610001", "vendor:1:2050000"}


def test_joined_and_split_spellings_and_one_cve_answer(ws: Path, tmp_path: Path):
    write(
        tmp_path / "et" / "rules" / "emerging-extra.rules",
        'alert http any any -> any any (msg:"ET MALWARE Cobalt Strike Beacon"; http.uri; content:"/cs1"; sid:2000201; rev:1;)',
        'alert http any any -> any any (msg:"ET MALWARE CobaltStrike Stager"; http.uri; content:"/cs2"; sid:2000202; rev:1;)',
        'alert http any any -> any any (msg:"ET EXPLOIT Log4j CVE-2021-44228 attempt"; http.uri; content:"jndi"; sid:2000203; rev:1;)',
        'alert http any any -> any any (msg:"ET EXPLOIT log4shell"; http.uri; content:"jndi2"; reference:cve,2021-44228; sid:2000204; rev:1;)',
    )
    run("sync")

    def sids(q: str) -> set[int]:
        return {r["sid"] for r in json.loads(run("search", q, "--per-logic", "--json"))["results"]}

    assert sids("cobaltstrike") == sids("cobalt strike") == {2000201, 2000202}
    assert sids("CVE-2021-44228") == sids("cve:CVE-2021-44228") == {2000203, 2000204}


def test_unusable_best_setter_falls_back_to_the_next_one(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The best-ranked setter of a bit may not be shipped (redistribute: no); the next setter that
    can be shipped is added instead, and a bit without any usable setter is reported."""
    root = tmp_path / "ws"
    a, b = tmp_path / "a", tmp_path / "b"
    setter_a = SETTER.replace('content:"/login"', 'content:"/login-a"').replace("sid:2000002", "sid:9100002")
    setter_b = SETTER.replace('content:"/login"', 'content:"/login-b"').replace("sid:2000002", "sid:9200002")
    checker = CHECKER.replace("sid:2000003", "sid:9100003")
    write(a / "a.rules", checker, setter_a)
    write(b / "b.rules", setter_b)
    root.mkdir()
    sources = [
        {
            "name": "a",
            "type": "local",
            "url": str(a),
            "priority": 50,
            "licence": "MIT",
            "copyright": "Copyright (c) 2026 Test Publisher",
            "redistribute": "yes",
        },
        {
            "name": "b",
            "type": "local",
            "url": str(b),
            "priority": 10,
            "licence": "MIT",
            "copyright": "Copyright (c) 2026 Test Publisher",
            "redistribute": "no",
        },
    ]
    (root / "sources.yaml").write_text(yaml.safe_dump({"sources": sources}))
    monkeypatch.setenv("SURIHARVEST_HOME", str(root))
    monkeypatch.chdir(root)
    run("doctor")
    run("sync")
    out_dir = tmp_path / "out"
    out = run("export", "sid:9100003", "--out", str(out_dir), "--unit", "logic", "--redistributable-only")
    text = (out_dir / "suricata.rules").read_text()
    assert "sid:9100002" in text and "sid:9200002" not in text and "1 flowbit setters added" in out
    # only the non-redistributable setter left: reported as missing
    write(a / "a.rules", checker)
    run("sync")
    out = run("export", "sid:9100003", "--out", str(tmp_path / "out2"), "--unit", "logic", "--redistributable-only")
    assert "ET.login" in out


def with_fake_engine(root: Path, profile: str) -> None:
    """Give the workspace a scripted engine named `local` that loads every well-formed rule, and use it for
    `profile`: modify entries are applied only after the profile's engine validated the rewritten rules."""
    from tests.test_engine_offline import fake_engine

    binary = fake_engine(root.parent, "7.0.99")
    settings = root / "suriharvest.yaml"
    data = (yaml.safe_load(settings.read_text()) if settings.exists() else None) or {}
    data["engines"] = [{"name": "local", "binary": str(binary)}]
    settings.write_text(yaml.safe_dump(data))
    run("profile", "set", profile, "--engine", "local")


def test_sources_remove_drops_the_source_and_its_rules_from_search(ws: Path):
    """docs/conventions.md lists `sources list|add|remove|enable|disable`; suriharvest had no `remove`."""

    assert "repo B something else" in run("search", "something", "--per-logic")
    assert "removed repoB" in run("sources", "remove", "repoB")
    assert "repoB" not in run("sources", "list")
    run("update", "--no-validate")
    assert "repo B something else" not in run("search", "something", "--per-logic")
    again = runner.invoke(app, ["sources", "remove", "repoB"])
    assert again.exit_code == 2 and "unknown source repoB" in again.output
