"""Regression tests for fixed bugs, and for the source registry."""

from __future__ import annotations

import json
import warnings
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from suriharvest.config import CATALOG, ConfigError, SourceConfig, catalog_sources, preset_sources
from suriharvest.parser import ACTIONS, looks_like_rules_bytes
from suriharvest.sidalloc import ALLOCATIONS, allocated, next_unallocated, owner
from suriharvest.sidmap import SidMap
from tests.test_pipeline import run, write, ws  # noqa: F401 - fixture

# ---------------------------------------------------------------------------------------------------------------
# the rules pre-filter knows every action


@pytest.mark.parametrize("action", sorted(ACTIONS))
def test_looks_like_rule_accepts_every_action(action: str):
    line = f'{action} tcp any any -> any any (msg:"x"; sid:1;)\n'.encode()
    assert looks_like_rules_bytes(line)
    assert looks_like_rules_bytes(b"# " + line)  # disabled rules count too


def test_rules_file_with_only_reject_variants_is_synced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    src = tmp_path / "src"
    write(src / "ips.rules", 'rejectboth tcp any any -> any 23 (msg:"telnet"; flow:to_server; sid:1000010; rev:1;)')
    root = tmp_path / "ws"
    root.mkdir()
    (root / "sources.yaml").write_text(
        yaml.safe_dump({"sources": [{"name": "g", "type": "git", "url": f"file://{_git_repo(src, tmp_path)}"}]})
    )
    monkeypatch.setenv("SURIHARVEST_HOME", str(root))
    run("doctor")
    out = run("sync")
    assert "+1 ~0 -0 files; 1 rules read" in out  # the git pre-filter used to skip files without alert/drop/reject/pass


def _git_repo(src: Path, tmp: Path) -> Path:
    import shutil
    import subprocess

    repo = tmp / "repo"
    shutil.copytree(src, repo)
    git = ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t"]
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run([*git, "add", "."], check=True)
    subprocess.run([*git, "commit", "-qm", "one"], check=True)
    return repo


# ---------------------------------------------------------------------------------------------------------------
# stable sid remapping


def g(h: str, sid: int, score: int = 50, src: str = "a") -> SimpleNamespace:
    return SimpleNamespace(logic_hash=h, gid=1, sid=sid, score=score, canonical_source=src)


def rank(x: SimpleNamespace) -> tuple:
    return (0, -x.score, x.logic_hash)


def test_sid_map_is_stable_across_builds(tmp_path: Path):
    path = tmp_path / "sid-map.tsv"
    smap = SidMap(path)
    first = smap.assign([g("aa", 1000001, 90), g("bb", 1000001, 10)], rank, base=7_000_000)
    smap.save()
    assert first == {"bb": 7_000_000}
    # next build: a new rule joins the clash with a better score, and an unrelated clash appears before it
    smap = SidMap(path)
    second = smap.assign([g("aa", 1000001, 90), g("bb", 1000001, 10), g("cc", 1000001, 99), g("dd", 5, 1), g("ee", 5, 2)], rank, 7_000_000)
    smap.save()
    assert second["bb"] == 7_000_000  # unchanged
    assert "aa" not in second  # the old holder keeps the original sid even though cc scores higher
    assert second["cc"] not in (7_000_000, 1000001)
    # third build: same input, same answer (nothing reallocated)
    third = SidMap(path).assign(
        [g("aa", 1000001, 90), g("bb", 1000001, 10), g("cc", 1000001, 99), g("dd", 5, 1), g("ee", 5, 2)], rank, 7_000_000
    )
    assert third == second
    # the holder disappears for a while: the remapped rules keep their sids
    fourth = SidMap(path).assign([g("bb", 1000001, 10), g("cc", 1000001, 99)], rank, 7_000_000)
    assert fourth == {"bb": 7_000_000, "cc": second["cc"]}


def test_sid_map_never_allocates_in_an_allocated_range(tmp_path: Path):
    wybot = next(a for a in ALLOCATIONS if a.namespace == "wybot")
    out = SidMap(tmp_path / "m.tsv").assign([g("aa", 1000001), g("bb", 1000001)], rank, base=wybot.first)
    assert out == {"bb": wybot.last + 1} and not allocated(wybot.last + 1)


def test_cli_export_keeps_remapped_sids(ws: Path, tmp_path: Path):  # noqa: F811
    def exported(d: Path) -> dict[str, int]:
        return {m["logic_hash"]: m["exported_sid"] for m in map(json.loads, (d / "manifest.jsonl").read_text().splitlines())}

    run("export", "source:repoB", "--out", str(tmp_path / "e1"), "--unit", "logic", "--remap-colliding-sids")
    one = exported(tmp_path / "e1")
    assert max(one.values()) >= 1_900_000_000  # default remap base, outside every allocated range
    assert (ws / "state" / "sid-map.tsv").exists()
    # a third rule with the same sid shows up in another repo
    write(tmp_path / "repoA" / "more.rules", 'alert tcp any any -> any 9 (msg:"third"; content:"zz"; sid:1000001; rev:1;)')
    run("sync")
    run("export", "source:repoB,repoA", "--out", str(tmp_path / "e2"), "--unit", "logic", "--remap-colliding-sids")
    two = exported(tmp_path / "e2")
    for h, sid in one.items():
        assert two[h] == sid  # every earlier decision holds


# ---------------------------------------------------------------------------------------------------------------
# sid allocation table


def test_sid_allocation_owner():
    assert owner(1, 2_000_001, "ET MALWARE x").namespace == "et"
    assert owner(1, 2_000_001, "something else") is None  # ET range, not an ET rule
    assert owner(1, 2_610_001, "TGI HUNT x").namespace == "tgreen"  # inside 2M-3M but not ET's
    assert owner(1, 2_200_001, "SURICATA STREAM x").namespace == "oisf"
    assert owner(3, 2_000_001, "ET x") is None  # only gid 1
    assert owner(1, 1_500_000, "local") is None
    assert next_unallocated(1_500_000) == 2_104_000  # local range, then ET's first range
    assert next_unallocated(1_900_000_000) == 1_900_000_000


# ---------------------------------------------------------------------------------------------------------------
# validation cache key covers classification/reference config


def test_config_hash_changes_with_classification_and_reference(tmp_path: Path):
    from suriharvest.validate import config_files, config_hash

    y = tmp_path / "suricata.yaml"
    y.write_text("%YAML 1.1\n---\nclassification-file: classification.config\nreference-config-file: /nonexistent/ref.config\n")
    (tmp_path / "classification.config").write_text("config classification: trojan-activity,A Network Trojan was detected,1\n")
    (tmp_path / "reference.config").write_text("config reference: url http://\n")  # not the configured one: ignored
    (tmp_path / "threshold.config").write_text("")  # default name next to the yaml
    assert [f.name for f in config_files(str(y))] == ["classification.config", "threshold.config"]
    before = config_hash("7.0.3", str(y))
    (tmp_path / "classification.config").write_text("config classification: new-class,New,2\n")
    after = config_hash("7.0.3", str(y))
    assert before != after
    y.write_text("%YAML 1.1\n---\n")  # defaults: classification.config and reference.config next to the yaml
    defaults = config_hash("7.0.3", str(y))
    (tmp_path / "reference.config").write_text("config reference: url https://\n")
    assert config_hash("7.0.3", str(y)) != defaults


# ---------------------------------------------------------------------------------------------------------------
# verdict on a source: no SQLAlchemy JSON-contains deprecation, exact name match


def test_source_verdict_without_sqlalchemy_warning(ws: Path):  # noqa: F811
    from suriharvest.config import Workspace
    from suriharvest.db import session_factory
    from suriharvest.index import apply_verdict_for

    with session_factory(Workspace(ws).db_path)() as s, warnings.catch_warnings():
        warnings.simplefilter("error")
        n = apply_verdict_for(s, "source", "repoA")
        assert n == 2  # LOCAL_A and the ET copy
        assert apply_verdict_for(s, "source", "repo") == 0  # a prefix of a name is not the name


# ---------------------------------------------------------------------------------------------------------------
# source registry


def test_bundled_catalog_is_free_and_complete():
    raw = yaml.safe_load(CATALOG.read_text())["sources"]
    for e in raw:
        assert {"name", "type", "url", "licence", "redistribute", "status", "tier", "notes"} <= set(e), e["name"]
    srcs = catalog_sources()
    assert {s.name for s in srcs} >= {"et-open", "oisf-trafficid", "abuse.ch-sslbl"}
    assert all(s.type in ("http-tarball", "http-file", "git", "local") for s in srcs)
    assert not any("urlhaus" in s.url or "threatfox" in s.url or "${secret}" in s.url or s.auth for s in srcs)
    et = next(s for s in srcs if s.name == "et-open")
    assert "BSD" in et.licence and et.redistribute == "yes"


def test_presets_disable_dead_and_too_new_sources(tmp_path: Path):
    cat = tmp_path / "cat.yaml"
    cat.write_text(
        yaml.safe_dump(
            {
                "sources": [
                    {"name": "ok", "type": "http-file", "url": "https://x/a.rules", "tier": "core", "redistribute": "yes"},
                    {"name": "gone", "type": "http-file", "url": "https://x/b.rules", "tier": "core", "status": "dead"},
                    {"name": "s8", "type": "http-file", "url": "https://x/c.rules", "tier": "core", "min_suricata": "8.0.0"},
                    {"name": "extra", "type": "git", "url": "https://x/r", "tier": "community"},
                ]
            }
        )
    )
    on = {s.name: s.enabled for s in preset_sources("core", "7.0.3", cat)}
    assert on == {"ok": True, "gone": False, "s8": False, "extra": False}
    assert {s.name: s.enabled for s in preset_sources("community", "8.0.1", cat)} == {"ok": True, "gone": False, "s8": True, "extra": True}


def test_source_config_validation():
    with pytest.raises(ConfigError):
        SourceConfig(name="x", type="ftp", url="")
    with pytest.raises(ConfigError):
        SourceConfig(name="x", type="git", url="https://x", redistribute="maybe")
    with pytest.raises(ConfigError):
        SourceConfig(name="x", type="git", url="https://x", status="broken")
    assert SourceConfig(name="x", type="git", url="https://x", redistribute=True).redistribute == "yes"  # YAML yes
    assert not SourceConfig(name="x", type="git", url="https://x", status="dead").active


def test_dead_sources_are_not_synced(ws: Path):  # noqa: F811
    data = yaml.safe_load((ws / "sources.yaml").read_text())
    data["sources"][1]["status"] = "dead"  # repoA
    (ws / "sources.yaml").write_text(yaml.safe_dump(data))
    assert "repoA" not in run("sync")


def test_init_and_redistributable_only_export(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ws: Path):  # noqa: F811
    out = run("export", "--out", str(tmp_path / "all"), "--unit", "logic", "--remap-colliding-sids")
    assert "left out" not in out
    data = yaml.safe_load((ws / "sources.yaml").read_text())
    for s in data["sources"]:
        s["redistribute"] = "yes" if s["name"] == "et" else "no"
    (ws / "sources.yaml").write_text(yaml.safe_dump(data))
    run("sync")
    out = run("export", "--out", str(tmp_path / "pub"), "--unit", "logic", "--redistributable-only")
    assert "left out" in out and "redistribute: no" in out
    manifest = [json.loads(x) for x in (tmp_path / "pub" / "manifest.jsonl").read_text().splitlines()]
    assert manifest and {m["source"] for m in manifest} == {"et"} and all(m["redistribute"] == "yes" for m in manifest)
    # init writes the catalog with the registry fields and a default profile
    new = tmp_path / "fresh"
    monkeypatch.delenv("SURIHARVEST_HOME")
    run("init", str(new))
    srcs = yaml.safe_load((new / "sources.yaml").read_text())["sources"]
    assert all({"licence", "redistribute", "status", "tier"} <= set(s) for s in srcs)
    monkeypatch.setenv("SURIHARVEST_HOME", str(new))
    assert "default" in run("profile", "list")


def test_bases_inside_allocated_ranges_are_refused(ws: Path, tmp_path: Path):  # noqa: F811
    from typer.testing import CliRunner

    from suriharvest.cli import app
    from suriharvest.sidalloc import overlapping

    assert overlapping(9_800_000, 9_899_999)  # the old dataset default: inside an allocated range
    assert not overlapping(1_900_000_000, 1_999_999_999)
    r = CliRunner().invoke(
        app,
        ["export", "source:repoB", "--out", str(tmp_path / "x"), "--unit", "logic", "--remap-colliding-sids", "--remap-base", "9600000"],
    )
    assert r.exit_code == 2 and "overlaps allocated sid ranges" in r.output
    r = CliRunner().invoke(app, ["export", "--out", str(tmp_path / "y"), "--iocs-as-datasets", "--sid-base", "2000000"])
    assert r.exit_code == 2


def test_suricata_update_disable_conf_from_profile_exclusions(ws: Path, tmp_path: Path):  # noqa: F811
    data = yaml.safe_load((ws / "sources.yaml").read_text())
    data["sources"][0]["oisf_name"] = "et/open"  # suricata-update fetches "et" itself
    (ws / "sources.yaml").write_text(yaml.safe_dump(data))
    run("profile", "create", "p", "--query", "source:et")
    run("profile", "exclude", "p", "2000003", "--kind", "sid")
    out = tmp_path / "su"
    run("export", "--out", str(out), "--format", "suricata-update", "--profile", "p")
    assert "1:2000003" in (out / "disable.conf").read_text()


def test_range_owner_keeps_its_sid_against_an_earlier_squatter(tmp_path: Path):
    from types import SimpleNamespace

    from suriharvest.sidmap import SidMap

    def g(h, prio, src):
        return SimpleNamespace(logic_hash=h, gid=1, sid=2000001, prio=prio, src=src)

    def rank(x):
        return (x.prio, x.logic_hash)

    def owner(x):
        return x.src == "et"

    path = tmp_path / "sid-map.tsv"
    squat, et_rule, other = g("aaaa", 5, "squatter"), g("bbbb", 10, "et"), g("cccc", 50, "fork")
    m = SidMap(path)
    assert m.assign([squat], rank, owner=owner) == {}  # the squatter is exported first, alone
    m.save()
    m = SidMap(path)
    out = m.assign([squat, et_rule], rank, owner=owner)
    assert "bbbb" not in out and "aaaa" in out  # the sidallocation.org owner keeps 2000001, the squatter moves
    m.save()
    # without an owner in the clash the incumbent keeps the sid (stability)
    m = SidMap(path)
    out = m.assign([et_rule, other], rank, owner=lambda x: False)
    assert "bbbb" not in out and "cccc" in out


def test_duplicate_sid_options_are_quarantined_and_export_survives_bad_text(ws: Path, monkeypatch: pytest.MonkeyPatch):  # noqa: F811
    from typer.testing import CliRunner

    from suriharvest import export as export_mod
    from suriharvest.cli import app
    from suriharvest.parser import ParseError, parse_rule

    with pytest.raises(ParseError, match="sid options"):
        parse_rule('alert tcp any any -> any any (msg:"two sids"; content:"x"; sid:5; sid:6; rev:1;)')

    def boom(text: str, sid: int) -> str:
        raise ParseError("expected exactly one sid option, found 2")

    monkeypatch.setattr(export_mod, "replace_sid", boom)
    out = ws / "x"
    r = CliRunner().invoke(app, ["export", "--out", str(out), "--unit", "logic", "--remap-colliding-sids"])
    assert r.exit_code == 0, r.output
    assert "malformed" in r.output and (out / "suricata.rules").exists()
