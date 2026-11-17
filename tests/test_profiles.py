"""Profiles: exclusions by name and other kinds, sticky rule keys, builds and diffs, suggestions."""

from __future__ import annotations

import json
import os
from pathlib import Path

from tests.test_pipeline import ET_V3, ET_V4, run, ws  # noqa: F401 - fixture


def build_dir(out: str) -> Path:
    return Path(out.split("-> ")[1].strip())


def test_exclusions_build_and_diff(ws: Path, tmp_path: Path):  # noqa: F811
    run("profile", "create", "default", "--query", "source:et")
    out = run("profile", "exclude", "default", "Foo CnC", "--reason", "noisy here")
    assert "matches 1 rules" in out
    run("profile", "exclude", "default", "2000004", "--kind", "sid")
    first = run("profile", "build", "default")
    d = build_dir(first.splitlines()[0])
    # readable summary: build number as `update` writes it, exclusions as text, no comparison on a first build
    assert first.startswith("build default #") and "first build of profile default" in first
    assert "{" not in first and "since build" not in first
    assert "  excluded by: msg_contains 1, sid 1\n" in first
    rules = (d / "suricata.rules").read_text()
    assert "Foo CnC" not in rules and "sid:2000004" not in rules and "sid:2000003" in rules
    excluded = [json.loads(x) for x in (d / "excluded.jsonl").read_text().splitlines()]
    assert {e["sid"] for e in excluded} == {2000001, 2000004}
    assert any("noisy here" in e["reason"] for e in excluded)
    # upstream renames the rule: the exclusion still holds through the remembered rule key
    f = tmp_path / "et" / "rules" / "emerging-malware.rules"
    f.write_text(f.read_text().replace(ET_V3, ET_V4.replace("Foo CnC Checkin", "FooBot Beacon")))
    run("sync")
    second = run("profile", "build", "default")
    rules = (build_dir(second.splitlines()[0]) / "suricata.rules").read_text()
    assert "FooBot Beacon" not in rules
    assert "+0 -0 ~0 rules" in second
    assert "since build #" in second and "first build" not in second
    as_json = json.loads(run("profile", "build", "default", "--json"))
    assert as_json["profile"] == "default" and as_json["summary"]["previous_build"] and as_json["rules"] > 0
    listing = run("profile", "exclusions", "default")
    assert "not among the candidates" not in listing.split("Foo CnC")[1].split("\n")[0]


def test_new_rules_and_flowbit_setter_not_readded(ws: Path, tmp_path: Path):  # noqa: F811
    run("profile", "create", "s", "--query", "source:et")
    run("profile", "exclude", "s", "ET INFO set bit", "--kind", "msg_exact")
    out = run("profile", "build", "s")
    assert (
        "2 flowbits have no setter" in out
    )  # ET.login (setter excluded) and never.set; the analyst excluded the setter: it is not added back
    assert "0 rule(s) not in the last build" in run("profile", "new", "s")
    f = tmp_path / "et" / "rules" / "emerging-malware.rules"
    f.write_text(
        f.read_text() + 'alert http any any -> any any (msg:"ET MALWARE brand new"; http.uri; content:"/new-thing"; sid:2000099; rev:1;)\n'
    )
    run("sync")
    new = run("profile", "new", "s")
    assert "brand new" in new and "1 rule(s) not in the last build" in new


def test_suggestions_and_preview(ws: Path):  # noqa: F811
    run("profile", "create", "p", "--query", "source:et")
    run("profile", "set", "p", "--include-disabled")
    sug = run("profile", "suggest", "p")
    assert "Category ET INFO" in sug and "Checks a flowbit that nothing sets" in sug and "Disabled by default upstream" in sug
    assert "2 rule(s) match" in run("profile", "preview", "ET INFO", "--kind", "category")


def test_disabled_rules_are_not_candidates_by_default(ws: Path):  # noqa: F811
    run("profile", "create", "d", "--query", "source:et,repoA")
    out = run("profile", "build", "d")
    d = build_dir(out.splitlines()[0])
    rules = (d / "suricata.rules").read_text()
    assert "sid:2000005" not in rules  # shipped commented out
    assert "sid:1000001" in rules  # repoA reached through source:et,repoA


def test_exclusion_file_round_trip(ws: Path):  # noqa: F811
    import yaml

    run("profile", "create", "default", "--query", "source:et")
    run("profile", "exclude", "default", "Foo CnC", "--reason", "noisy")
    f = ws / "exclusions" / "default.yaml"
    data = yaml.safe_load(f.read_text())
    assert data["rule_exclusions"] == [{"msg": "Foo CnC", "reason": "noisy"}]
    # the analyst edits the file by hand: drops the msg entry, adds a category with a review date
    data["rule_exclusions"] = []
    data["exclusions"] = [{"kind": "category", "value": "ET INFO", "reason": "policy", "review": "2027-01-01"}]
    f.write_text(yaml.safe_dump(data))
    out = run("profile", "build", "default")
    assert "+1 -1 applied" in out
    rules = (build_dir(next(x for x in out.splitlines() if x.startswith("build "))) / "suricata.rules").read_text()
    assert "Foo CnC" in rules and "ET INFO" not in rules
    listing = run("profile", "exclusions", "default")
    assert "ET INFO" in listing and "Foo CnC" not in listing
    # a broken file is reported, not applied
    f.write_text("rule_exclusions: [unclosed\n")
    assert "not applied" in run("profile", "exclusions", "default")


def test_update_skips_unchanged_index_and_builds(ws: Path, tmp_path: Path):  # noqa: F811
    run("profile", "create", "c", "--query", "source:et")
    first = run("update", "--no-validate")
    assert "build c #1" in first
    second = run("update", "--no-validate")
    assert "index: up to date" in second and "build c: up to date (#1" in second
    run("profile", "exclude", "c", "Foo CnC")
    third = run("update", "--no-validate")
    assert "index: up to date" in third and "build c #2" in third  # an exclusion changed: rebuild
    f = tmp_path / "et" / "rules" / "emerging-malware.rules"
    f.write_text(
        f.read_text() + 'alert http any any -> any any (msg:"ET MALWARE newer"; http.uri; content:"/zz-new"; sid:2000098; rev:1;)\n'
    )
    fourth = run("update", "--no-validate")
    assert "index: up to date" not in fourth and "build c #3" in fourth


def add_local(name: str, path: Path) -> None:
    folder = path.parent / f"{name}-src"
    folder.mkdir()
    path.rename(folder / path.name)
    run("sources", "add", name, str(folder), "--type", "local", "--redistribute", "no")
    run("sync")


def test_only_newest_revision_of_a_rule_is_kept(ws: Path, tmp_path: Path):  # noqa: F811
    # a mirror still carries ET rev 3 while the feed has rev 4 of the same sid
    old = tmp_path / "old.rules"
    old.write_text(ET_V3 + "\n")
    f = tmp_path / "et" / "rules" / "emerging-malware.rules"
    f.write_text(f.read_text().replace(ET_V3, ET_V4))
    run("sync")
    add_local("oldfile", old)
    run("profile", "create", "t", "--query", "source:et,oldfile")
    out = run("profile", "build", "t")
    d = build_dir(next(x for x in out.splitlines() if x.startswith("build ")))
    rules = (d / "suricata.rules").read_text()
    assert rules.count("sid:2000001;") == 1 and "rev:4;" in rules and "FooBot/2" in rules
    assert "older revision" in (d / "excluded.jsonl").read_text()


def test_workspace_can_be_moved(ws, tmp_path, monkeypatch):  # noqa: F811
    """Builds keep working after the workspace folder is moved (paths are relocated)."""
    import gc
    import shutil

    from tests.test_pipeline import db, run

    f = tmp_path / "mine.rules"
    f.write_text('alert tcp any any -> any any (msg:"moved marker"; content:"mv"; sid:5551000; rev:1;)\n')
    add_local("mine", f)
    run("profile", "create", "default", "--query", "source:et,mine")
    run("profile", "build", "default")
    moved = tmp_path / "elsewhere" / "workspace"
    # Windows cannot move a folder that is the current directory or holds a database this process has open
    monkeypatch.chdir(tmp_path)
    gc.collect()
    shutil.move(str(ws), str(moved))
    monkeypatch.setenv("SURIHARVEST_HOME", str(moved))
    out = run("sync")
    assert "failed" not in out
    paths = [p for (p,) in db(moved).execute("select path from profile_builds")]
    assert paths and all(p.startswith(str(moved)) for p in paths)
    assert "moved marker" in (Path(paths[-1]) / "suricata.rules").read_text()
    run("profile", "new", "default")


def test_equal_revision_winner_is_deterministic(ws: Path, tmp_path: Path):  # noqa: F811
    """Two copies of one rule key with the same rev but different text: the sid owner (the source whose sid_namespace
    owns the key) wins even against a better source priority, whatever the query order."""
    other = tmp_path / "fork.rules"
    other.write_text(ET_V3.replace('content:"FooBot"', 'content:"FooBotX"') + "\n")
    add_local("fork", other)
    # the fork gets the better priority: the owner (et) still keeps its rule
    import yaml

    data = yaml.safe_load((ws / "sources.yaml").read_text())
    for src in data["sources"]:
        if src["name"] == "fork":
            src["priority"] = 1
    (ws / "sources.yaml").write_text(yaml.safe_dump(data))
    run("sync")
    run("profile", "create", "t", "--query", "source:et,fork")
    for _ in range(2):
        out = run("profile", "build", "t")
        d = build_dir(next(x for x in out.splitlines() if x.startswith("build ")))
        rules = (d / "suricata.rules").read_text()
        assert rules.count("sid:2000001;") == 1 and "FooBotX" not in rules and 'content:"FooBot";' in rules


def test_diff_between_builds(ws: Path, tmp_path: Path):  # noqa: F811
    run("profile", "create", "default", "--query", "source:et")
    run("profile", "build", "default")
    f = tmp_path / "et" / "rules" / "emerging-malware.rules"
    text = f.read_text().replace("sid:2000003; rev:1;", "sid:2000003; rev:2;")
    f.write_text(text + 'alert http any any -> any any (msg:"ET MALWARE added"; http.uri; content:"/added"; sid:2000097; rev:1;)\n')
    run("sync")
    run("profile", "build", "default")
    out = run("profile", "diff", "default")
    assert "+1 -0 ~1" in out and "ET MALWARE added" in out and "rev 1 -> 2" in out
    data = json.loads(run("profile", "diff", "default", "1", "2", "--json"))
    assert [r["sid"] for r in data["added"]] == [2000097]
    listing = run("profile", "builds", "default")
    assert "\n 2 " in listing and "\n 1 " in listing


def test_new_revision_with_new_logic_is_a_change(ws: Path, tmp_path: Path):  # noqa: F811
    run("profile", "create", "default", "--query", "source:et")
    run("profile", "build", "default")
    out = run("profile", "diff", "default")  # one build only: not an error
    assert "nothing to compare yet" in out
    assert json.loads(run("profile", "diff", "default", "--json"))["changed"] == []
    f = tmp_path / "et" / "rules" / "emerging-malware.rules"
    f.write_text(f.read_text().replace('content:"/admin"; sid:2000003; rev:1;', 'content:"/administrator"; sid:2000003; rev:2;'))
    run("sync")
    build = run("profile", "build", "default")
    assert "+0 -0 ~1" in build
    data = json.loads(run("profile", "diff", "default", "--json"))
    assert data["added"] == [] and data["removed"] == []
    assert [(r["sid"], r["change"]) for r in data["changed"]] == [(2000003, "rev 1 -> 2; new logic")]


def test_unknown_engine_no_op_exclusions_and_remove(ws: Path):  # noqa: F811
    from typer.testing import CliRunner

    from suriharvest.cli import app

    r = CliRunner().invoke(app, ["profile", "create", "x", "--engine", "suricata-8"])
    assert r.exit_code == 2 and "no engine 'suricata-8'" in r.output
    run("profile", "create", "x", "--query", "source:et")
    r = CliRunner().invoke(app, ["profile", "set", "x", "--engine", "nope"])
    assert r.exit_code == 2
    assert "no rule matches it now" in run("profile", "exclude", "x", "4242424", "--kind", "sid")
    assert "shipped disabled upstream" in run("profile", "exclude", "x", "2000005", "--kind", "sid")  # DISABLED fixture rule
    out = run("profile", "build", "x")
    folder = Path(out.split("-> ")[1].split("\n")[0].strip()).parent
    assert folder.is_dir()
    gone = run("profile", "remove", "x", "--yes")
    assert "profile x removed (2 exclusion(s))" in gone and not folder.exists()
    assert (ws / "exclusions" / "x.yaml.removed").exists() and not (ws / "exclusions" / "x.yaml").exists()
    assert "x" not in run("profile", "list").split()


def test_latest_link_utc_folder_and_progress_lines(ws: Path):  # noqa: F811
    from suriharvest.pipeline import progress_lines

    run("profile", "create", "l", "--query", "source:et")
    first = Path(run("profile", "build", "l").split("-> ")[1].split("\n")[0].strip())
    assert first.name.endswith("Z")  # UTC, like the CLI and the web UI
    run("profile", "exclude", "l", "2000001", "--kind", "sid")
    second = Path(run("profile", "build", "l").split("-> ")[1].split("\n")[0].strip())
    latest = second.parent / "latest"
    if latest.is_symlink() or os.name != "nt":  # Windows without the symlink privilege: only the LATEST file
        assert latest.resolve() == second.resolve() and (latest / "suricata.rules").exists()
    assert (second.parent / "LATEST").read_text().strip() == second.name
    lines: list[str] = []
    cb = progress_lines(lines.append, "validate local", every=0)
    for done in (0, 100, 500, 1000):
        cb(done, 1000)
    assert lines and all(x.startswith("validate local: ") and "/1,000 rules" in x for x in lines)


def test_profile_build_dates_sid_map_rows_from_source_date_epoch(ws: Path, monkeypatch):  # noqa: F811
    """A profile build dates new sid map rows like a release build (SOURCE_DATE_EPOCH), not with the system date:
    the same data built again from scratch gives a byte-identical sid map and identical build files."""
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1763100000")  # 2025-11-14
    run("profile", "create", "b", "--query", "source:repoB")
    smap = ws / "state" / "sid-map.tsv"

    def build() -> tuple[bytes, dict[str, bytes]]:
        d = build_dir(run("profile", "build", "b").splitlines()[0])
        files = {p.name: p.read_bytes() for p in d.iterdir() if p.is_file() and p.name != "changes.json"}
        return smap.read_bytes(), files

    first_map, first_files = build()
    rows = [x.split("\t") for x in first_map.decode().splitlines() if x and not x.startswith("#")]
    assert rows and {r[4] for r in rows} == {"2025-11-14"}
    smap.unlink()  # start over: the remap decisions are made (and dated) again
    second_map, second_files = build()
    assert second_map == first_map and second_files == first_files
