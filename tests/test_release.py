"""release build, init flags, update flags and sources check (offline: a fake Suricata that accepts every rule)."""

from __future__ import annotations

import contextlib
import gzip
import hashlib
import json
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from suriharvest.cli import app
from tests.fakes import ACCEPT_ALL, python_script
from tests.test_pipeline import run, write, ws  # noqa: F401 - fixture


@pytest.fixture
def released(ws: Path, tmp_path: Path) -> Path:  # noqa: F811
    fake = python_script(tmp_path / "fake-suricata", ACCEPT_ALL)
    run("init", str(ws), "--refresh", "--engine", f"suricata-7={fake}")
    # init --refresh rewrote sources.yaml from the catalog: put the test sources back
    data = {
        "sources": [
            {
                "name": "et",
                "type": "local",
                "url": str(tmp_path / "et"),
                "priority": 10,
                "licence": "MIT",
                "copyright": "Copyright (c) 2026 Test Publisher",
                "sid_namespace": "et",
                "redistribute": "yes",
                "licence_files": ["LICENSE"],
            },
            {
                "name": "repoA",
                "type": "local",
                "url": str(tmp_path / "repoA"),
                "licence": "MIT",
                "copyright": "Copyright (c) 2026 Test Publisher",
                "redistribute": "yes",
            },
            {
                "name": "repoB",
                "type": "local",
                "url": str(tmp_path / "repoB"),
                "licence": "GPL-3.0",
                "copyright": "Copyright (c) 2026 Test Publisher",
                "redistribute": "no",
            },
        ]
    }
    (ws / "sources.yaml").write_text(yaml.safe_dump(data))
    (tmp_path / "et" / "LICENSE").write_text("BSD licence text of the test publisher\n")
    run("update")
    return ws


def test_release_build_is_reproducible_and_gated(released: Path, tmp_path: Path):
    out1, out2 = tmp_path / "r1", tmp_path / "r2"
    args = ["--engine", "suricata-7", "--build-epoch", "1763100000", "--download-base", "https://example.invalid/dl"]
    text = run("release", "build", str(out1), *args)
    assert "suricata-7 (Suricata 7.0.99)" in text
    names = {p.name for p in out1.iterdir()}
    for f in (
        "suricata-7.rules",
        "suriharvest-7.tar.gz",
        "manifest.jsonl.gz",
        "summary.json",
        "changes.json",
        "index.yaml",
        "NOTICE.md",
        "LICENSES.tar.gz",
        "SHA256SUMS",
        "collisions.json",
        "validation.json",
        "suricata-overrides.txt",
        "RELEASE_NOTES.md",
    ):
        assert f in names, f
    merged = (out1 / "suricata-7.rules").read_text()
    assert "repo B" not in merged  # redistribute: no -> left out by default
    by_source = "".join((out1 / n).read_text() for n in sorted(names) if n.startswith("suricata-7.by-source."))
    assert sorted(x for x in by_source.splitlines() if not x.startswith("#")) == sorted(
        x for x in merged.splitlines() if not x.startswith("#")
    )  # exact partition
    for line in (out1 / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split("  ")
        assert hashlib.sha256((out1 / name).read_bytes()).hexdigest() == digest
    idx = yaml.safe_load((out1 / "index.yaml").read_text())
    assert idx["sources"]["suriharvest/suricata-7"]["url"] == "https://example.invalid/dl/suriharvest-7.tar.gz"
    assert idx["sources"]["suriharvest/suricata-7"]["license"] == "MIT"  # the sources' SPDX ids, not "Various"
    manifest = [json.loads(x) for x in gzip.decompress((out1 / "manifest.jsonl.gz").read_bytes()).splitlines()]
    assert manifest and all(m["engine"] == "suricata-7" for m in manifest)
    import io
    import tarfile

    with tarfile.open(fileobj=io.BytesIO(gzip.decompress((out1 / "LICENSES.tar.gz").read_bytes()))) as tf:
        lic = {m.name: tf.extractfile(m).read().decode() for m in tf.getmembers()}
    assert lic["LICENSES/et/LICENSE"].startswith("BSD licence text")
    assert "| et | MIT | `LICENSE`, `texts/MIT.txt` | [MIT](https://spdx.org/licenses/MIT.html) |" in lic["LICENSES/INDEX.md"]
    assert lic["LICENSES/texts/MIT.txt"].startswith("MIT License")
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress((out1 / "suriharvest-7.tar.gz").read_bytes()))) as tf:
        assert "LICENSES/INDEX.md" in tf.getnames()
    # same corpus, same epoch: byte-identical
    run("release", "build", str(out2), *args)
    assert (out1 / "SHA256SUMS").read_text() == (out2 / "SHA256SUMS").read_text()
    # a source vanishes: the release gate fails against the previous release
    data = yaml.safe_load((released / "sources.yaml").read_text())
    data["sources"][1]["enabled"] = False  # repoA
    (released / "sources.yaml").write_text(yaml.safe_dump(data))
    run("sync")
    r = CliRunner().invoke(app, ["release", "build", str(tmp_path / "r3"), *args, "--previous", str(out1)])
    assert r.exit_code == 1 and "vanished" in r.output
    r = CliRunner().invoke(app, ["release", "build", str(tmp_path / "r4"), *args, "--previous", str(out1), "--no-gates"])
    assert r.exit_code == 0
    changes = json.loads((tmp_path / "r4" / "changes.json").read_text())
    assert changes["removed"] and not changes["added"]


def test_init_flags(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("SURIHARVEST_HOME", raising=False)
    cat = tmp_path / "cat.yaml"
    cat.write_text(
        yaml.safe_dump(
            {
                "sources": [
                    {"name": "a", "type": "http-file", "url": "https://x/a.rules", "tier": "core", "redistribute": "yes"},
                    {"name": "b", "type": "http-file", "url": "https://x/b.rules", "tier": "community", "redistribute": "unknown"},
                    {"name": "c", "type": "http-file", "url": "https://x/c.rules", "tier": "experimental", "redistribute": "yes"},
                ]
            }
        )
    )
    w = tmp_path / "w"
    run(
        "init",
        str(w),
        "--catalog",
        str(cat),
        "--tier",
        "core",
        "--tier",
        "community",
        "--redistributable-only",
        "--engine",
        "suricata-7=suricata",
        "--engine",
        "suricata-8=jasonish/suricata:8.0.8",
    )
    on = {s["name"]: s["enabled"] for s in yaml.safe_load((w / "sources.yaml").read_text())["sources"]}
    assert on == {"a": True, "b": False, "c": False}
    settings = yaml.safe_load((w / "suriharvest.yaml").read_text())
    assert settings["engines"] == [{"name": "suricata-7", "binary": "suricata"}, {"name": "suricata-8", "image": "jasonish/suricata:8.0.8"}]
    assert settings["remap_base"] == 1_900_000_000
    r = CliRunner().invoke(app, ["init", str(w)])
    assert r.exit_code == 2  # exists; --refresh needed
    run("init", str(w), "--refresh", "--catalog", str(cat), "--preset", "all")


def test_update_allow_failures_and_report(ws: Path, tmp_path: Path):  # noqa: F811
    data = yaml.safe_load((ws / "sources.yaml").read_text())
    data["sources"].append({"name": "broken", "type": "local", "url": str(tmp_path / "nope")})
    (ws / "sources.yaml").write_text(yaml.safe_dump(data))
    assert CliRunner().invoke(app, ["update", "--no-validate"]).exit_code == 1
    rep = tmp_path / "rep.md"
    r = CliRunner().invoke(app, ["update", "--no-validate", "--allow-failures", "--max-failed-sources", "50", "--report-file", str(rep)])
    assert r.exit_code == 0, r.output
    assert rep.read_text().startswith("#")


def test_sources_check_offline(tmp_path: Path):
    index = tmp_path / "index.yaml"
    index.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "sources": {
                    "et/open": {"url": "https://x/%(__version__)s/e.tar.gz", "license": "MIT"},
                    "new/free": {"url": "https://x/n.rules", "license": "MIT", "vendor": "V", "summary": "S"},
                    "paid/feed": {"url": "https://x/%(secret-code)s/p.tar.gz", "license": "Commercial", "parameters": {"secret-code": {}}},
                    "abuse.ch/urlhaus": {"url": "https://x/u.tar.gz", "license": "CC0-1.0"},
                },
            }
        )
    )
    health = tmp_path / "health.yaml"
    r = CliRunner().invoke(app, ["sources", "check", "--oisf-index", str(index), "--no-http", "--health", str(health)])
    assert r.exit_code == 1  # a candidate and catalog entries gone from this index
    assert "new/free" in r.output and "paid/feed" not in r.output and "urlhaus" not in r.output
    first = health.read_text()
    CliRunner().invoke(app, ["sources", "check", "--oisf-index", str(index), "--no-http", "--health", str(health)])
    assert health.read_text() == first  # deterministic


def test_sources_yaml_changes_apply_without_a_sync(released: Path, tmp_path: Path):
    """redistribute: no, a changed licence or a removed source take effect at release/export time, not at the next sync."""
    args = ["--engine", "suricata-7", "--build-epoch", "0"]
    run("release", "build", str(tmp_path / "before"), *args)
    assert "repo A shell" in (tmp_path / "before" / "suricata-7.rules").read_text()
    data = yaml.safe_load((released / "sources.yaml").read_text())
    data["sources"][1]["redistribute"] = "no"  # repoA
    data["sources"][0]["licence"] = "BSD-3-Clause"  # et
    (released / "sources.yaml").write_text(yaml.safe_dump(data))
    out = tmp_path / "after"
    run("release", "build", str(out), *args)
    assert "repo A shell" not in (out / "suricata-7.rules").read_text()
    assert not (out / "suricata-7.by-source.repoA.rules").exists()
    notice = (out / "NOTICE.md").read_text()
    assert "| repoA |" not in notice and "| et | BSD-3-Clause |" in notice
    run("export", "--out", str(tmp_path / "x"), "--redistributable-only", "--unit", "logic", "--remap-colliding-sids")
    assert "repo A shell" not in (tmp_path / "x" / "suricata.rules").read_text()
    # removed from sources.yaml: gone from the next build too
    data["sources"] = [x for x in data["sources"] if x["name"] != "et"]
    (released / "sources.yaml").write_text(yaml.safe_dump(data))
    gone = tmp_path / "gone"
    r = CliRunner().invoke(app, ["release", "build", str(gone), *args, "--no-gates"])
    # et removed and repoA not redistributable: nothing is left, and an empty build is refused, leaving no files
    assert r.exit_code != 0 and "0-rule build" in r.output, r.output
    assert not gone.exists() or not any(gone.iterdir())


def test_licence_files_only_from_what_the_source_publishes(tmp_path: Path):
    from types import SimpleNamespace

    from suriharvest.config import SourceConfig, Workspace
    from suriharvest.release import _licence_files

    w = Workspace(tmp_path / "ws")
    tarball = w.source_dir("tb")
    (tarball / "rules" / ".git").mkdir(parents=True)
    (tarball / "rules" / "LICENSE").write_text("publisher licence")
    (tarball / "rules" / ".git" / "LICENSE").write_text("not this")
    (tarball / "rules" / "license-notes.html").write_text("not this either")
    with contextlib.suppress(OSError):  # Windows without the symlink privilege: the rest still applies
        (tarball / "COPYING.md").symlink_to(tmp_path / "secret.txt")
    (tmp_path / "secret.txt").write_text("outside the source")
    mine = tmp_path / "mine"
    (mine / "deep").mkdir(parents=True)
    (mine / "LICENSE").write_text("user's private licence file")
    (mine / "deep" / "NOTICE").write_text("private")
    (mine / "OURS.txt").write_text("explicitly published")
    cfgs = {
        "tb": SourceConfig(name="tb", type="http-tarball", url="https://example.org/x.tar.gz", redistribute="yes"),
        "local-auto": SourceConfig(name="local-auto", type="local", url=str(mine), redistribute="yes"),
        "local-listed": SourceConfig(
            name="local-listed", type="local", url=str(mine), redistribute="yes", licence_files=["OURS.txt", "../secret.txt"]
        ),
        "nored": SourceConfig(name="nored", type="local", url=str(mine), redistribute="no", licence_files=["OURS.txt"]),
    }
    rows = {n: SimpleNamespace(licence="MIT", redistribute=c.redistribute) for n, c in cfgs.items()}
    files = dict(_licence_files(sorted(cfgs), rows, cfgs, w))
    assert files.pop("LICENSES/tb/rules__LICENSE") == b"publisher licence"
    assert files.pop("LICENSES/local-listed/OURS.txt") == b"explicitly published"
    index = files.pop("LICENSES/INDEX.md").decode()
    files.pop("LICENSES/texts/MIT.txt")  # bundled SPDX text, not a file from the source
    assert files == {}  # no .git, no symlink, no unlisted local file, nothing from a non-redistributable source
    assert "| nored | MIT | `texts/MIT.txt` |" in index and "| local-auto | MIT | `texts/MIT.txt` |" in index


def test_copied_notice_lines_cannot_swallow_a_rule(released: Path, tmp_path: Path):
    from suriharvest.release import loaded_rule_count

    f = tmp_path / "et" / "rules" / "emerging-malware.rules"
    f.write_text("# Copyright (c) 2026 Test Publisher \\\n# licence: MIT \\\\\n" + f.read_text())
    run("update")
    out = tmp_path / "rel"
    run("release", "build", str(out), "--engine", "suricata-7", "--build-epoch", "0", "--no-gates")
    summary = json.loads((out / "summary.json").read_text())["engines"]["suricata-7"]
    for name in ["suricata-7.rules", *(p.name for p in out.glob("suricata-7.by-source.*.rules"))]:
        text = (out / name).read_text()
        assert not any(line.rstrip().endswith("\\") for line in text.splitlines() if line.startswith("#")), name
    merged = (out / "suricata-7.rules").read_text()
    assert "Copyright (c) 2026 Test Publisher" in merged
    assert loaded_rule_count(merged) == summary["rules"]
    assert loaded_rule_count("# a \\\nalert x (sid:1;)\nalert y (sid:2;)\n") == 1  # what the check guards against


def test_release_ships_merged_configs_and_lists_duplicates(released: Path, tmp_path: Path):
    import io
    import tarfile

    from tests.test_pipeline import ET_V3

    et = tmp_path / "et"
    (et / "classification.config").write_text(
        "# publisher's file\nconfig classification: custom-thing,Custom thing,2\n"
        "config classification: trojan-activity,Redefined,4\nconfig classification: bad;name,x,1\n"
    )
    (et / "reference.config").write_text(
        "config reference: myref https://example.org/r/\nconfig reference: broken\n"
        "config reference: jsref javascript:alert(1)\nconfig reference: unused https://example.org/u/\n"
        "config reference: shared https://et.example.org/\nconfig reference: cve https://evil.example.org/\n"
    )
    (tmp_path / "repoA" / "reference.config").write_text("config reference: shared https://other.example.org/\n")
    write(
        et / "rules" / "extra.rules",
        'alert tcp any any -> any 7 (msg:"ET INFO odd class"; content:"zz"; classtype:nowhere-defined; '
        "reference:myref,1; reference:jsref,2; reference:shared,3; sid:2000777; rev:1;)",
    )
    write(
        tmp_path / "repoA" / "dup.rules",
        ET_V3.replace("sid:2000001", "sid:1000500").replace("ET MALWARE Foo", "renumbered Foo"),
        'alert tcp any any -> any 8 (msg:"repo A ref"; content:"yy"; reference:shared,4; sid:1000501; rev:1;)',
    )
    # a copy in a source that is not published (redistribute: no) must not be named in the manifest
    write(tmp_path / "repoB" / "dup.rules", ET_V3.replace("sid:2000001", "sid:1000600").replace("ET MALWARE Foo", "private Foo"))
    run("update")
    out = tmp_path / "rel"
    run("release", "build", str(out), "--engine", "suricata-7", "--build-epoch", "1763100000")
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress((out / "suriharvest-7.tar.gz").read_bytes()))) as tf:
        cls = tf.extractfile("rules/classification.config").read().decode()
        ref = tf.extractfile("rules/reference.config").read().decode()
    assert "config classification: custom-thing,Custom thing,2" in cls
    assert "config classification: trojan-activity,A Network Trojan was detected,1" in cls  # defaults win
    assert "Redefined" not in cls and "bad;name" not in cls
    assert "config classification: nowhere-defined,nowhere-defined,3" in cls  # used by a rule, defined nowhere
    assert "config reference: myref https://example.org/r/" in ref and "config reference: cve http://cve.mitre.org/" in ref
    assert "broken" not in ref and "javascript" not in ref and "evil" not in ref  # http(s) only; defaults kept
    assert "unused" not in ref  # only systems the source's own published rules use
    assert "config reference: shared" not in ref  # defined differently by two sources: dropped
    manifest = [json.loads(x) for x in gzip.decompress((out / "manifest.jsonl.gz").read_bytes()).splitlines()]
    pub = next(m for m in manifest if m["sid"] == 2000001 and not m.get("excluded_reason"))
    dup = [m for m in manifest if m.get("excluded_reason") == "duplicate"]
    assert [(d["sid"], d["source"], d["duplicate_of"]) for d in dup if d["sid"] == 1000500] == [
        (1000500, "repoA", f"1:{pub['exported_sid']}")
    ]
    assert not [d for d in dup if d["sid"] == 1000600 or d["source"] == "repoB"]
    assert pub["msg"].startswith("ET MALWARE Foo")
    # excluded rows are listed, not counted
    summary = json.loads((out / "summary.json").read_text())
    published = [m for m in manifest if not m.get("excluded_reason")]
    assert summary["engines"]["suricata-7"]["rules"] == len(published)


def test_empty_sid_map_ships_a_header_not_an_empty_file(released: Path, tmp_path: Path):
    """GitHub rejects 0-byte release assets (HTTP 400 Bad Content-Length): an empty map ships a comment header."""
    smap = released / "state" / "sid-map.tsv"
    smap.parent.mkdir(parents=True, exist_ok=True)
    smap.write_text("")
    out = tmp_path / "r"
    run(
        "release",
        "build",
        str(out),
        "--engine",
        "suricata-7",
        "--build-epoch",
        "1763100000",
        "--download-base",
        "https://example.invalid/dl",
    )
    text = (out / "sid-map.tsv").read_text()
    assert text.startswith("# logic_hash\t") and len(text.splitlines()) == 1
    assert not [p.name for p in out.iterdir() if p.stat().st_size == 0]
    assert "sid-map.tsv" in (out / "SHA256SUMS").read_text()
