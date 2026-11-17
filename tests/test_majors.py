"""Per-major rulesets (majors.py), offline: a fake upstream serves a different tarball for Suricata 7.0.3 and 8.0;
fake engines 7 and 8 validate. Each engine's build must come from its own major's copy, identical texts stay one
rule (one version, one logic group, no sid remapping)."""

from __future__ import annotations

import gzip
import io
import json
import os
import shutil
import tarfile
from pathlib import Path

import pytest
import yaml

from suriharvest.config import EngineConfig, Settings, SourceConfig
from suriharvest.majors import engine_rulesets, source_rulesets, strip_variant, variant, variant_dir
from tests.test_engine_offline import fake_engine
from tests.test_pipeline import run, write

URL = "https://rules.example.invalid/open/suricata-${suricata_version}/emerging.rules.tar.gz"
HEAD = "# Copyright (c) Example Threats {v}\n# Licensed under the MIT licence"
SHARED = 'alert http any any -> any any (msg:"ET SHARED same text"; http.uri; content:"/same"; sid:2000001; rev:1;)'
REV7 = 'alert http any any -> any any (msg:"ET SAME logic"; http.uri; content:"/logic"; metadata:branch 7; sid:2000002; rev:2;)'
REV8 = 'alert http any any -> any any (msg:"ET SAME logic"; http.uri; content:"/logic"; metadata:branch 8; sid:2000002; rev:3;)'
OLD7 = 'alert http any any -> any any (msg:"ET NEWKW check"; http.uri; content:"/old-way"; sid:2000003; rev:4;)'
NEW8 = 'alert http any any -> any any (msg:"ET NEWKW check"; http.uri; content:"/new-way"; NEED8; sid:2000003; rev:5;)'
GONE8 = 'alert http any any -> any any (msg:"ET only in the 7 branch"; http.uri; content:"/legacy"; sid:2000004; rev:1;)'
PLAIN = 'alert tcp any any -> any 4444 (msg:"plain shared"; content:"plainshared"; sid:1000001; rev:1;)'


def tarball(files: dict[str, str]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tf:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return gzip.compress(raw.getvalue(), mtime=0)


UPSTREAM = {
    "7.0.3": tarball(
        {"rules/emerging.rules": "\n".join([HEAD.format(v=7), SHARED, REV7, OLD7, GONE8]) + "\n", "rules/LICENSE": "licence text of 7\n"}
    ),
    "8.0": tarball(
        {"rules/emerging.rules": "\n".join([HEAD.format(v=8), SHARED, REV8, NEW8]) + "\n", "rules/LICENSE": "licence text of 8\n"}
    ),
}


@pytest.fixture
def calls(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, dict | None]]:
    from suriharvest import sync

    seen: list[tuple[str, dict | None]] = []

    def fake_download(url, token=None, validators=None, allow_private=False):
        seen.append((url, validators))
        version = url.split("/suricata-", 1)[1].split("/", 1)[0]
        data = UPSTREAM[version]
        etag = str(hash(data))
        if validators and validators.get("etag") == etag:
            return None, validators  # 304
        return data, {"etag": etag}

    monkeypatch.setattr(sync, "download", fake_download)
    return seen


@pytest.fixture
def ws(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, calls: list) -> Path:
    root = tmp_path / "ws"
    monkeypatch.setenv("SURIHARVEST_HOME", str(root))
    monkeypatch.chdir(tmp_path)
    f7, f8 = fake_engine(tmp_path, "7.0.17"), fake_engine(tmp_path, "8.0.8")
    run("init", str(root), "--engine", f"suricata-7={f7}", "--engine", f"suricata-8={f8}")
    write(tmp_path / "plain" / "p.rules", PLAIN)
    srcs = [
        {
            "name": "et",
            "type": "http-tarball",
            "url": URL,
            "url_versions": {"7": "7.0.3", "8": "8.0"},
            "licence": "MIT",
            "redistribute": "yes",
            "sid_namespace": "et",
            "priority": 10,
            "licence_files": ["rules/LICENSE"],
        },
        {
            "name": "plain",
            "type": "local",
            "url": str(tmp_path / "plain"),
            "licence": "MIT",
            "redistribute": "yes",
            "copyright": "Copyright (c) Plain Example",
        },
    ]
    (root / "sources.yaml").write_text(yaml.safe_dump({"sources": srcs}))
    # the fakes report 7.0.17 / 8.0.8; say so, as an image tag would
    cfg = yaml.safe_load((root / "suriharvest.yaml").read_text())
    for e in cfg["engines"]:
        e["version"] = "7.0.17" if e["name"] == "suricata-7" else "8.0.8"
    (root / "suriharvest.yaml").write_text(yaml.safe_dump(cfg))
    monkeypatch.chdir(root)
    run("update")
    return root


def db(root: Path):
    from suriharvest.db import session_factory

    return session_factory(root / "data" / "suriharvest.db")()


def test_versions_per_major():
    e7, e8 = EngineConfig("suricata-7", version="7.0.17"), EngineConfig("suricata-8", version="8.0.8")
    both = Settings(ruleset_version="8.0.8", engines=[e7, e8])
    assert engine_rulesets(both) == {"7": "7.0.17", "8": "8.0.8"}
    assert engine_rulesets(Settings(ruleset_version="8.0.1", engines=[e7, e8])) == {"7": "7.0.17", "8": "8.0.1"}
    assert engine_rulesets(Settings(ruleset_version="8.0.8", engines=[e8, EngineConfig("suricata-8b", version="8.0.2")])) == {}
    et = SourceConfig("et", "http-tarball", URL, url_versions={"7": "7.0.3", "8": "8.0"})
    assert source_rulesets(et, both) == {"7": "7.0.17", "8": "8.0.8"}
    assert [et.resolved_url(v) for v in source_rulesets(et, both).values()] == [
        URL.replace("${suricata_version}", "7.0.3"),
        URL.replace("${suricata_version}", "8.0"),
    ]
    assert source_rulesets(SourceConfig("x", "http-file", "https://x.example/r.rules"), both) == {}  # no placeholder: shared
    assert source_rulesets(SourceConfig("g", "git", "https://x.example/${suricata_version}.git"), both) == {}  # git: shared
    new = SourceConfig("n", "http-file", URL, min_suricata="8")
    assert source_rulesets(new, both) == {"8": "8.0.8"}  # written for 8: no 7 copy
    assert variant("@8/rules/x.rules") == "8" and variant("rules/x.rules") is None and strip_variant("@7/a/b.rules") == "a/b.rules"


def test_variant_dir_picks_own_then_older(tmp_path: Path):
    for d in ("@7", "@8"):
        (tmp_path / d).mkdir()
    assert variant_dir(tmp_path, "7").name == "@7" and variant_dir(tmp_path, "8").name == "@8"
    assert variant_dir(tmp_path, "9").name == "@8" and variant_dir(tmp_path, "6").name == "@7"
    assert variant_dir(tmp_path, None).name == "@8"
    assert variant_dir(tmp_path / "missing", "7") == tmp_path / "missing"


def test_one_download_per_major_stored_apart(ws: Path, calls: list):
    assert sorted(u.split("/suricata-")[1].split("/")[0] for u, _ in calls) == ["7.0.3", "8.0"]
    assert sorted(p.name for p in (ws / "corpus" / "et").iterdir()) == ["@7", "@8"]
    assert (ws / "corpus" / "et" / "@7" / "rules" / "LICENSE").read_text() == "licence text of 7\n"
    from suriharvest.models import Occurrence, RuleVersion

    with db(ws) as s:
        paths = {(v.sid, v.rev, o.path) for o, v in s.query(Occurrence, RuleVersion).filter(Occurrence.version_id == RuleVersion.id)}
    assert (2000001, 1, "@7/rules/emerging.rules") in paths and (2000001, 1, "@8/rules/emerging.rules") in paths
    assert (1000001, 1, "p.rules") in paths  # a shared source keeps plain paths
    # nothing changed upstream: conditional requests per major, answered 304, nothing re-ingested
    calls.clear()
    out = run("update")
    assert len(calls) == 2 and all(v and v.get("etag") for _, v in calls), calls
    assert "ok et: unchanged" in out.replace("[green]", "").replace("[/]", "")


def test_identity_is_shared_validation_is_per_major(ws: Path):
    from suriharvest.models import LogicGroup, Occurrence, RuleVersion, ValidationResult

    with db(ws) as s:
        shared = s.query(RuleVersion).filter_by(sid=2000001).all()
        assert len(shared) == 1  # the same text in both copies is one version ...
        assert s.query(Occurrence).filter_by(version_id=shared[0].id).count() == 2  # ... seen twice
        same = s.query(RuleVersion).filter_by(sid=2000002).all()
        assert len(same) == 2 and len({v.logic_hash for v in same}) == 1  # rev/metadata differ: one logic
        assert s.query(LogicGroup).filter_by(sid=2000002).count() == 1
        by_rev = {v.rev: v.content_hash for v in s.query(RuleVersion).filter(RuleVersion.sid.in_([2000002, 2000003]))}
        engines = {h: {e for (e,) in s.query(ValidationResult.engine).filter_by(content_hash=h)} for h in by_rev.values()}
        assert engines[by_rev[2]] == {"suricata-7"} and engines[by_rev[4]] == {"suricata-7"}  # 7 copy: only engine 7
        assert engines[by_rev[3]] == {"suricata-8"} and engines[by_rev[5]] == {"suricata-8"}  # 8 copy: only engine 8
        g_new = next(g for g in s.query(LogicGroup).filter_by(sid=2000003) if g.rev == 5)
        assert g_new.loads_in == ["suricata-8"] and g_new.fails_in == []  # never tried on 7: not a failure there
        g_logic = s.query(LogicGroup).filter_by(sid=2000002).one()
        assert g_logic.loads_in == ["suricata-7", "suricata-8"]
        g_shared = s.query(LogicGroup).filter_by(sid=2000001).one()
        assert g_shared.loads_in == ["suricata-7", "suricata-8"]


def test_release_publishes_each_major_from_its_own_copy(ws: Path, tmp_path: Path):
    out = tmp_path / "rel"
    run("release", "build", str(out), "--engine", "suricata-7", "--engine", "suricata-8", "--build-epoch", "0")
    r7, r8 = (out / "suricata-7.rules").read_text(), (out / "suricata-8.rules").read_text()
    for text in (SHARED, PLAIN):
        assert text in r7 and text in r8
    assert REV7 in r7 and OLD7 in r7 and GONE8 in r7 and "NEED8" not in r7 and REV8 not in r7
    assert REV8 in r8 and NEW8 in r8 and GONE8 not in r8 and OLD7 not in r8 and REV7 not in r8
    assert "Example Threats 7" in r7 and "Example Threats 8" in r8  # each engine's file carries its copy's notice
    assert json.loads((out / "collisions.json").read_text()) == []  # same sids in both: nothing remapped
    with tarfile.open(out / "suriharvest-7.tar.gz") as tf:
        assert tf.extractfile("LICENSES/et/rules__LICENSE").read() == b"licence text of 7\n"  # type: ignore[union-attr]
    with tarfile.open(out / "suriharvest-8.tar.gz") as tf:
        assert tf.extractfile("LICENSES/et/rules__LICENSE").read() == b"licence text of 8\n"  # type: ignore[union-attr]
    rows = [json.loads(x) for x in gzip.decompress((out / "manifest.jsonl.gz").read_bytes()).splitlines()]
    sids = {(r["engine"], r["exported_sid"], r["rev"]) for r in rows if r["source"] == "et"}
    assert sids == {
        ("suricata-7", 2000001, 1),
        ("suricata-7", 2000002, 2),
        ("suricata-7", 2000003, 4),
        ("suricata-7", 2000004, 1),
        ("suricata-8", 2000001, 1),
        ("suricata-8", 2000002, 3),
        ("suricata-8", 2000003, 5),
    }
    same = {r["logic_hash"] for r in rows if r["exported_sid"] == 2000002}
    assert len(same) == 1  # one logic hash for both engines' copy of the rule


def test_profile_builds_follow_their_engine(ws: Path):
    run("profile", "create", "p7", "--engine", "suricata-7")
    run("profile", "create", "p8", "--engine", "suricata-8")
    for name, want, never in (("p7", (REV7, OLD7, GONE8), (NEW8, REV8)), ("p8", (REV8, NEW8), (OLD7, REV7, GONE8))):
        run("profile", "build", name)
        prof = ws / "data" / "profiles" / name  # the LATEST pointer file (no latest symlink on Windows)
        text = (prof / (prof / "LATEST").read_text().strip() / "suricata.rules").read_text()
        assert all(x in text for x in want) and not any(x in text for x in never), (name, text)


@pytest.mark.engine
@pytest.mark.skipif(
    not os.environ.get("SURIHARVEST_TEST_ENGINE_IMAGE") and shutil.which("suricata") is None, reason="suricata not installed"
)
def test_real_engine_validates_and_publishes_its_own_copy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, calls: list):
    """The real engine (local binary or SURIHARVEST_TEST_ENGINE_IMAGE) next to a fake engine of the other major: the
    real one checks only its own major's copy (the other copy's rule would not load in it) and publishes from it."""
    from suriharvest.validate import probe

    image = os.environ.get("SURIHARVEST_TEST_ENGINE_IMAGE")
    real_cfg = {"binary": None, "image": image} if image else {"binary": shutil.which("suricata")}
    version = probe(EngineConfig("probe", **real_cfg)).version  # type: ignore[arg-type]
    real, other = ("8", "7") if version.startswith("8") else ("7", "8")
    fake = fake_engine(tmp_path, "7.0.17" if other == "7" else "8.0.8")
    root = tmp_path / "ws"
    monkeypatch.setenv("SURIHARVEST_HOME", str(root))
    monkeypatch.chdir(tmp_path)
    run("init", str(root))
    real_rule = f'alert http any any -> any any (msg:"ET real {real}"; http.uri; content:"/real"; sid:2100001; rev:1;)'
    other_rule = f'alert http any any -> any any (msg:"ET only {other}"; http.uri; content:"/other"; foo_bar_kw; sid:2100002; rev:1;)'
    upstream = {real: real_rule, other: other_rule}
    folder = {"7": "7.0.3", "8": "8.0"}
    saved = dict(UPSTREAM)
    try:
        for m, text in upstream.items():
            UPSTREAM[folder[m]] = tarball({"rules/emerging.rules": SHARED + "\n" + text + "\n"})
        src = {
            "name": "et",
            "type": "http-tarball",
            "url": URL,
            "url_versions": folder,
            "licence": "MIT",
            "redistribute": "yes",
            "copyright": "Copyright (c) Example Threats",
        }
        (root / "sources.yaml").write_text(yaml.safe_dump({"sources": [src]}))
        engines = [
            {"name": f"suricata-{real}", "version": version, **real_cfg},
            {"name": f"suricata-{other}", "binary": str(fake), "version": "7.0.17" if other == "7" else "8.0.8"},
        ]
        (root / "suriharvest.yaml").write_text(yaml.safe_dump({"engines": engines}))
        monkeypatch.chdir(root)
        run("update")
        out = tmp_path / "rel"
        run("release", "build", str(out), "--engine", f"suricata-{real}", "--engine", f"suricata-{other}", "--build-epoch", "0")
    finally:
        UPSTREAM.clear()
        UPSTREAM.update(saved)
    from suriharvest.models import LogicGroup, ValidationResult

    with db(root) as s:
        g_real = s.query(LogicGroup).filter_by(sid=2100001).one()
        g_shared = s.query(LogicGroup).filter_by(sid=2000001).one()
        assert f"suricata-{real}" in g_real.loads_in and f"suricata-{real}" in g_shared.loads_in  # the real engine loaded them
        assert s.query(ValidationResult).filter_by(engine=f"suricata-{real}").count() == 2  # its copy only: shared + own
    text = (out / f"suricata-{real}.rules").read_text()
    assert real_rule in text and SHARED in text and "foo_bar_kw" not in text


def test_path_form_file_selector_matches_per_major_copies(ws: Path):
    """A `file` exclusion written as the path in the source (rules/emerging.rules) still matches when
    the source is downloaded once per major (occurrence paths @7/rules/..., @8/rules/...)."""
    run("profile", "create", "p8", "--engine", "suricata-8")
    assert "matches 0 rules" not in run("profile", "exclude", "p8", "rules/emerging.rules", "--kind", "file")
    run("profile", "build", "p8")
    prof = ws / "data" / "profiles" / "p8"
    text = (prof / (prof / "LATEST").read_text().strip() / "suricata.rules").read_text()
    assert "ET " not in text and "plain shared" in text
