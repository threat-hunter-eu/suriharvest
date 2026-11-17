"""Validation edge cases against a scripted fake Suricata (offline): long rules whose error line Suricata 7 cuts
short, causes Suricata 8 logs as warnings, dataset files, engines that cannot run, ruleset/engine versions.
The same cases run against real engines in tests/test_engine.py (pytest -m engine)."""

from __future__ import annotations

import tarfile
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from suriharvest.cli import app
from suriharvest.config import EngineConfig, SourceConfig, Workspace, default_ruleset_version
from suriharvest.validate import Engine, check_batch, dataset_paths, parse_errors, probe, rewrite_dataset_paths
from tests.fakes import python_script
from tests.test_pipeline import run, write

FAKE = r"""# Fake Suricata {version}: `-V`, and `-T -S FILE` reporting errors the way the real one does.
import re, sys
VERSION = "{version}"
args = sys.argv[1:]
if "-V" in args:
    print(f"This is Suricata version {{VERSION}} RELEASE"); sys.exit(0)
rules = args[args.index("-S") + 1]
import os
base = os.path.dirname(rules)
out, err = [], []
def log(stream, text):
    if VERSION.startswith("7"):
        text = text[:2047]  # Suricata 7 cuts a log line at about 2 KB
    stream.append(text)
for n, line in enumerate(open(rules, encoding="utf-8").read().splitlines(), start=1):
    sid = re.search(r"sid:(\d+);", line).group(1)
    causes = []
    if "BADKW" in line:
        causes.append("E: detect-parse: unknown rule keyword 'BADKW'.")
    if "NEED8" in line and VERSION.startswith("7"):
        causes.append("E: detect-parse: unknown rule keyword 'NEED8'.")
    m = re.search(r"load ([^,;\s]+)", line)
    if m:
        import os
        if not os.path.isfile(os.path.join(base, m.group(1))):
            causes.append("E: detect-dataset: failed to set up dataset 'x'.")
    warn_only = "WARNFAIL" in line and VERSION.startswith("8")
    if "WARNOK" in line or warn_only:
        log(out, f"W: detect-http-protocol: rule {{sid}}: Invalid http.protocol string containing a space")
    if causes or warn_only:
        for c in causes:
            log(err, c)
        log(err, f'E: detect: error parsing signature "{{line}}" from file {{rules}} at line {{n}}')
if err:
    err.append("E: suricata: Loading signatures failed.")
print("\n".join(out))
print("\n".join(err), file=sys.stderr)
sys.exit(1 if err else 0)
"""


def fake_engine(tmp_path: Path, version: str) -> Path:
    return python_script(tmp_path / f"fake-suricata-{version}", FAKE.format(version=version))


def rule(sid: int, body: str = "") -> str:
    return f'alert http any any -> any any (msg:"r{sid}"; {body}content:"x{sid}"; sid:{sid}; rev:1;)'


LONG = "A" * 3000


class Counting:
    def __init__(self, engine: Engine) -> None:
        self.engine, self.runs = engine, 0

    def run(self, rules_file: Path, workdir: Path) -> tuple[int, str]:
        self.runs += 1
        return self.engine.run(rules_file, workdir)


# ---------------------------------------------------------------------------------------------------------------
# bug 1: long rules on Suricata 7


@pytest.mark.parametrize("version", ["7.0.17", "8.0.8"])
def test_long_broken_rule_is_not_ok_and_errors_stay_with_their_rule(tmp_path: Path, version: str):
    eng = Counting(probe(EngineConfig("e", binary=str(fake_engine(tmp_path, version)))))
    rules = [
        ("ok1", rule(1)),
        ("long_bad", rule(2, f'content:"{LONG}"; BADKW; ')),
        ("ok3", rule(3)),
        ("long_ok", rule(4, f'content:"{LONG}"; ')),
        ("bad5", rule(5, "BADKW; ")),
    ]
    work = tmp_path / "w"
    work.mkdir()
    res = check_batch(eng, rules, work)  # type: ignore[arg-type]
    assert res["long_bad"].status == "error" and "unknown rule keyword 'BADKW'" in (res["long_bad"].error or "")
    assert res["bad5"].status == "error" and (res["bad5"].error or "").count("BADKW") == 1  # its own cause only
    assert [res[k].status for k in ("ok1", "ok3", "long_ok")] == ["ok", "ok", "ok"]
    assert eng.runs == 2  # one run + one check of the rules that passed; no bisection


def test_cut_error_line_matching_two_rules_is_resolved_without_guessing(tmp_path: Path):
    eng = Counting(probe(EngineConfig("e", binary=str(fake_engine(tmp_path, "7.0.17")))))
    head = f'alert http any any -> any any (msg:"same"; content:"{LONG}"; '
    rules = [("bad", head + "BADKW; sid:1; rev:1;)"), ("good", head + "sid:2; rev:1;)"), ("ok", rule(3))]
    work = tmp_path / "w"
    work.mkdir()
    res = check_batch(eng, rules, work)  # type: ignore[arg-type]
    assert res["bad"].status == "error" and res["good"].status == "ok" and res["ok"].status == "ok"


def test_parse_errors_suricata7_cut_line():
    long_sig = 'alert http any any -> any any (msg:"long"; content:"' + "A" * 2000
    out = (
        "E: detect-parse: unknown rule keyword 'foo_bar'.\n"
        f'E: detect: error parsing signature "{long_sig}\n'
        "E: detect-parse: unknown rule keyword 'nope_kw'.\n"
        'E: detect: error parsing signature "alert http any any -> any any (msg:\\"bad5\\"; nope_kw; sid:5; rev:1;)" '
        "from file /w/b.rules at line 5\n"
        "E: suricata: Loading signatures failed.\n"
    )
    p = parse_errors(out)
    assert p.errors == {5: "detect-parse: unknown rule keyword 'nope_kw'."}  # never the cause of the cut one
    assert p.unplaced == [(long_sig, "detect-parse: unknown rule keyword 'foo_bar'.")]


# ---------------------------------------------------------------------------------------------------------------
# bug 2: causes logged as W: (Suricata 8)


def test_warning_cause_is_kept_and_matched_by_sid(tmp_path: Path):
    eng = probe(EngineConfig("e", binary=str(fake_engine(tmp_path, "8.0.8"))))
    rules = [("warn_ok", rule(10, "WARNOK; ")), ("warn_fail", rule(11, "WARNFAIL; ")), ("bad", rule(12, "BADKW; "))]
    work = tmp_path / "w"
    work.mkdir()
    res = check_batch(eng, rules, work)
    assert res["warn_ok"].status == "ok"
    assert res["warn_fail"].status == "error" and "rule 11: Invalid http.protocol" in (res["warn_fail"].error or "")
    assert "rule 10" not in (res["bad"].error or "") and "rule 10" not in (res["warn_fail"].error or "")


def test_parse_errors_suricata8_warning_on_stdout():
    out = (
        "W: detect-http-protocol: rule 2019236: Invalid http.protocol string containing a space\n"
        "W: detect: rule 7: something harmless\n"
        "W: detect: rule files specified, but no rules were loaded\n"
        'E: detect: error parsing signature "alert http any any -> any any (msg:\\"x\\"; sid:2019236; rev:1;)" from file /w/b.rules at line 1\n'
    )
    assert parse_errors(out).errors == {1: "detect-http-protocol: rule 2019236: Invalid http.protocol string containing a space"}


# ---------------------------------------------------------------------------------------------------------------
# bug 3: dataset rules load with their files and are published with them


def test_rewrite_dataset_paths():
    r = 'alert dns any any -> any any (msg:"m"; dns.query; dataset:isset,ph,type string,load datasets/ph.txt; content:"dataset:x load y"; sid:1;)'
    out = rewrite_dataset_paths(r, lambda p: f"datasets/src/{p}")
    assert out is not None and "load datasets/src/datasets/ph.txt;" in out and 'content:"dataset:x load y"' in out
    assert rewrite_dataset_paths(r, lambda p: None) is None


@pytest.mark.parametrize(
    "opt",
    [
        "DataSet:isset,ph,type string,load /etc/passwd",  # uppercase keyword, absolute path
        "dataset:isset,ph,type string,LOAD ../../etc/x",  # .. path
        "dataset:isset,ph,type string,state /var/lib/x.lst",  # state path
        "dataset:set,ph,type string,save out.lst",  # writes a file on the sensor
        r"dataset:isset,ph,type string,load a\;b",  # escaped semicolon inside the value
        "datarep:ph,>,5,type string,load /tmp/rep.csv",
    ],
)
def test_unsafe_dataset_paths_leave_the_rule_out(opt: str):
    r = f'alert dns any any -> any any (msg:"m"; dns.query; {opt}; sid:1;)'
    assert dataset_paths(r), r  # always seen, so the release looks at the rule
    assert rewrite_dataset_paths(r, lambda p: f"datasets/src/{p}") is None


def test_dataset_option_split_like_suricata():
    # a quoted ";" in msg does not hide the dataset option; an uppercase keyword is still found and rewritten
    r = r'alert dns any any -> any any (msg:"a\; DATASET:isset,x,load evil"; dns.query; DATASET:isset,ph,type string,load lists/ph.txt; sid:1;)'
    assert dataset_paths(r) == ["lists/ph.txt"]
    out = rewrite_dataset_paths(r, lambda p: f"datasets/src/{p}")
    assert out is not None and "load datasets/src/lists/ph.txt;" in out and "load evil" in out


DS_RULE = 'alert dns any any -> any any (msg:"DBL phishing"; dns.query; dataset:isset,phishing,type string,load lists/phishing.txt; sid:12001901; rev:1;)'


@pytest.fixture
def matrix(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Workspace with engines suricata-7 and suricata-8 (fakes), a source with a dataset file (min_suricata 8)."""
    root = tmp_path / "ws"
    monkeypatch.setenv("SURIHARVEST_HOME", str(root))
    monkeypatch.chdir(tmp_path)
    f7, f8 = fake_engine(tmp_path, "7.0.17"), fake_engine(tmp_path, "8.0.8")
    run("init", str(root), "--engine", f"suricata-7={f7}", "--engine", f"suricata-8={f8}")
    write(tmp_path / "dbl" / "rules" / "phishing.rules", "# License: CC BY-SA 4.0", DS_RULE)
    write(tmp_path / "dbl" / "rules" / "lists" / "phishing.txt", "ZXZpbC5leGFtcGxl")
    write(tmp_path / "plain" / "p.rules", rule(1000001))
    srcs = [
        {
            "name": "dbl",
            "type": "local",
            "url": str(tmp_path / "dbl"),
            "licence": "CC-BY-SA-4.0",
            "copyright": "Copyright (c) 2026 Test Publisher",
            "redistribute": "yes",
            "min_suricata": 8,
        },
        {
            "name": "plain",
            "type": "local",
            "url": str(tmp_path / "plain"),
            "licence": "MIT",
            "copyright": "Copyright (c) 2026 Test Publisher",
            "redistribute": "yes",
        },
    ]
    (root / "sources.yaml").write_text(yaml.safe_dump({"sources": srcs}))
    monkeypatch.chdir(root)
    run("update")
    return root


def test_dataset_rule_validates_with_its_file_and_ships_with_it(matrix: Path, tmp_path: Path):
    from suriharvest.db import session_factory
    from suriharvest.models import LogicGroup

    with session_factory(matrix / "data" / "suriharvest.db")() as s:
        g = next(x for x in s.query(LogicGroup) if x.sid == 12001901)
        assert g.loads_in == ["suricata-7", "suricata-8"]  # the fakes accept it once the file is next to it
        assert "does_not_load" not in g.flags
    out = tmp_path / "rel"
    run("release", "build", str(out), "--engine", "suricata-7", "--engine", "suricata-8", "--build-epoch", "0")
    want = "load datasets/dbl/lists/phishing.txt;"
    assert want in (out / "suricata-8.rules").read_text()
    assert want in (out / "suricata-8.by-source.dbl.rules").read_text()
    assert "12001901" not in (out / "suricata-7.rules").read_text()  # min_suricata 8: only in the 8 build
    assert not (out / "suricata-7.datasets.tar.gz").exists()
    with tarfile.open(out / "suricata-8.datasets.tar.gz") as tf:
        assert tf.extractfile("datasets/dbl/lists/phishing.txt").read() == b"ZXZpbC5leGFtcGxl\n"  # type: ignore[union-attr]
    with tarfile.open(out / "suriharvest-8.tar.gz") as tf:
        names = set(tf.getnames())
    # a relative load resolves next to the rule file; one rules file only (suricata-update loads every *.rules)
    assert "rules/datasets/dbl/lists/phishing.txt" in names
    assert not any(x.startswith("rules/by-source/") for x in names)
    assert [x for x in names if x.endswith(".rules")] == ["rules/suricata.rules"]
    summary = yaml.safe_load((out / "summary.json").read_text())
    assert summary["engines"]["suricata-8"]["dataset_files"] == ["datasets/dbl/lists/phishing.txt"]


def test_dataset_rule_without_its_file_is_missing_file_not_does_not_load(matrix: Path):
    (matrix.parent / "dbl" / "rules" / "lists" / "phishing.txt").unlink()
    from suriharvest.db import session_factory
    from suriharvest.models import LogicGroup, ValidationResult

    with session_factory(matrix / "data" / "suriharvest.db")() as s:
        s.query(ValidationResult).delete()
        s.commit()
    run("validate")
    with session_factory(matrix / "data" / "suriharvest.db")() as s:
        g = next(x for x in s.query(LogicGroup) if x.sid == 12001901)
        assert g.loads_in == [] and g.fails_in == [] and "needs_files" in g.flags and "does_not_load" not in g.flags


# ---------------------------------------------------------------------------------------------------------------
# bug 4: an engine that cannot run fails update and release build


def test_broken_engine_fails_update_and_release(matrix: Path, tmp_path: Path):
    cfg = yaml.safe_load((matrix / "suriharvest.yaml").read_text())
    cfg["engines"].append({"name": "suricata-9", "binary": str(tmp_path / "does-not-exist")})
    (matrix / "suriharvest.yaml").write_text(yaml.safe_dump(cfg))
    r = CliRunner().invoke(app, ["update", "--allow-failures"])
    assert r.exit_code == 1, r.output
    assert "engine suricata-9" in r.output and "failed" in r.output
    out = tmp_path / "rel9"
    r = CliRunner().invoke(app, ["release", "build", str(out), "--engine", "suricata-9", "--build-epoch", "0"])
    assert r.exit_code != 0 and "without validation results" in r.output, r.output
    assert not out.exists() or not any(out.iterdir())


def test_engine_with_the_wrong_version_is_refused(tmp_path: Path):
    with pytest.raises(RuntimeError, match="expected Suricata 8"):
        probe(EngineConfig("suricata-8", binary=str(fake_engine(tmp_path, "7.0.17"))))


# ---------------------------------------------------------------------------------------------------------------
# limitation 5: engine versions vs the ruleset version


def test_engine_and_ruleset_versions(tmp_path: Path):
    e7 = EngineConfig("suricata-7", binary=None, image="docker.io/jasonish/suricata:7.0.17@sha256:" + "a" * 64)
    e8 = EngineConfig("suricata-8", binary=None, image="docker.io/jasonish/suricata:8.0.8@sha256:" + "b" * 64)
    assert (e7.suricata_version, e8.suricata_version) == ("7.0.17", "8.0.8")
    assert EngineConfig("suricata-8").suricata_version == "8"
    assert EngineConfig("local").suricata_version is None
    assert EngineConfig("x", version="8.0.1").suricata_version == "8.0.1"
    assert default_ruleset_version([e7, e8]) == "8.0.8" and default_ruleset_version([EngineConfig("local")]) == "7.0.3"
    et = SourceConfig(
        "et-open",
        "http-tarball",
        "https://rules.emergingthreats.net/open/suricata-${suricata_version}/x.tar.gz",
        url_versions={"7": "7.0.3", "8": "8.0"},
    )
    assert "suricata-8.0/" in et.resolved_url(default_ruleset_version([e7, e8]))
    w = Workspace(tmp_path)
    (tmp_path / "suriharvest.yaml").write_text("suricata_version: '7.0.3'\nengines:\n  - name: suricata-8\n    image: x/suricata:8.0.8\n")
    assert w.settings().ruleset_version == "7.0.3"  # the old key still works
    (tmp_path / "suriharvest.yaml").write_text("engines:\n  - name: suricata-8\n    image: x/suricata:8.0.8\n")
    assert w.settings().ruleset_version == "8.0.8" and w.settings().max_engine_version == "8.0.8"


@pytest.mark.parametrize(("engines", "enabled", "ruleset"), [(["7", "8"], True, "8.0.8"), (["7"], False, "7.0.17")])
def test_init_enables_min_suricata_sources_for_the_newest_engine(tmp_path: Path, engines: list[str], enabled: bool, ruleset: str):
    root = tmp_path / "ws"
    args = [x for n in engines for x in ("--engine", f"suricata-{n}=docker.io/jasonish/suricata:{n}.0.{'17' if n == '7' else '8'}")]
    r = CliRunner().invoke(app, ["init", str(root), "--tier", "community", *args], catch_exceptions=False)
    assert r.exit_code == 0, r.output
    srcs = {x["name"]: x for x in yaml.safe_load((root / "sources.yaml").read_text())["sources"]}
    assert srcs["ipfire-dbl"]["enabled"] is enabled
    assert yaml.safe_load((root / "suriharvest.yaml").read_text())["ruleset_version"] == ruleset
