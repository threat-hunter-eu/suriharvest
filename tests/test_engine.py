"""Validation against a real Suricata (run with: pytest -m engine).

Uses the local `suricata` binary (CI runs these tests inside the pinned engine images), or a docker image when
SURIHARVEST_TEST_ENGINE_IMAGE is set (e.g. docker.io/jasonish/suricata:8.0.8@sha256:...)."""

import os
import shutil
from pathlib import Path

import pytest

from suriharvest.config import EngineConfig, version_tuple
from suriharvest.validate import Engine, batches, categorise, check_batch, parse_output, probe

pytestmark = pytest.mark.engine

IMAGE = os.environ.get("SURIHARVEST_TEST_ENGINE_IMAGE")
needs_engine = pytest.mark.skipif(not IMAGE and shutil.which("suricata") is None, reason="suricata not installed")

RULES = [
    ("ok", 'alert http any any -> any any (msg:"ok"; http.uri; content:"/a"; sid:1; rev:1;)'),
    ("unknown", 'alert http any any -> any any (msg:"bad kw"; foo_bar; content:"x"; sid:2; rev:1;)'),
    ("snort3", 'alert tcp any any -> any any (msg:"snort3"; service:http; content:"x"; sid:3; rev:1;)'),
    ("dataset", 'alert http any any -> any any (msg:"ds"; http.host; dataset:isset,foo,type string,load foo.lst; sid:4; rev:1;)'),
    ("modbus", 'alert modbus any any -> any any (msg:"modbus"; modbus:function 1; sid:5; rev:1;)'),
]
LONG = "A" * 3000


class Counting:
    """An engine that counts its runs: a batch whose errors were all read needs one run plus one re-check."""

    def __init__(self, engine: Engine) -> None:
        self.engine, self.version, self.runs = engine, engine.version, 0

    def run(self, rules_file: Path, workdir: Path) -> tuple[int, str]:
        self.runs += 1
        return self.engine.run(rules_file, workdir)


def _engine() -> Engine:
    cfg = EngineConfig("test", binary=None, image=IMAGE) if IMAGE else EngineConfig("local")
    return probe(cfg)


def _workdir(tmp_path: Path, name: str = "w") -> Path:
    d = tmp_path / name
    d.mkdir()
    d.chmod(0o777)  # the container may run Suricata as another user
    return d


@needs_engine
def test_errors_map_to_rules(tmp_path: Path):
    eng = Counting(_engine())
    res = check_batch(eng, RULES, _workdir(tmp_path))  # type: ignore[arg-type]
    assert res["ok"].status == "ok"
    assert res["modbus"].status == "ok"  # protocol detection enabled by our overrides
    assert categorise(res["unknown"].error) == "unknown_keyword"
    assert categorise(res["snort3"].error) == "unknown_keyword"  # foreign syntax fails to load
    assert categorise(res["dataset"].error) == "missing_file"
    assert eng.runs == 2  # every error was read from the output: no bisection


@needs_engine
def test_long_broken_rule_is_not_ok(tmp_path: Path):
    """Suricata 7 cuts the error line of a rule longer than ~2 KB: the rule must still be an error, with its own
    cause, and the next error must keep its own cause."""
    eng = Counting(_engine())
    rules = [
        ("ok1", 'alert http any any -> any any (msg:"ok1"; content:"/a"; sid:1; rev:1;)'),
        ("long_bad", f'alert http any any -> any any (msg:"long"; content:"{LONG}"; foo_bar; sid:2; rev:1;)'),
        ("ok3", 'alert http any any -> any any (msg:"ok3"; content:"/b"; sid:3; rev:1;)'),
        ("long_ok", f'alert http any any -> any any (msg:"long ok"; content:"{LONG}"; sid:4; rev:1;)'),
        ("bad5", 'alert http any any -> any any (msg:"bad5"; nope_kw; sid:5; rev:1;)'),
    ]
    res = check_batch(eng, rules, _workdir(tmp_path))  # type: ignore[arg-type]
    assert res["long_bad"].status == "error" and "foo_bar" in (res["long_bad"].error or "")
    assert res["bad5"].status == "error" and "nope_kw" in (res["bad5"].error or "") and "foo_bar" not in (res["bad5"].error or "")
    assert [res[k].status for k in ("ok1", "ok3", "long_ok")] == ["ok", "ok", "ok"]
    assert eng.runs == 2


@needs_engine
def test_cause_logged_as_warning_is_kept(tmp_path: Path):
    """Suricata 8 rejects an http.protocol with a space and says why only on a W: line (sid 2019236 in ET)."""
    eng = _engine()
    rules = [
        ("space", 'alert http any any -> any any (msg:"proto"; http.protocol; content:"HTTP/1.1 x"; sid:1; rev:1;)'),
        ("bad", 'alert http any any -> any any (msg:"bad"; nope_kw; sid:2; rev:1;)'),
    ]
    res = check_batch(eng, rules, _workdir(tmp_path))
    assert "nope_kw" in (res["bad"].error or "") and "http.protocol" not in (res["bad"].error or "")
    if version_tuple(eng.version) >= (8,):
        assert res["space"].status == "error" and "Invalid http.protocol" in (res["space"].error or ""), res["space"]
    else:
        assert res["space"].status == "ok"


@needs_engine
def test_dataset_rule_loads_with_its_file(tmp_path: Path):
    lst = tmp_path / "src" / "lists" / "foo.lst"
    lst.parent.mkdir(parents=True)
    lst.write_text("ZXZpbC5leGFtcGxl\n")  # base64("evil.example")
    rule = 'alert http any any -> any any (msg:"ds"; http.host; dataset:isset,foo,type string,load lists/foo.lst; sid:4; rev:1;)'
    res = check_batch(_engine(), [("ds", rule)], _workdir(tmp_path), {"lists/foo.lst": lst})
    assert res["ds"].status == "ok", res["ds"].error


@pytest.mark.engine
def test_parse_output_and_batches():
    out = (
        "E: detect-parse: unknown rule keyword 'foo_bar'.\n"
        'E: detect: error parsing signature "alert ..." from file /w/b.rules at line 2\n'
        "E: suricata: Loading signatures failed.\n"
    )
    assert parse_output(out) == {2: "detect-parse: unknown rule keyword 'foo_bar'."}
    bs = batches([(1, 1, "a", "x"), (1, 1, "b", "y"), (1, 2, "c", "z")], size=10)
    assert [len(b) for b in bs] == [2, 1]


# ---------------------------------------------------------------------------------------------------------------
# Every written ruleset (release, profile build, export, feed) loads in a real Suricata with dataset sources that
# reuse a dataset name, ship a missing file and name an absolute path.

DS_ET = 'alert dns any any -> any any (msg:"ET DNS bad list"; dns.query; dataset:isset,baddomains,type string,load lists/bad.lst; sid:2000002; rev:1;)'
DS_OTHER = 'alert dns any any -> any any (msg:"other bad list"; dns.query; dataset:isset,baddomains,type string,load lists/mine.lst; sid:9000003; rev:1;)'
DS_GONE = 'alert dns any any -> any any (msg:"file not shipped"; dns.query; dataset:isset,gone,type string,load lists/gone.lst; sid:9000004; rev:1;)'
DS_ABS = 'alert dns any any -> any any (msg:"absolute"; dns.query; dataset:isset,host,type string,load /etc/hostname; sid:9000005; rev:1;)'
PLAIN = 'alert http any any -> any any (msg:"ET WEB plain"; http.uri; content:"/plain"; sid:2000010; rev:1;)'


def _suricata_t(rules: Path, log: Path) -> None:
    import subprocess

    log.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(["suricata", "-T", "-S", str(rules), "-l", str(log)], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, f"{rules}: {proc.stdout[-2000:]} {proc.stderr[-2000:]}"


@pytest.mark.skipif(IMAGE is not None or shutil.which("suricata") is None, reason="needs a local suricata")
def test_every_written_ruleset_loads_with_dataset_sources(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    import io
    import tarfile

    import yaml
    from fastapi.testclient import TestClient

    from suriharvest.config import Workspace
    from suriharvest.web.app import create_app
    from tests.test_pipeline import run, write

    root = tmp_path / "ws"
    monkeypatch.setenv("SURIHARVEST_HOME", str(root))
    monkeypatch.chdir(tmp_path)
    major = probe(EngineConfig("local")).version.split(".")[0]  # the CI images run 7 and 8 under the same name
    eng = f"suricata-{major}"
    run("init", str(root), "--engine", f"{eng}={shutil.which('suricata')}")
    write(tmp_path / "et" / "rules" / "a.rules", DS_ET, PLAIN)
    write(tmp_path / "et" / "rules" / "lists" / "bad.lst", "ZXZpbC5leGFtcGxl")
    write(tmp_path / "other" / "o.rules", DS_OTHER, DS_GONE, DS_ABS)
    write(tmp_path / "other" / "lists" / "mine.lst", "bWluZS5leGFtcGxl")
    srcs = [
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
            "name": "aaa-other",
            "type": "local",
            "url": str(tmp_path / "other"),
            "priority": 80,
            "licence": "MIT",
            "copyright": "Copyright (c) 2026 Other",
            "redistribute": "yes",
        },
    ]
    (root / "sources.yaml").write_text(yaml.safe_dump({"sources": srcs}))
    monkeypatch.chdir(root)
    run("update")
    # release: the suricata-update tarball, merged and per-source files
    rel = tmp_path / "rel"
    run("release", "build", str(rel), "--engine", eng, "--build-epoch", "0")
    x = tmp_path / "x"
    with tarfile.open(rel / f"suriharvest-{major}.tar.gz") as tf:
        tf.extractall(x, filter="data")
    assert "baddomains" in (x / "rules" / "suricata.rules").read_text() and "9000003" in (x / "rules" / "suricata.rules").read_text()
    for f in [x / "rules" / "suricata.rules", *sorted((x / "rules" / "by-source").glob("*.rules"))]:
        _suricata_t(f, tmp_path / "log" / f.name)
    # profile build (no engine filter: the missing-file and absolute-path rules are candidates)
    run("profile", "create", "every", "--query", "")
    run("profile", "build", "every")
    d = (root / "data" / "profiles" / "every" / "latest").resolve()
    for f in [d / "suricata.rules", *sorted((d / "by-source").glob("*.rules"))]:
        _suricata_t(f, tmp_path / "log" / f"p-{f.name}")
    # export
    out = tmp_path / "exp"
    run("export", "--out", str(out), "--profile", "every", "--remap-colliding-sids", "--include-failing")
    _suricata_t(out / "suricata.rules", tmp_path / "log" / "export")
    # web feed
    r = TestClient(create_app(Workspace(root), allowed_hosts={"testserver"})).get("/feed/every/all.tar.gz")
    assert r.status_code == 200
    fx = tmp_path / "feed"
    with tarfile.open(fileobj=io.BytesIO(r.content)) as tf:
        tf.extractall(fx, filter="data")
    _suricata_t(fx / "rules" / "suricata.rules", tmp_path / "log" / "feed")


BS = "\\"
# A ";" right after a backslash never ends an option in Suricata, even after a backslash pair: in ESC_PAIR the
# metadata value swallows "sid:19", so the rule has no sid; in ESC_GID it swallows "gid:2", so the rule is 1:18.
ESC_PAIR = f'alert tcp any any -> any any (msg:"x"; metadata:k v{BS}{BS}; sid:19; rev:1;)'
ESC_GID = f'alert tcp any any -> any any (msg:"x"; metadata:k v{BS}{BS}; gid:2; sid:18; rev:1;)'


@needs_engine
def test_escaped_semicolon_semantics_match_the_engine(tmp_path: Path):
    """ruleopts.py / parser.py split options the way Suricata does (checked here against the real engine)."""
    from suriharvest.parser import ParseError, parse_rule

    res = check_batch(_engine(), [("pair", ESC_PAIR), ("gid", ESC_GID)], _workdir(tmp_path))
    assert res["pair"].status != "ok" and "sid" in (res["pair"].error or "")  # the engine sees no sid either
    assert res["gid"].status == "ok"
    with pytest.raises(ParseError):
        parse_rule(ESC_PAIR)
    r = parse_rule(ESC_GID)
    assert (r.gid, r.sid) == (1, 18) and not r.has("gid")
    # the gid really was swallowed: a second rule 1:18 is a duplicate for the engine
    dup = check_batch(_engine(), [("a", ESC_GID), ("b", 'alert tcp any any -> any any (msg:"y"; sid:18; rev:1;)')], _workdir(tmp_path, "d"))
    assert any(o.status != "ok" for o in dup.values())
