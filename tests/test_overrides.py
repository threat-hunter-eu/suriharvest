"""Profile overrides: enable, modify (action / rewrite), thresholds; kept across updates; checked by Suricata."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest
import yaml

from suriharvest.overrides import OverrideError, normalise
from tests.test_pipeline import ET_V3, ET_V4, run, with_fake_engine, ws  # noqa: F401 - fixture


def build_dir(out: str) -> Path:
    return Path(out.split("-> ")[1].split("\n")[0].strip())


def edit_profile_file(root: Path, name: str, **sections) -> None:  # type: ignore[no-untyped-def]
    f = root / "exclusions" / f"{name}.yaml"
    data = yaml.safe_load(f.read_text()) or {}
    data.update(sections)
    time.sleep(0.01)
    f.write_text(yaml.safe_dump(data, sort_keys=False))


OVERRIDES = {
    "enable": [{"kind": "sid", "value": "2000005", "reason": "we want the DNS rule"}],
    "modify": [
        {"kind": "sid", "value": "2000001", "action": "drop", "reason": "IPS"},
        {"kind": "msg_regex", "value": "after login", "from": r'content:"/admin"', "to": 'content:"/admin"; nocase'},
        {"kind": "sid", "value": "2000003", "from": r"sid:\d+", "to": "sid:1"},  # would change the sid: refused
        {"kind": "sid", "value": "424242", "action": "drop"},  # matches nothing: reported
    ],
    "thresholds": [
        {"kind": "sid", "value": "2000001", "filter": "suppress", "track": "by_src", "ip": "192.0.2.0/24"},
        {"kind": "sid", "value": "2000003", "filter": "threshold", "type": "limit", "track": "by_src", "count": 1, "seconds": 60},
        {
            "kind": "rule_regex",
            "value": "dns\\.query",
            "filter": "rate_filter",
            "track": "by_rule",
            "count": 10,
            "seconds": 1,
            "new_action": "drop",
            "timeout": 30,
        },
    ],
}


def test_overrides_apply_at_build_and_survive_updates(ws: Path, tmp_path: Path):  # noqa: F811
    run("profile", "create", "ips", "--query", "source:et")
    with_fake_engine(ws, "ips")
    run("profile", "exclusions", "ips")  # writes exclusions/ips.yaml
    edit_profile_file(ws, "ips", **OVERRIDES)
    out = run("profile", "build", "ips")
    d = build_dir(out)
    rules = (d / "suricata.rules").read_text()
    lines = {int(x.split("sid:")[1].split(";")[0]): x for x in rules.splitlines() if "sid:" in x and not x.startswith("# suri")}
    assert lines[2000001].startswith("drop http") and "metadata:suriharvest_modified true;)" in lines[2000001]
    assert 'content:"/admin"; nocase' in lines[2000003] and "suriharvest_modified" in lines[2000003]
    assert lines[2000005].startswith("alert dns")  # enabled: shipped commented out upstream
    assert "suriharvest_modified" not in lines[2000002]
    man = {json.loads(x)["sid"]: json.loads(x) for x in (d / "manifest.jsonl").read_text().splitlines()}
    assert man[2000001].get("modified") and not man[2000002].get("modified")
    thr = (d / "threshold.config").read_text().splitlines()
    assert "suppress gen_id 1, sig_id 2000001, track by_src, ip 192.0.2.0/24" in thr
    assert "threshold gen_id 1, sig_id 2000003, type limit, track by_src, count 1, seconds 60" in thr
    assert "rate_filter gen_id 1, sig_id 2000005, track by_rule, count 10, seconds 1, new_action drop, timeout 30" in thr
    assert "modify refused: et:1:2000003: modify #3: the rewrite changes gid:sid" in out
    assert "matched no rule: modify #4 (sid: 424242)" in out
    # the profile file keeps them, rendered back in canonical form
    saved = yaml.safe_load((ws / "exclusions" / "ips.yaml").read_text())
    assert saved["modify"][0] == {"kind": "sid", "value": "2000001", "action": "drop", "reason": "IPS"}
    assert saved["thresholds"][1]["count"] == 1
    # upstream ships a new revision: the next build applies the same overrides to it
    f = tmp_path / "et" / "rules" / "emerging-malware.rules"
    f.write_text(f.read_text().replace(ET_V3, ET_V4))
    run("sync")
    d2 = build_dir(run("profile", "build", "ips"))
    new = next(x for x in (d2 / "suricata.rules").read_text().splitlines() if "sid:2000001;" in x)
    assert "rev:4" in new and new.startswith("drop http") and "suriharvest_modified" in new
    assert "sig_id 2000001" in (d2 / "threshold.config").read_text()


def test_exclusion_wins_and_remapped_sid_is_used_in_thresholds(ws: Path):  # noqa: F811
    run("profile", "create", "p")
    run("profile", "set", "p", "--include-disabled")
    run("profile", "exclusions", "p")
    edit_profile_file(
        ws,
        "p",
        thresholds=[{"kind": "msg_contains", "value": "repo", "filter": "suppress"}],
        modify=[{"kind": "msg_regex", "value": "repo A", "action": "drop"}],
    )
    run("profile", "exclude", "p", "repo A shell", "--kind", "msg_exact")
    d = build_dir(run("profile", "build", "p"))
    rules = (d / "suricata.rules").read_text()
    assert "repo A shell" not in rules and "drop " not in rules
    man = [json.loads(x) for x in (d / "manifest.jsonl").read_text().splitlines()]
    thr = (d / "threshold.config").read_text()
    for m in man:
        if m["msg"] and "repo B" in m["msg"]:
            assert f"sig_id {m['exported_sid']}" in thr  # the sid the rule has in this build
    assert any(m["exported_sid"] != m["sid"] for m in man), man  # repoB:1000001 clash was remapped


def test_bad_entries_are_reported_and_the_file_left_alone(ws: Path):  # noqa: F811
    run("profile", "create", "q", "--query", "source:et")
    run("profile", "exclusions", "q")
    good = {"kind": "sid", "value": "2000003", "filter": "suppress"}
    edit_profile_file(
        ws,
        "q",
        thresholds=[
            {"kind": "sid", "value": "2000001", "filter": "suppress", "track": "by_src", "ip": "not-an-ip"},
            good,
            {"kind": "sid", "value": "2000001", "filter": "threshold", "type": "limit", "track": "by_src", "count": 0, "seconds": 60},
        ],
    )
    out = run("profile", "build", "q")
    assert "not applied" in out and "thresholds #1 skipped" in out and "thresholds #3 skipped" in out
    assert "the other entries apply" in out
    # one broken entry no longer costs the others
    assert "suppress gen_id 1, sig_id 2000003" in (build_dir(out) / "threshold.config").read_text()
    assert "not-an-ip" in (ws / "exclusions" / "q.yaml").read_text()  # left as written
    out = run("profile", "exclude", "all", "x", "--kind", "msg_exact")
    (ws / "exclusions" / "all-profiles.yaml").write_text("modify:\n- {kind: sid, value: '1', action: drop}\n")
    assert "only in a profile" in run("profile", "build", "q")


@pytest.mark.parametrize(
    ("section", "entry", "msg"),
    [
        ("modify", {"kind": "sid", "value": "1"}, "needs action"),
        ("modify", {"kind": "sid", "value": "1", "action": "explode"}, "action must be"),
        ("modify", {"kind": "sid", "value": "1", "from": "(", "to": "x"}, "bad regular expression"),
        ("modify", {"kind": "sid", "value": "1", "action": "drop", "from": "a", "to": "b"}, "either action"),
        ("thresholds", {"kind": "sid", "value": "1", "filter": "suppress", "track": "by_src"}, "go together"),
        (
            "thresholds",
            {"kind": "sid", "value": "1", "filter": "threshold", "type": "limit", "track": "by_src", "count": "x", "seconds": 1},
            "whole number",
        ),
        (
            "thresholds",
            {"kind": "sid", "value": "1", "filter": "threshold", "type": "often", "track": "by_src", "count": 1, "seconds": 1},
            "type must",
        ),
        ("thresholds", {"kind": "sid", "value": "1", "filter": "suppress", "track": "by_rule", "ip": "1.2.3.4"}, "track must"),
        (
            "thresholds",
            {"kind": "sid", "value": "1", "filter": "rate_filter", "track": "by_src", "count": 1, "seconds": 1, "timeout": 1},
            "new_action",
        ),
        ("enable", {"kind": "nosuch", "value": "1"}, "kind must be"),
        ("enable", {"kind": "sid"}, "kind and value"),
    ],
)
def test_entry_validation(section: str, entry: dict, msg: str):
    with pytest.raises(OverrideError, match=msg):
        normalise(section, entry)


def test_suppress_accepts_variables_and_lists():
    e = normalise(
        "thresholds", {"kind": "sid", "value": "1", "filter": "suppress", "track": "by_either", "ip": "[$HOME_NET,10.0.0.1,2001:db8::/32]"}
    )
    assert e["ip"] == "[$HOME_NET,10.0.0.1,2001:db8::/32]"


@pytest.mark.engine
@pytest.mark.skipif(
    not os.environ.get("SURIHARVEST_TEST_ENGINE_IMAGE") and shutil.which("suricata") is None, reason="suricata not installed"
)
def test_suricata_loads_the_modified_rules_and_threshold_file(ws: Path, tmp_path: Path):  # noqa: F811
    from suriharvest.config import EngineConfig
    from suriharvest.validate import OVERRIDES as ENGINE_SETTINGS
    from suriharvest.validate import parse_output, probe

    run("profile", "create", "ips", "--query", "source:et")
    run("profile", "exclusions", "ips")
    edit_profile_file(ws, "ips", **OVERRIDES)
    d = build_dir(run("profile", "build", "ips"))
    work = tmp_path / "suri"
    work.mkdir()
    for f in ("suricata.rules", "threshold.config"):
        shutil.copy(d / f, work / f)
    work.chmod(0o777)
    image = os.environ.get("SURIHARVEST_TEST_ENGINE_IMAGE")
    eng = probe(EngineConfig("test", binary=None, image=image) if image else EngineConfig("local"))
    base = [a.replace("{work}", str(work)) for a in eng.cfg.command()]
    inside = str(work)  # docker mounts the folder at the same path
    cmd = [*base, "-T", "-v", "-c", eng.config_path, "-S", f"{inside}/suricata.rules", "-l", inside]
    for o in [*ENGINE_SETTINGS, f"threshold-file={inside}/threshold.config"]:
        cmd += ["--set", o]
    proc = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=600, cwd=work)
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out[-3000:]
    assert not parse_output(out), out[-3000:]
    assert "threshold" in out.lower() and "error" not in out.lower().replace("errors: 0", ""), out[-3000:]


def test_rules_with_their_own_threshold_get_no_threshold_config_lines(ws: Path, tmp_path: Path):  # noqa: F811
    """Suricata ignores threshold.config entries (but suppress) for a rule with its own
    threshold/detection_filter (one warning per rule): such lines are left out and the build says so. N11: the
    overrides and their matches show in `profile exclusions` and on the web exclusions page."""
    from fastapi.testclient import TestClient

    from suriharvest.config import Workspace
    from suriharvest.web.app import create_app

    f = tmp_path / "et" / "rules" / "emerging-scan.rules"
    f.write_text(
        'alert tcp any any -> any 7 (msg:"ET SCAN own threshold"; content:"zz"; '
        "threshold:type limit, track by_src, count 1, seconds 60; sid:2000077; rev:1;)\n"
    )
    run("sync")
    run("profile", "create", "t", "--query", "source:et")
    run("profile", "exclusions", "t")
    edit_profile_file(
        ws,
        "t",
        thresholds=[
            {
                "kind": "source",
                "value": "et",
                "filter": "rate_filter",
                "track": "by_src",
                "count": 5,
                "seconds": 60,
                "new_action": "drop",
                "timeout": 30,
            },
            {"kind": "sid", "value": "2000077", "filter": "suppress", "reason": "lab scanner"},
        ],
    )
    out = run("profile", "build", "t")
    thr = (build_dir(out) / "threshold.config").read_text()
    assert "rate_filter gen_id 1, sig_id 2000077" not in thr and "suppress gen_id 1, sig_id 2000077" in thr
    assert "rate_filter gen_id 1, sig_id 2000004" in thr
    assert "1 rule(s) have their own threshold/detection_filter" in " ".join(out.split()) and "et:1:2000077" in out
    listing = run("profile", "exclusions", "t")
    assert "overrides of t" in listing and "thresholds #2" in listing and "suppress" in listing and "lab scanner" in listing
    page = TestClient(create_app(Workspace(ws), allowed_hosts={"testserver"})).get("/profiles/t/exclusions").text
    assert "Overrides (2)" in page and "rate_filter" in page
