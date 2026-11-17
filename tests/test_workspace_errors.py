"""Commands run outside a workspace, and `init` with a ruleset version that cannot work."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from suriharvest.cli import app

runner = CliRunner()


@pytest.mark.parametrize("home", [False, True])
def test_commands_outside_a_workspace_say_so_and_create_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, home: bool):
    empty = tmp_path / "somewhere"
    empty.mkdir()
    monkeypatch.chdir(empty)
    if home:
        monkeypatch.setenv("SURIHARVEST_HOME", str(empty))
    else:
        monkeypatch.delenv("SURIHARVEST_HOME", raising=False)
    for args in (["search", "foo"], ["doctor"], ["stats"]):
        r = runner.invoke(app, args)
        assert r.exit_code == 2, (args, r.output)
        out = " ".join(r.output.split())
        assert "not a suriharvest workspace" in out and "suriharvest init DIR" in out, out
        assert ("SURIHARVEST_HOME" if home else "this folder") in out
        assert "run `suriharvest doctor`" not in out
    assert list(empty.iterdir()) == []  # no stray data/ folder


def test_doctor_still_creates_the_database_of_a_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    (tmp_path / "sources.yaml").write_text("sources: []\n")
    monkeypatch.setenv("SURIHARVEST_HOME", str(tmp_path))
    r = runner.invoke(app, ["doctor"])
    assert "(created)" in r.output and (tmp_path / "data" / "suriharvest.db").exists(), r.output


@pytest.mark.parametrize("bad", ["abc", "7.x", "7.0.0.1", "-7", ""])
def test_init_refuses_a_ruleset_version_that_is_not_a_version(tmp_path: Path, bad: str):
    r = runner.invoke(app, ["init", str(tmp_path / "ws"), "--ruleset-version", bad])
    assert r.exit_code == 2 and "--ruleset-version must be" in " ".join(r.output.split()), r.output
    assert not (tmp_path / "ws" / "sources.yaml").exists()


def test_init_warns_when_nothing_is_enabled(tmp_path: Path):
    r = runner.invoke(app, ["init", str(tmp_path / "ws"), "--ruleset-version", "6.0.0"])
    out = " ".join(r.output.split())
    assert r.exit_code == 0 and "0 of" in out and "no source is enabled" in out, out
    ok = runner.invoke(app, ["init", str(tmp_path / "ws7"), "--ruleset-version", "7.0"])
    assert ok.exit_code == 0 and "no source is enabled" not in ok.output, ok.output
