"""The command line follows docs/conventions.md (shared with sigharvest): verbs, global options, --json, exit codes."""

from __future__ import annotations

import json
import re
from pathlib import Path

from typer.testing import CliRunner

from suriharvest.cli import app
from tests.test_pipeline import run, ws  # noqa: F401 - fixture

ANSI = re.compile(r"\x1b\[[0-9;]*m")


class _Plain(CliRunner):
    """CI forces colour (GITHUB_ACTIONS, FORCE_COLOR): compare the text without escape codes."""

    def invoke(self, *args, **kw):  # type: ignore[no-untyped-def, override]
        r = super().invoke(*args, **kw)
        r.stdout_bytes = ANSI.sub("", r.stdout_bytes.decode()).encode()
        if getattr(r, "output_bytes", None) is not None:
            r.output_bytes = ANSI.sub("", r.output_bytes.decode()).encode()
        return r


runner = _Plain(env={"COLUMNS": "200"})


def test_global_options_and_serve():
    top = runner.invoke(app, ["--help"])
    assert top.exit_code == 0 and "serve" in top.output and "--verbose" in top.output
    assert not any(line.strip().startswith(("│ web ", "web ")) for line in top.output.splitlines())  # hidden alias
    for name in ("serve", "web"):
        r = runner.invoke(app, [name, "--help"])
        assert r.exit_code == 0 and "--token-env" in r.output and "--allow-host" in r.output
    assert runner.invoke(app, ["--version"]).output.startswith("suriharvest ")
    assert runner.invoke(app, ["version"]).output.startswith("suriharvest ")


def test_serve_refuses_a_public_bind_without_a_token(ws: Path):  # noqa: F811
    for name in ("serve", "web"):
        r = runner.invoke(app, [name, "--host", "0.0.0.0"])
        assert r.exit_code == 2 and "--token-env" in r.output


def test_search_json_envelope_and_exit_codes(ws: Path):  # noqa: F811
    doc = json.loads(run("search", "", "--per-logic", "--json", "--limit", "2"))
    assert set(doc) >= {"total", "offset", "limit", "results"} and doc["offset"] == 0 and doc["limit"] == 2
    assert len(doc["results"]) == min(2, doc["total"])
    second = json.loads(run("search", "", "--per-logic", "--json", "--limit", "1", "--offset", "1"))
    assert second["results"] == doc["results"][1:2]
    assert runner.invoke(app, ["-v", "search", "x"]).exit_code == 0
    r = runner.invoke(app, ["show", "999999999"])
    assert r.exit_code == 1 and r.output.startswith("error: nothing found")  # ran, matched nothing
    assert runner.invoke(app, ["search", "metadata:=x"]).exit_code == 2  # a query that cannot be read


def test_search_option_names_and_deprecated_aliases(ws: Path):  # noqa: F811
    help_ = runner.invoke(app, ["search", "--help"]).output
    assert "--per-logic" in help_ and "--include-junk" in help_
    assert not re.search(r"--all\b|--junk\b", help_)  # the old names are hidden
    new = json.loads(run("search", "", "--per-logic", "--include-junk", "--json"))
    for old in (["--all", "--junk"], ["--all", "--include-junk"]):
        r = runner.invoke(app, ["search", "", *old, "--json"])
        assert r.exit_code == 0 and "deprecated" in r.output
        assert json.loads(r.stdout.splitlines()[-1])["total"] == new["total"]
    assert json.loads(run("search", "", "--json"))["total"] <= new["total"]


def test_export_query_then_out_and_the_old_form(ws: Path, tmp_path: Path):  # noqa: F811
    new = run("export", "source:et", "--out", str(tmp_path / "new"), "--unit", "logic")
    old = runner.invoke(app, ["export", str(tmp_path / "old"), "--query", "source:et", "--unit", "logic"])
    assert old.exit_code == 0 and "deprecated" in old.output and "--out" in old.output
    assert (tmp_path / "new" / "suricata.rules").read_text().splitlines()[1:] == (
        tmp_path / "old" / "suricata.rules"
    ).read_text().splitlines()[1:]
    assert "deprecated" not in new
    r = runner.invoke(app, ["export", "source:et", "--out", str(tmp_path / "x"), "--query", "source:et"])
    assert r.exit_code == 2 and "once" in r.output
    shared = runner.invoke(
        app, ["export", "--out", str(tmp_path / "s"), "--include-private-sources", "--unit", "logic", "--remap-colliding-sids"]
    )
    assert shared.exit_code == 0, shared.output


def test_a_query_starting_with_a_dash_stays_a_query(ws: Path, tmp_path: Path):  # noqa: F811
    """The Export page's copy-paste line puts the options first and the query after `--`."""
    import html
    import re
    import shlex

    from fastapi.testclient import TestClient

    from suriharvest.config import Workspace
    from suriharvest.web.app import create_app

    client = TestClient(create_app(Workspace(ws), allowed_hosts={"testserver"}))
    page = client.get("/export", params={"q": f"--out={tmp_path / 'evil'}"}).text
    found = re.search(r'<code id="cli">(.*?)</code>', page)
    assert found, page[:500]
    line = html.unescape(found.group(1))
    assert line.startswith("suriharvest export --out out/ ")
    assert shlex.split(line)[-2:] == ["--", f"--out={tmp_path / 'evil'}"]
    # pasted as shown, the CLI reads it as a query, not as --out
    r = runner.invoke(app, ["export", "--out", str(tmp_path / "out"), "--remap-colliding-sids", "--", f"--out={tmp_path / 'evil'}"])
    assert "No such option" not in r.output and not (tmp_path / "evil").exists()
    assert runner.invoke(app, ["export", "--out", str(tmp_path / "ok"), "--unit", "logic", "--", "source:et"]).exit_code == 0


def test_help_is_grouped_in_the_shared_panels_with_examples_and_sentences():
    """docs/conventions.md: commands grouped as Start here, Rules, Sources, Publish, Admin (sigharvest's panel names);
    the first group shows an example; option help is written in sentences."""
    from suriharvest.cli_help import PANELS

    top = runner.invoke(app, ["--help"]).output
    # Rich draws rounded corners (╭) on a modern terminal and square ones (┌) where it detects a legacy Windows
    # console (a Windows CI runner has no VT console): match the panel title, not the corner glyph.
    titles = [m for m in re.findall(r"[╭┌]─ ([A-Z][a-z]+(?: [a-z]+)?) ─", top) if m != "Options"]
    assert titles == ["Start here", "Rules", "Sources", "Publish", "Admin"] == list(PANELS)
    assert "Example: suriharvest init" in top and "Help for any command: suriharvest COMMAND --help." in top
    listed = {line.split()[1] for line in top.splitlines() if line.startswith("│ ") and len(line.split()) > 2}
    from typer.main import get_command

    registered = {n for n, c in get_command(app).commands.items() if not c.hidden}
    assert registered <= listed and registered == {n for names in PANELS.values() for n in names}  # no "Other" panel
    for args in (["serve", "--help"], ["search", "--help"], ["profile", "import-conf", "--help"]):
        out = runner.invoke(app, args).output
        assert "bind address" not in out and "show what would be imported" not in out, args
    assert "Bind address; anything but loopback needs --token-env." in runner.invoke(app, ["serve", "--help"]).output


def test_version_prints_dependencies_and_engines(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # no workspace: the suricata on PATH is reported
    out = runner.invoke(app, ["version"]).output.splitlines()
    assert out[0].startswith("suriharvest ") and ", schema " in out[0]
    assert out[1].startswith("Python 3.")
    assert any(line.startswith("sqlalchemy 2.") for line in out) and any(line.startswith("fastapi ") for line in out)
    assert any(line.startswith("suricata on PATH: ") for line in out)
    assert any(line.startswith("suricata-update: ") for line in out)


def test_errors_and_hints_are_not_wrapped_inside_a_path(tmp_path: Path, monkeypatch):
    """At 80 columns (a pipe or a log) an error naming a long path stays one copy-pasteable line, as in sigharvest."""
    deep = tmp_path / ("a-rather-long-folder-name-" * 4) / "home"
    deep.mkdir(parents=True)
    monkeypatch.chdir(deep)
    monkeypatch.delenv("SURIHARVEST_HOME", raising=False)
    r = _Plain(env={"COLUMNS": "80"}).invoke(app, ["stats"])
    assert r.exit_code == 2
    line = next(x for x in r.output.splitlines() if x.startswith("error: not a suriharvest workspace"))
    assert str(deep) in line and "suriharvest init DIR" in line


def test_version_never_runs_the_workspace_engines(ws: Path, monkeypatch):  # noqa: F811
    """A cloned workspace can name any binary in suriharvest.yaml: `version` lists it but runs only `suricata` from
    PATH (doctor is the explicit probe)."""
    import subprocess

    trap = ws / "evil-engine"
    trap.write_text('#!/bin/sh\ntouch "$0.ran"\n')
    trap.chmod(0o755)
    import yaml

    from suriharvest.config import Workspace

    settings = Workspace(ws).settings_file

    doc = (yaml.safe_load(settings.read_text()) if settings.exists() else None) or {}
    doc["engines"] = [{"name": "evil", "binary": str(trap)}, {"name": "img", "image": "example/suricata:8.0.8"}]
    settings.write_text(yaml.safe_dump(doc))
    calls: list[list[str]] = []
    real = subprocess.run
    monkeypatch.setattr(subprocess, "run", lambda cmd, *a, **k: calls.append(list(cmd)) or real(cmd, *a, **k))
    monkeypatch.chdir(ws)
    out = runner.invoke(app, ["version"]).output
    assert "workspace engine evil: " in out and str(trap) in out and "workspace engine img: example/suricata:8.0.8" in out
    assert not (ws / "evil-engine.ran").exists()
    assert all(Path(c[0]).name == "suricata" and c[1:] == ["-V"] for c in calls), calls
