"""Damaged workspaces, odd paths and values a hostile or careless user gives: one `error:` line and the documented
exit code (docs/conventions.md), never a traceback."""

from __future__ import annotations

import re
import socket
import sys
from pathlib import Path

import pytest

from suriharvest.cli import main


def run(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], *args: str) -> tuple[int, str]:
    """The installed entry point (main(), with its error handling), as a user runs it."""
    monkeypatch.setattr(sys, "argv", ["suriharvest", *args])
    code = 0
    try:
        main()
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else 1
    out = capsys.readouterr()
    plain = re.sub(r"\x1b\[[0-9;]*m", "", out.out + out.err)  # CI forces colour: Rich splits `--offset` with codes
    return code, " ".join(plain.split())


@pytest.fixture
def ws(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> Path:
    root = tmp_path / "ws"
    code, out = run(monkeypatch, capsys, "init", str(root))
    assert code == 0, out
    (root / "sources.yaml").write_text("sources: []\n")
    monkeypatch.setenv("SURIHARVEST_HOME", str(root))
    return root


@pytest.mark.parametrize("text", ["[[[ not yaml\n", "sources: [a\n", "\t- bad: indentation\n"])
def test_a_sources_file_that_is_not_yaml_is_one_error_line(ws: Path, monkeypatch, capsys, text: str):
    (ws / "sources.yaml").write_text(text)
    code, out = run(monkeypatch, capsys, "update")
    assert code == 2 and "sources.yaml is not valid YAML" in out and "Traceback" not in out, out
    code, out = run(monkeypatch, capsys, "doctor")
    assert code == 1 and "bad sources.yaml" in out and "Traceback" not in out, out


def test_a_settings_file_that_is_not_utf8_is_one_error_line(ws: Path, monkeypatch, capsys):
    (ws / "suriharvest.yaml").write_bytes(b"\xff\xfe engines: [\n")
    code, out = run(monkeypatch, capsys, "search", "x")
    assert code == 2 and "suriharvest.yaml is not UTF-8 text" in out and "Traceback" not in out, out


def test_a_settings_file_that_is_not_a_mapping_is_one_error_line(ws: Path, monkeypatch, capsys):
    (ws / "suriharvest.yaml").write_text("- just\n- a list\n")
    code, out = run(monkeypatch, capsys, "search", "x")
    assert code == 2 and "expected a mapping of settings" in out, out


def test_a_damaged_database_says_how_to_recover(ws: Path, monkeypatch, capsys):
    (ws / "data" / "suriharvest.db").write_bytes(b"this is not sqlite" * 300)
    for args in (["doctor"], ["search", "x"], ["stats"]):
        code, out = run(monkeypatch, capsys, *args)
        assert code == 2 and "database (data/suriharvest.db) is damaged" in out and "Traceback" not in out, (args, out)


def test_init_on_a_file_is_one_error_line(tmp_path: Path, monkeypatch, capsys):
    f = tmp_path / "afile"
    f.write_text("x")
    code, out = run(monkeypatch, capsys, "init", str(f))
    assert code == 2 and "already exists and is not a folder" in out and "Traceback" not in out, out


def test_cli_search_has_the_same_size_limit_as_the_web(ws: Path, monkeypatch, capsys):
    """A pasted blob of 20,000 words ran for minutes in the CLI (the web refused it at once)."""
    code, out = run(monkeypatch, capsys, "search", "a " * 20_000)
    assert code == 2 and "query too long" in out, out
    code, out = run(monkeypatch, capsys, "search", " ".join(f"w{i}" for i in range(40)))
    assert code == 2 and "too many terms" in out, out


def test_cli_search_refuses_an_offset_sqlite_cannot_hold(ws: Path, monkeypatch, capsys):
    code, out = run(monkeypatch, capsys, "search", "x", "--offset", "99999999999999999999")
    assert code == 2 and "Traceback" not in out and "--offset" in out, out


def test_an_export_that_selects_nothing_exits_1(ws: Path, monkeypatch, capsys, tmp_path: Path):
    code, out = run(monkeypatch, capsys, "export", "zzzz-nothing-matches", "--out", str(tmp_path / "out"))
    assert code == 1 and "no rules were exported" in out, out


def test_serve_on_a_busy_port_is_one_error_line_with_exit_code_2(ws: Path, monkeypatch, capsys):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        port = sock.getsockname()[1]
        code, out = run(monkeypatch, capsys, "serve", "--port", str(port))
    assert code == 2 and f"cannot listen on 127.0.0.1 port {port}" in out and "Ctrl+C stops it" not in out, out


def test_ctrl_c_in_a_query_exits_130_without_a_traceback(ws: Path, monkeypatch, capsys):
    """Ctrl+C inside a query made SQLAlchemy log "Error closing cursor" with two tracebacks (Python's last-resort
    logging handler); the user saw them instead of a quiet exit."""
    import logging

    def interrupted(*_a: object, **_k: object) -> None:
        try:
            raise RuntimeError("Cannot operate on a closed database.")
        except RuntimeError:
            logging.getLogger("sqlalchemy.pool.impl.QueuePool").error("Error closing cursor", exc_info=True)
        raise KeyboardInterrupt

    monkeypatch.setattr("suriharvest.search.corpus_stats", interrupted)
    monkeypatch.setattr(logging.root, "handlers", [])  # as outside pytest: no handler, Python's last resort prints
    monkeypatch.setattr(logging.getLogger("sqlalchemy"), "handlers", [])
    code, out = run(monkeypatch, capsys, "stats")
    assert code == 130 and "Error closing cursor" not in out and "Traceback" not in out, out
