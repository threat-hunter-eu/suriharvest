"""Windows portability: lock, read-only deletes, output encoding, engine env, LF output."""

from __future__ import annotations

import io
import os
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from suriharvest import validate
from suriharvest.config import EngineConfig
from suriharvest.lock import LockBusy, workspace_lock
from suriharvest.portable import rmtree, setup_stdio


def test_lock_busy_reports_holder_from_another_process(tmp_path: Path) -> None:
    holder = textwrap.dedent(
        f"""
        import sys, time
        sys.path.insert(0, {str(Path(__file__).resolve().parents[1] / "src")!r})
        from pathlib import Path
        from suriharvest.lock import workspace_lock
        with workspace_lock(Path({str(tmp_path)!r}), "test holder"):
            print("locked", flush=True)
            sys.stdin.readline()
        """
    )
    proc = subprocess.Popen([sys.executable, "-c", holder], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        assert proc.stdout is not None and proc.stdout.readline().strip() == "locked"
        with pytest.raises(LockBusy, match=r"pid \d+: test holder"), workspace_lock(tmp_path, "second"):
            pass
        # a failed attempt must not wipe the holder's text
        assert "test holder" in (tmp_path / "suriharvest.lock").read_text(encoding="utf-8")
    finally:
        assert proc.stdin is not None
        proc.stdin.write("\n")
        proc.stdin.close()
        proc.wait(timeout=30)
    with workspace_lock(tmp_path, "after"):
        assert "after" in (tmp_path / "suriharvest.lock").read_text(encoding="utf-8")
    assert (tmp_path / "suriharvest.lock").read_text(encoding="utf-8") == ""


def test_rmtree_removes_read_only_files(tmp_path: Path) -> None:
    pack = tmp_path / "repo.git" / "objects" / "pack"
    pack.mkdir(parents=True)
    for name in ("pack-1.pack", "pack-1.idx"):
        (pack / name).write_bytes(b"x")
        os.chmod(pack / name, stat.S_IREAD)
    rmtree(tmp_path / "repo.git")
    assert not (tmp_path / "repo.git").exists()
    rmtree(tmp_path / "missing", ignore_errors=True)
    with pytest.raises(FileNotFoundError):
        rmtree(tmp_path / "missing")


class _Pipe(io.TextIOWrapper):
    def isatty(self) -> bool:
        return False


def test_setup_stdio_redirected_output_is_utf8(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = io.BytesIO()
    out = _Pipe(raw, encoding="cp1252", errors="strict")
    monkeypatch.setattr(sys, "stdout", out)
    monkeypatch.setattr(sys, "stderr", _Pipe(io.BytesIO(), encoding="cp1252"))
    setup_stdio()
    print("règle 漢字")
    out.flush()
    assert raw.getvalue().decode("utf-8").strip() == "règle 漢字"


def test_engine_env_keeps_windows_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SYSTEMROOT", r"C:\Windows")
    monkeypatch.setenv("SOURCE_TOKEN", "secret")
    monkeypatch.setattr(validate.os, "name", "nt")
    env = validate._env()
    assert env["SYSTEMROOT"] == r"C:\Windows" and "SOURCE_TOKEN" not in env
    monkeypatch.setattr(validate.os, "name", "posix")
    assert "SYSTEMROOT" not in validate._env()


def test_missing_engine_names_the_fix(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a: object, **k: object) -> None:
        raise FileNotFoundError(2, "The system cannot find the file specified")

    monkeypatch.setattr(validate.subprocess, "run", boom)
    with pytest.raises(RuntimeError, match=r"suricata not found on PATH: install Suricata.*--no-validate"):
        validate.probe(EngineConfig(name="local"))
    with pytest.raises(RuntimeError, match=r"docker not found on PATH"):
        validate.probe(EngineConfig(name="d", image="jasonish/suricata:8.0.8"))


def test_error_line_with_space_in_path() -> None:
    line = 'E: detect: error parsing signature "alert ip any any -> any any (sid:1;)" from file C:\\build host\\tmp dir\\x.rules at line 3'
    m = validate._ERR_LINE.search(line)
    assert m and m.group(2).endswith("x.rules") and m.group(3) == "3"


def test_every_text_write_uses_lf() -> None:
    """Exports, releases and feeds must be byte-identical whether built on Linux or Windows: newline="\\n" everywhere."""
    import ast

    src = Path(__file__).resolve().parents[1] / "src" / "suriharvest"
    missing = []
    for f in src.rglob("*.py"):
        for node in ast.walk(ast.parse(f.read_text(encoding="utf-8"))):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                continue
            name = node.func.attr
            text_open = name == "open" and node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value == "w"
            if (name == "write_text" or text_open) and not any(k.arg == "newline" for k in node.keywords):
                missing.append(f"{f.relative_to(src).as_posix()}:{node.lineno}")
    assert not missing, missing


def test_latest_pointer_survives_a_case_insensitive_file_system(tmp_path, monkeypatch):
    """On Windows and macOS `latest` and `LATEST` are one name: the second build must not find LATEST replaced
    by the `latest` symlink (it raised PermissionError / IsADirectoryError)."""
    import os

    from suriharvest import profiles

    real = os.path.samefile
    folder = tmp_path / "p"
    folder.mkdir()

    def same(a, b):  # simulate a case-insensitive file system for the two pointer names
        names = {os.path.basename(str(a)).lower(), os.path.basename(str(b)).lower()}
        return names == {"latest"} or real(a, b)

    monkeypatch.setattr(profiles.os.path, "samefile", same)
    for name in ("b1", "b2", "b3"):
        (folder / name).mkdir()
        (folder / "latest").write_text("x") if not (folder / "latest").exists() else None
        profiles._point_latest(folder / name)
        assert (folder / "LATEST").read_text() == f"{name}\n" and not (folder / "LATEST").is_symlink()
    # a LATEST that an older version replaced by a symlink is repaired (where this user may create links: Windows
    # needs Developer Mode or admin for them, WinError 1314)
    (folder / "LATEST").unlink()
    try:
        (folder / "LATEST").symlink_to("b3", target_is_directory=True)
    except OSError as e:
        if getattr(e, "winerror", None) != 1314:
            raise
        return
    profiles._point_latest(folder / "b3")
    assert (folder / "LATEST").read_text() == "b3\n"


@pytest.mark.parametrize("name", ["con", "NUL", "aux.rules", "com1", "lpt9", "rules."])
def test_source_and_profile_names_that_windows_cannot_store_are_refused(name: str):
    """A source becomes corpus/<name>/ and by-source/<name>.rules, a profile data/profiles/<name>/: a workspace made
    on Linux with a source called `con` could not be checked out, copied or exported on Windows."""
    from suriharvest.config import ConfigError, SourceConfig
    from suriharvest.portable import windows_unsafe_name

    assert windows_unsafe_name(name)
    with pytest.raises(ConfigError, match="invalid source name"):
        SourceConfig(name=name, type="local", url="/tmp/x")
    for ok in ("console", "et-open", "nul-rules", "com10", "a.b"):
        assert windows_unsafe_name(ok) is None, ok
