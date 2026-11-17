"""Small helpers that keep the same behaviour on Linux, macOS and Windows."""

from __future__ import annotations

import contextlib
import os
import shutil
import stat
import sys
from pathlib import Path


def _clear_readonly(func, path, exc) -> None:  # type: ignore[no-untyped-def]
    # Git for Windows writes pack files read-only, and Windows refuses to delete read-only files. Never through a
    # symbolic link: chmod follows it, and the target can be anything (rmtree refuses a link as its top folder).
    try:
        st = os.lstat(path)
    except OSError:
        raise exc from None
    if func is os.path.islink or stat.S_ISLNK(st.st_mode):
        raise exc
    with contextlib.suppress(OSError):
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
    func(path)


def decode_text(data: bytes) -> str:
    """Text a person saved on any system: UTF-16 with a byte order mark (PowerShell 5.1 `>`, Notepad "Unicode"),
    UTF-8 with or without one (`Out-File -Encoding utf8`), undecodable bytes replaced."""
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", "replace")
    return data.decode("utf-8-sig", "replace")


def rmtree(path: Path | str, ignore_errors: bool = False) -> None:
    """shutil.rmtree that also removes read-only files (Windows)."""
    try:
        shutil.rmtree(path, onexc=_clear_readonly)
    except OSError:
        if not ignore_errors:
            raise


def setup_stdio() -> None:
    """Never crash on a character the output encoding cannot represent.

    Redirected to a file or a pipe, Python on Windows writes in the ANSI code page (cp1252) and a rule message with
    any other character raised UnicodeEncodeError. Not a terminal: UTF-8. A terminal: keep its encoding, replace
    what it cannot show.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            if stream.isatty():
                reconfigure(errors="replace")
            else:
                reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            pass


_WINDOWS_DEVICES = {"con", "prn", "aux", "nul", *(f"{p}{i}" for p in ("com", "lpt") for i in range(10))}


def windows_unsafe_name(name: str) -> str | None:
    """Why a source or profile name cannot be a folder or file name on Windows (it becomes corpus/<name>/,
    data/profiles/<name>/ and by-source/<name>.rules), or None. A workspace made on Linux must open on Windows too."""
    if name.split(".", 1)[0].lower() in _WINDOWS_DEVICES:
        return "it is a reserved device name on Windows (CON, PRN, AUX, NUL, COM1, LPT1...)"
    if name.endswith("."):
        return "Windows drops a trailing dot from file names"
    return None
