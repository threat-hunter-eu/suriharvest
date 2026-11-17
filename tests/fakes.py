"""Executable test doubles (fake Suricata engines) that run on Linux, macOS and Windows."""

from __future__ import annotations

import os
import sys
from pathlib import Path

# A Suricata 7.0.99 that answers -V and accepts every ruleset.
ACCEPT_ALL = 'import sys\nif "-V" in sys.argv[1:]:\n    print("This is Suricata version 7.0.99 RELEASE")\nsys.exit(0)\n'


def python_script(path: Path, source: str) -> Path:
    """An executable that runs `source` with Python; returns the path to put in an engine's binary.

    POSIX: a script with a shebang. Windows has no shebangs: a .cmd launcher next to a .py file.
    """
    if os.name == "nt":
        py = path.with_name(path.name + ".py")
        py.write_text(source, encoding="utf-8")
        cmd = path.with_name(path.name + ".cmd")
        cmd.write_text(f'@"{sys.executable}" "{py}" %*\r\n', encoding="utf-8", newline="")
        return cmd
    path.write_text("#!/usr/bin/env python3\n" + source, encoding="utf-8")
    path.chmod(0o755)
    return path
