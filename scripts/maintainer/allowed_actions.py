#!/usr/bin/env python3
"""Fail when a workflow uses a third-party action that is not in .github/allowed-actions.txt.

The organisation allows GitHub-owned actions plus a short list of third-party actions pinned to an exact commit SHA.
A Dependabot pull request that moves one of them to a new SHA would fail later with "action is not allowed"; this
check fails first, with the fix: add the new pin to .github/allowed-actions.txt *and* to the organisation and
repository allow-lists (maintainers only), then rerun.

Standard library only (it runs with the system python3 in CI, like the privacy gate). Usage:
    python3 -I scripts/maintainer/allowed_actions.py [ROOT]
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

USES = re.compile(r"""^[\s-]*uses:\s*["']?([^\s"'#]+)""")
GITHUB_OWNED = ("actions/", "github/")
LOCAL = ("./", "docker://")


def used_actions(root: Path) -> dict[str, list[str]]:
    """Third-party `uses:` values -> the files (path:line) they appear in."""
    files = sorted((root / ".github" / "workflows").glob("*.y*ml"))
    files += [p for p in (root / "action.yml", root / "action.yaml") if p.is_file()]
    found: dict[str, list[str]] = {}
    for path in files:
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            m = USES.match(line)
            if not m or m.group(1).startswith(LOCAL + GITHUB_OWNED):
                continue
            found.setdefault(m.group(1), []).append(f"{path.relative_to(root).as_posix()}:{n}")
    return found


def allowed(root: Path) -> set[str]:
    text = (root / ".github" / "allowed-actions.txt").read_text(encoding="utf-8")
    return {line.split("#", 1)[0].strip() for line in text.splitlines()} - {""}


def main(argv: list[str]) -> int:
    root = Path(argv[1] if len(argv) > 1 else ".").resolve()
    ok_list = allowed(root)
    bad = 0
    for entry in sorted(ok_list):
        if not re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", entry):
            print(f"::error file=.github/allowed-actions.txt::not an exact SHA pin: {entry}")
            bad += 1
    for uses, where in sorted(used_actions(root).items()):
        if uses in ok_list:
            print(f"ok  {uses}")
            continue
        bad += 1
        file, line = where[0].rsplit(":", 1)
        print(
            f"::error file={file},line={line}::{uses} is not in .github/allowed-actions.txt "
            f"(also used in: {', '.join(where[1:]) or '-'}). A maintainer must add it there and to the "
            "organisation/repository Actions allow-lists before this can merge."
        )
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
