"""Public text describes behaviour, not the process that found it: no review / audit / finding identifiers in docs,
the CHANGELOG, code comments, docstrings or tests (they mean nothing to a reader and age badly)."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SELF = Path(__file__).resolve()
SUFFIXES = {".py", ".md", ".sh", ".ps1", ".yml", ".yaml", ".toml", ".txt", ".html", ".css", ".js", ".cfg"}
# tests/acceptance is a copy of a harness kept in sync elsewhere; its "walkthrough" means a guided run
SKIP_PREFIXES = ("tests/acceptance/",)

# Built from parts so this file does not match itself when read by another tool.
_ID = r"[CHMLSPNUW]\d{1,2}"
PATTERNS = {
    "review number": r"(?<![-\w])[Rr]eview #?\d{1,2}\b",
    "walkthrough": r"\b[Nn]ovice\b|\b[Ww]alkthrough \d",
    "audit / review name": r"\b[Ll]icen[cs]e audit\b|\b[Ff]inal review\b|\b[Ss]ecurity review\b|\bcicd-audit\b",
    # AI coding tools and their scratch folders are not part of this project's public text
    "assistant tool name": r"(?i)\b(?:clau" + r"de|anthro" + r"pic|cod" + r"ex|copi" + r"lot|chat" + r"gpt|open" + r"ai)\b",
    "load test / checkpoint": r"\b[Ll]oad test\b|\b[Cc]heckpoint[- ]?\d",
    "finding id prefix": r'(?:#|""")\s*' + _ID + r"\b\s*[:,/+]",
    "finding id in parentheses": r"\((?:" + _ID + r"[,/ ]*)+\)",
}


def _files() -> list[Path]:
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=False).stdout.split()
    if not out:  # not a git checkout (sdist): scan the usual folders
        out = [str(p.relative_to(ROOT)) for d in ("src", "tests", "docs") for p in (ROOT / d).rglob("*") if p.is_file()]
        out += [p.name for p in ROOT.glob("*.md")]
    return [ROOT / f for f in out if Path(f).suffix in SUFFIXES and not f.startswith(SKIP_PREFIXES) and (ROOT / f).resolve() != SELF]


@pytest.mark.parametrize("name", sorted(PATTERNS))
def test_no_internal_review_identifiers(name: str):
    rx = re.compile(PATTERNS[name])
    hits = []
    for p in _files():
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError):
            continue
        for n, line in enumerate(text.splitlines(), 1):
            if rx.search(line):
                hits.append(f"{p.relative_to(ROOT)}:{n}: {line.strip()[:120]}")
    assert not hits, f"{name}: describe the behaviour instead of the review that found it:\n" + "\n".join(hits)


def test_the_guard_catches_what_it_should():
    bad = [
        "/tmp/" + "clau" + "de-0/x",
        "# review 3 L3: caps",
        '"""Review 4 M2: x',
        "(novice walkthrough 2)",
        "see the licence audit",
        "# H1: squat",
        "fixed (M4)",
    ]
    good = ["--review 2027-05-01", "review_at=dt", "(review `performance_impact` and test)", "# HTTP/1.1: a body", "sha256: x"]
    rxs = [re.compile(r) for r in PATTERNS.values()]
    assert all(any(r.search(b) for r in rxs) for b in bad)
    assert not any(r.search(g) for r in rxs for g in good)
