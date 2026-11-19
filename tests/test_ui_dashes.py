"""UI copy uses a plain hyphen or a middle dot, never a long dash (shared harvest-base convention with
sigharvest)."""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "src/suriharvest/web"
LONG_DASHES = ("—", "–", "&mdash;", "&ndash;", "&#8212;", "&#8211;", "&#x2014;", "&#x2013;")
FILES = sorted(
    p
    for p in [*WEB.rglob("*.html"), *WEB.rglob("*.js"), *WEB.rglob("*.css"), *WEB.rglob("*.py"), ROOT / "src/suriharvest/summary.py"]
    if p.is_file()
)


@pytest.mark.parametrize("path", FILES, ids=lambda p: str(p.relative_to(ROOT)))
def test_no_long_dashes_in_ui_copy(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    found = [d for d in LONG_DASHES if d.lower() in text.lower()]
    assert not found, f"{path.relative_to(ROOT)}: use '-' or '&middot;' instead of {found}"
