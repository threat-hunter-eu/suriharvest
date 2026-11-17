"""What docs/conventions.md promises that a file can show (shared with sigharvest): the shared stylesheet, the
file names, the changelog layout. The command line side is in tests/test_cli_conventions.py."""

from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# SHA-256 of src/suriharvest/web/static/harvest-base.css. The same file (and this value) is in sigharvest: change both.
HARVEST_BASE_SHA256 = "446063cf64875c7599ba2c1d960519851f4c281fc86c2d5b0d4401c217ce083e"


def test_harvest_base_is_the_shared_copy() -> None:
    data = (ROOT / "src/suriharvest/web/static/harvest-base.css").read_bytes()
    assert hashlib.sha256(data).hexdigest() == HARVEST_BASE_SHA256, "harvest-base.css changed: copy it to sigharvest and update both hashes"
    assert b"suriharvest" not in data.split(b"*/", 1)[1], "product-specific rules belong in style.css"
    for page in ("src/suriharvest/web/templates/base.html", "src/suriharvest/site/templates/site_base.html"):
        html = (ROOT / page).read_text(encoding="utf-8")
        assert html.index("harvest-base.css") < html.index("/style.css"), page  # the shared base first, the tokens after


def test_style_css_defines_every_token_the_base_uses() -> None:
    import re

    base = (ROOT / "src/suriharvest/web/static/harvest-base.css").read_text(encoding="utf-8")
    style = (ROOT / "src/suriharvest/web/static/style.css").read_text(encoding="utf-8")
    used = set(re.findall(r"var\((--[a-z0-9-]+)", base))
    defined = set(re.findall(r"(--[a-z0-9-]+)\s*:", style))
    assert used <= defined, sorted(used - defined)


def test_conventions_doc_and_shared_file_names() -> None:
    text = (ROOT / "docs/conventions.md").read_text(encoding="utf-8")
    assert text.startswith("# Conventions shared by sigharvest and suriharvest")
    for name in ("web.md", "releases.md", "site.md", "scheduling.md", "concepts.md", "conventions.md"):
        assert (ROOT / "docs" / name).is_file(), name
    assert not (ROOT / "docs/release.md").exists() and not (ROOT / "docs/technical.md").exists()
    assert (ROOT / ".github/workflows/nightly.yml").is_file()
    for name in ("bug.yml", "source.yml", "rule-feedback.yml", "config.yml"):
        assert (ROOT / ".github/ISSUE_TEMPLATE" / name).is_file(), name
    for name in ("test_web_layout.py", "test_neutral_wording.py"):
        assert (ROOT / "tests" / name).is_file(), name
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert changelog.index("## [Unreleased]") < changelog.index("## [0.1.0]")
