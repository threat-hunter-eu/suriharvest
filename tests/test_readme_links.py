"""README.md links and images (docs/conventions.md): links are absolute; the repository's own images are relative paths
(GitHub renders them while the repository is private) and scripts/maintainer/pypi_readme.py makes everything absolute for the
PyPI long description at build time (publish.yml)."""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BLOB = "https://github.com/threat-hunter-eu/suriharvest/blob/main/"
RAW = "https://raw.githubusercontent.com/threat-hunter-eu/suriharvest/main/"
IMAGE = re.compile(r'<(?:img|source)\b[^>]*?\b(?:src|srcset)="([^"]+)"')


def _targets(text: str) -> list[str]:
    return re.findall(r"\]\(([^)\s]+)\)", text) + re.findall(r'(?:src|srcset|href)="([^"]+)"', text)


def _images(text: str) -> list[str]:
    return IMAGE.findall(text) + re.findall(r"!\[[^\]]*\]\(([^)\s]+)\)", text)


def _absolute(t: str) -> bool:
    return t.startswith(("https://", "http://", "mailto:", "#"))


def test_readme_links_are_absolute_and_images_relative():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    images = _images(text)
    assert images
    relative_links = [t for t in _targets(text) if not _absolute(t) and t not in images]
    assert not relative_links, f"links must be absolute (PyPI): {relative_links}"
    own = [i for i in images if i.startswith((RAW, BLOB))]
    assert not own, f"use a relative path for the repository's own images: {own}"
    for i in images:
        if not _absolute(i):
            assert (ROOT / i).is_file(), i
    for t in _targets(text):
        if t.startswith(BLOB):
            assert (ROOT / t[len(BLOB) :].split("#")[0]).exists(), t


def test_pypi_readme_is_absolute_and_resolves():
    spec = importlib.util.spec_from_file_location("pypi_readme", ROOT / "scripts" / "maintainer" / "pypi_readme.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    out = mod.absolute((ROOT / "README.md").read_text(encoding="utf-8"), mod.repository(ROOT))
    targets = _targets(out)
    assert targets and all(_absolute(t) for t in targets), [t for t in targets if not _absolute(t)]
    badge = "https://github.com/threat-hunter-eu/suriharvest/actions/workflows/ci.yml/badge.svg"  # the only badge: CI
    for i in _images(out):
        assert i.startswith((RAW, "https://img.shields.io/")) or i == badge, i  # a blob/ URL is an HTML page, not the image
        if i.startswith(RAW):
            assert (ROOT / i[len(RAW) :]).is_file(), i
    assert mod.absolute(out, mod.repository(ROOT)) == out  # idempotent
    publish = (ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")
    assert 0 <= publish.index("scripts/maintainer/pypi_readme.py") < publish.index("uv build"), (
        "publish.yml rewrites README before building"
    )


def test_help_has_no_bool_metavar_and_names_the_web_pages():
    from typer.testing import CliRunner

    from suriharvest.cli import app

    def helptext(*args: str) -> tuple[int, str]:
        # CI forces colour (GitHub Actions): Rich then splits "--refresh" with escape codes; compare plain text
        r = CliRunner().invoke(app, [*args, "--help"], env={"COLUMNS": "200", "NO_COLOR": "1", "TERM": "dumb"})
        return r.exit_code, " ".join(re.sub(r"\x1b\[[0-9;]*m", "", r.output).split())

    code, out = helptext("init")
    assert code == 0 and "--refresh" in out and "<bool>" not in out, out
    code, out = helptext("serve")
    assert "<bool>" not in out and "workflow" not in out and "builds and changes" in out, out
