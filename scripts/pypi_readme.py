"""README.md for PyPI: relative links and images become absolute GitHub URLs (shared copy, docs/conventions.md).

On GitHub the README uses relative image paths (docs/screenshots/...), which render in a private repository too;
pypi.org has no repository to resolve them against. publish.yml runs this right before `uv build`, so the sdist and
wheel carry absolute URLs: images to raw.githubusercontent.com, other files to github.com/.../blob/main.
The repository URL is [project.urls].Homepage of pyproject.toml.

    python3 scripts/pypi_readme.py            # rewrite README.md in place
    python3 scripts/pypi_readme.py --check    # print the rewritten text, change nothing
"""

from __future__ import annotations

import re
import sys
import tomllib
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_SCHEME = re.compile(r"[a-z][a-z0-9+.-]*:", re.I)
_IMAGE_ATTR = re.compile(r'(<(?:img|source)\b[^>]*?\b(?:src|srcset)=")([^"]+)(")', re.I)
_HREF = re.compile(r'(<a\b[^>]*?\bhref=")([^"]+)(")', re.I)
_MD_IMAGE = re.compile(r"(!\[[^\]]*\]\()([^)\s]+)(\))")
_MD_LINK = re.compile(r"((?<!!)\[(?:[^\[\]]|\[[^\]]*\])*\]\()([^)\s]+)(\))")


def repository(root: Path = ROOT) -> str:
    """https://github.com/OWNER/REPO, from the Homepage URL."""
    meta = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    home = meta["project"]["urls"]["Homepage"].rstrip("/")
    if not re.fullmatch(r"https://github\.com/[\w.-]+/[\w.-]+", home):
        raise SystemExit(f"Homepage is not a GitHub repository URL: {home}")
    return home


def _relative(target: str) -> bool:
    return not (target.startswith(("#", "/")) or _SCHEME.match(target))


def absolute(text: str, home: str) -> str:
    """`text` with every relative link and image made absolute (anchors and absolute URLs unchanged)."""
    owner_repo = home.removeprefix("https://github.com/")
    raw = f"https://raw.githubusercontent.com/{owner_repo}/main/"
    blob = f"{home}/blob/main/"

    def to(prefix: str) -> Callable[[re.Match[str]], str]:
        def sub(m: re.Match[str]) -> str:
            target = m.group(2)
            return m.group(1) + (prefix + target.removeprefix("./") if _relative(target) else target) + m.group(3)

        return sub

    text = _IMAGE_ATTR.sub(to(raw), text)
    text = _MD_IMAGE.sub(to(raw), text)
    text = _HREF.sub(to(blob), text)
    return _MD_LINK.sub(to(blob), text)


def main(argv: list[str]) -> int:
    readme = ROOT / "README.md"
    out = absolute(readme.read_text(encoding="utf-8"), repository())
    if "--check" in argv:
        sys.stdout.write(out)
    else:
        readme.write_text(out, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
