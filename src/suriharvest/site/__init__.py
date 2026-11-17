"""`suriharvest site build`: a static, read-only site made from release files only (never from a workspace).

Input: a folder with the release's metadata files (summary.json is required; manifest.jsonl.gz, changes.json,
validation.json, collisions.json, NOTICE.md, SHA256SUMS are used when present). Output: plain HTML pages that reuse
the web UI's look (style.css, icons, fonts, the `_ui.html` macros), a metadata index for a client-side search
(msg, gid, sid, source, licence, engines) and one small script. No rule text is published on the site: rules stay
downloads from the release.

CSP-safe: no inline script or style (a `<meta http-equiv="Content-Security-Policy">` forbids them), every page
works without JavaScript except the search box. Deterministic: the same release files and options give the same
bytes (no wall-clock time; --build-epoch only).
"""

from __future__ import annotations

import gzip
import json
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

from jinja2 import ChoiceLoader, Environment, FileSystemLoader, StrictUndefined, select_autoescape

from suriharvest import __version__, project

HERE = Path(__file__).resolve().parent
WEB = HERE.parent / "web"
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
    "connect-src 'self'; base-uri 'none'; form-action 'self'"
)
STATIC_FROM_WEB = ("harvest-base.css", "style.css", "icons.svg", "theme.js", "favicon.svg")
MAX_LIST = 1000  # rows per list on the changes page


class SiteError(RuntimeError):
    pass


@dataclass
class SiteResult:
    out: Path
    pages: list[str]
    indexed: int


def licence_links(expression: str | None) -> list[dict[str, str | None]]:
    """Each SPDX id of a licence expression with the address of its text (CC-BY §3(a)(1)(C): the licence or its URI
    next to the material); url None for LicenseRef-* and free text."""
    import re

    if not expression:
        return []
    words = [w for w in re.split(r"[\s()]+", expression) if w and w.upper() not in ("AND", "OR", "WITH")]
    if not all(re.fullmatch(r"[A-Za-z][A-Za-z0-9.+-]*", w) for w in words):
        return [{"id": expression, "url": None}]
    return [{"id": w, "url": None if w.startswith("LicenseRef-") else f"https://spdx.org/licenses/{w}.html"} for w in words]


def _json(path: Path, default: Any) -> Any:
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else default


def _manifest(rel: Path) -> list[dict[str, Any]]:
    for name in ("manifest.jsonl.gz", "manifest.jsonl"):
        f = rel / name
        if f.is_file():
            raw = gzip.decompress(f.read_bytes()) if name.endswith(".gz") else f.read_bytes()
            return [json.loads(x) for x in raw.decode("utf-8").splitlines() if x.strip()]
    return []


def _short(engine: str) -> str:
    from suriharvest.web.ui import short_engine

    return short_engine(engine)


def _search_index(manifest: list[dict[str, Any]]) -> list[list[Any]]:
    """One entry per published logic: [msg, gid, exported sid, source, licence, [engine short names]]."""
    by_logic: dict[str, list[Any]] = {}
    for r in manifest:
        if r.get("excluded_reason"):
            continue
        e = by_logic.get(r["logic_hash"])
        if e is None:
            by_logic[r["logic_hash"]] = [r.get("msg") or "", r.get("gid"), r.get("exported_sid"), r.get("source"), r.get("licence"), []]
            e = by_logic[r["logic_hash"]]
        e[5].append(_short(r["engine"]))
    rows = sorted(by_logic.values(), key=lambda x: (x[1] or 0, x[2] or 0, x[3] or ""))
    for x in rows:
        x[5] = sorted(set(x[5]))
    return rows


def _downloads(rel: Path, download_base: str) -> list[dict[str, str]]:
    sums = rel / "SHA256SUMS"
    if not sums.is_file():
        return []
    out = []
    for line in sums.read_text(encoding="utf-8").splitlines():
        digest, _, name = line.partition("  ")
        if name and "/" not in name:
            out.append({"name": name, "sha256": digest, "url": f"{download_base.rstrip('/')}/{quote(name)}" if download_base else ""})
    return sorted(out, key=lambda d: d["name"])


def build(
    out: Path,
    release: Path,
    *,
    tag: str = "",
    download_base: str = "",
    base_url: str = "/",
    site_url: str = "",
    build_epoch: int = 0,
) -> SiteResult:
    summary_file = release / "summary.json"
    if not summary_file.is_file():
        raise SiteError(f"{release}: no summary.json (is this a release folder?)")
    if out.exists() and any(out.iterdir()):
        raise SiteError(f"{out} is not empty")
    base = "/" + base_url.strip("/") + "/" if base_url.strip("/") else "/"
    summary = _json(summary_file, {})
    manifest = _manifest(release)
    changes = _json(release / "changes.json", {})
    validation = _json(release / "validation.json", {})
    collisions = _json(release / "collisions.json", [])
    notice = (release / "NOTICE.md").read_text(encoding="utf-8") if (release / "NOTICE.md").is_file() else ""
    downloads = _downloads(release, download_base)
    msg_of = {(r["engine"], r["logic_hash"]): r.get("msg") or "" for r in manifest if not r.get("excluded_reason")}
    duplicates = sum(1 for r in manifest if r.get("excluded_reason") == "duplicate")
    index = _search_index(manifest)

    from suriharvest.web import ui

    env = Environment(
        loader=ChoiceLoader([FileSystemLoader(HERE / "templates"), FileSystemLoader(WEB / "templates")]),
        autoescape=select_autoescape(default=True),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters.update(num=ui.num, eng_label=ui.engine_label, eng_short=ui.short_engine, fulltime=ui.fulltime, reltime=ui.fulltime)
    env.globals.update(
        static_root=base + "static",
        base=base,
        csp=CSP,
        site_url=site_url.rstrip("/"),
        tag=tag,
        version=__version__,
        summary=summary,
        generated=summary.get("generated_at") or "",
        built=datetime.fromtimestamp(build_epoch, UTC).strftime("%Y-%m-%d %H:%M UTC"),
        repo_url=project.repo_url(),
        issues_url=project.issues_url(),
        contact_email=project.CONTACT_EMAIL,
        not_affiliated=project.NOT_AFFILIATED,
        trademarks=project.TRADEMARKS,
    )
    env.filters["licence_links"] = licence_links
    engines = sorted((summary.get("engines") or {}).items())
    pages: dict[str, tuple[str, dict[str, Any]]] = {
        "index.html": (
            "site_index.html",
            {
                "section": "overview",
                "engines": engines,
                "downloads": downloads,
                "gates": summary.get("gates") or [],
                "duplicates": duplicates,
                "n_collisions": len(collisions),
                "changes": changes,
                "unique": len(index),
            },
        ),
        "sources.html": ("site_sources.html", {"section": "sources", "engines": engines, "sources": summary.get("sources") or []}),
        "changes.html": (
            "site_changes.html",
            {"section": "changes", "changes": changes, "msg_of": msg_of, "limit": MAX_LIST, "collisions": collisions[:MAX_LIST]},
        ),
        "validation.html": (
            "site_validation.html",
            {"section": "validation", "engines": [e for e, _ in engines], "validation": sorted(validation.items())},
        ),
        "search.html": ("site_search.html", {"section": "search", "unique": len(index)}),
        "notice.html": ("site_notice.html", {"section": "notice", "notice": notice}),
        "404.html": ("site_404.html", {"section": ""}),
    }
    out.mkdir(parents=True, exist_ok=True)
    for name, (tpl, ctx) in pages.items():
        html = env.get_template(tpl).render(page=name, **ctx)
        (out / name).write_text(html, encoding="utf-8", newline="\n")
    (out / "search-index.json").write_text(
        json.dumps(
            {
                "tag": tag,
                "generated_at": summary.get("generated_at"),
                "fields": ["msg", "gid", "sid", "source", "licence", "engines"],
                "rules": index,
            },
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    static = out / "static"
    static.mkdir()
    for f in STATIC_FROM_WEB:
        shutil.copyfile(WEB / "static" / f, static / f)
    shutil.copytree(WEB / "static" / "fonts", static / "fonts")
    shutil.copyfile(HERE / "static" / "site.js", static / "site.js")
    (out / ".nojekyll").write_text("", encoding="utf-8", newline="\n")
    issued = datetime.fromtimestamp(build_epoch, UTC) if build_epoch else datetime.now(UTC)
    canonical = f"{site_url.rstrip('/')}{base}.well-known/security.txt" if site_url else ""
    (out / ".well-known").mkdir()
    (out / ".well-known" / "security.txt").write_text(project.security_txt(issued, canonical), encoding="utf-8", newline="\n")
    return SiteResult(out, sorted(pages), len(index))
