# /// script
# requires-python = ">=3.12"
# dependencies = ["playwright>=1.64.1", "pillow>=11", "pyyaml>=6"]
# ///
"""Regenerate docs/screenshots/*.png from a running web UI (the same script in sigharvest and suriharvest).

Point it at a demo workspace (`TOOL serve`) and run it from the repository root:

    uv run --with playwright playwright install chromium     # once
    uv run scripts/maintainer/screenshots.py                             # tool and port taken from the repository name
    uv run scripts/maintainer/screenshots.py --url http://127.0.0.1:8799 --only overview search

Every shot is taken at 2x, light and dark (`NAME-light.png`, `NAME-dark.png`, the README picks one with <picture> and
prefers-color-scheme), reduced to a 256-colour palette so each file stays small, plus docs/social-preview.png
(1280x640) built from the dark overview. The overview is the whole 1440x900 window; every other shot is only the page
content (no sidebar) of a narrower window, cropped in height, so its text stays legible at README width. A page
whose text shows a local path or a home folder is refused, so a screenshot never leaks the machine it was taken on.

Published images redistribute what they show. A rule page or a search result page is shot only when every rule on it
may be redistributed (licence class permissive or copyleft with the licence text shipped; for suriharvest a source
marked `redistribute: yes`): rules without a licence, restricted, non-commercial or unknown ones are only linked by
the project, so they never appear in a screenshot either (check_shareable). The search queries below pick rules
whose every copy is in a permissive source (licence=permissive&source_only=1), and the script checks the result.
Re-run it after any UI change; the shot list below is the only thing to edit.
"""

from __future__ import annotations

import argparse
import base64
import io
import json
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from playwright.sync_api import Browser, Page

ROOT = Path(__file__).resolve().parents[2]
WIDTH, HEIGHT, SCALE = 1440, 900, 2
# Every shot but the overview: the page content (#main) of a CROP_WIDTH window, at most CROP_HEIGHT tall (CSS px).
CROP_WIDTH, CROP_HEIGHT = 1180, 720
FULL = {"overview"}
BUDGET = 400_000  # bytes per file; larger files are reported, not refused
VISIBLE = 12  # search results checked for a search shot (more than fit in the crop)

# name -> path. "{first:QUERY}" is replaced by the logic hash of the first hit of /api/search?QUERY (a query string).
# Rule and search shots only show redistributable rules: see the module docstring and check_shareable.
SIG_QUERY = "q=mimikatz&licence=permissive"
SURI_QUERY = "q=cobalt+strike"
SHOTS: dict[str, dict[str, str]] = {
    "sigharvest": {
        "overview": "/",
        "search": f"/search?{SIG_QUERY}",
        "rule": f"/rule/{{first:{SIG_QUERY}}}",
        "coverage": "/coverage",
        "export": "/export?q=lsass",
    },
    "suriharvest": {
        "overview": "/",
        "search": f"/search?{SURI_QUERY}",
        "rule": f"/rule/{{first:{SURI_QUERY}}}",
        "builds": "/builds",
        "export": "/export",
    },
}
REDISTRIBUTABLE = ("permissive", "copyleft")
PORTS = {"sigharvest": 8799, "suriharvest": 8077}

# docs/social-preview.png (1280x640, upload it in the repository settings: Social preview): pitch and accent colour.
SOCIAL = {
    "sigharvest": (
        "Every public Sigma rule,<br>deduplicated and searchable.",
        "Collect · Deduplicate · Validate · Search · Export",
        "#4fb3ad",
    ),
    "suriharvest": (
        "Free Suricata rulesets,<br>merged and engine-tested.",
        "Collect · Test in Suricata · Fix sid clashes · Export",
        "#7aa2f7",
    ),
}
SOCIAL_HTML = """<!doctype html><meta charset="utf-8"><style>
@font-face {{ font-family: A; src: url({text}); font-weight: 400 800; }}
@font-face {{ font-family: D; src: url({display}); font-weight: 600 800; font-stretch: 100% 125%; }}
html, body {{ margin: 0; width: 1280px; height: 640px; overflow: hidden; background: #0c110f; font-family: A, sans-serif; color: #eef3ef; }}
.l {{ position: absolute; left: 72px; top: 0; bottom: 0; width: 540px; display: flex; flex-direction: column; justify-content: center; }}
.logo {{ width: 88px; height: 88px; }}
h1 {{ font-family: D, A, sans-serif; font-size: 72px; font-weight: 780; font-stretch: 118%; margin: 28px 0 8px; letter-spacing: -1.5px; }}
p {{ font-size: 30px; line-height: 1.3; margin: 0 0 28px; color: #c9d4cd; }}
.chips {{ font-size: 21px; color: {accent}; font-weight: 700; }}
.shot {{ position: absolute; left: 640px; top: 72px; width: 1020px; border-radius: 14px; box-shadow: 0 30px 80px #000a, 0 0 0 1px #ffffff22; }}
</style><div class="l"><img class="logo" src="{base}/static/favicon.svg"><h1>{name}</h1><p>{pitch}</p><div class="chips">{chips}</div></div>
<img class="shot" src="data:image/png;base64,{shot}">"""

# Text that must never appear on a page that is published as a screenshot.
# C:\Windows, C:\Program Files and C:\ProgramData are rule content (detections and converted queries, where the
# backslash is doubled, quote them), not this machine.
LEAKS = re.compile(r"(/home/|/root/|/Users/|/tmp/|\b[A-Z]:\\++(?!(?i:windows\\|program files|programdata\b))|\\Users\\|/mnt/[a-z]/)")


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as r:  # noqa: S310 (a local demo server given on the command line)
        return bytes(r.read())


class NotShareable(ValueError):
    """A rule whose text the project does not redistribute would appear in a published screenshot."""


def _licence_ids(expression: str) -> list[str]:
    ids = [w for w in re.split(r"[\s()]+", expression) if w and w.upper() not in ("AND", "OR", "WITH")]
    # GPL-3.0, GPL-3.0+, GPL-3.0-or-later -> the GPL-3.0-only text (same for AGPL and LGPL)
    return [re.sub(r"^((?:A|L)?GPL-[0-9.]+)(?:-or-later|\+)?$", r"\1-only", i) for i in ids]


def _suri_catalogue() -> dict[str, dict[str, Any]]:
    import yaml

    path = ROOT / "src" / "suriharvest" / "catalog" / "sources.yaml"
    items = yaml.safe_load(path.read_text(encoding="utf-8")) if path.is_file() else []
    items = items.get("sources", items) if isinstance(items, dict) else items
    return {str(x.get("name")): x for x in items or [] if isinstance(x, dict)}


def check_shareable(tool: str, rule: dict[str, Any], catalogue: dict[str, dict[str, Any]] | None = None) -> None:
    """Raise NotShareable unless the rule may be shown in a published image.

    sigharvest (an /api/rule record): licence class permissive, or copyleft with every licence text bundled in
    src/sigharvest/licences/. suriharvest (an /api/search hit): its canonical source is marked `redistribute: yes`
    in the catalogue and has a licence that is not non-commercial, no-derivatives or a LicenseRef."""
    name = rule.get("title") or rule.get("msg") or rule.get("logic_hash")
    if tool == "sigharvest":
        cls, licence = rule.get("licence_class"), str(rule.get("licence") or "")
        if cls not in REDISTRIBUTABLE:
            raise NotShareable(f"{name!r}: licence class {cls!r} ({licence or 'no licence'}) is not redistributed")
        if cls == "copyleft":
            texts = ROOT / "src" / "sigharvest" / "licences"
            missing = [i for i in _licence_ids(licence) if not (texts / f"{i}.txt").is_file()]
            if missing:
                raise NotShareable(f"{name!r}: copyleft licence text not shipped ({', '.join(missing)})")
        return
    entry = (catalogue if catalogue is not None else _suri_catalogue()).get(str(rule.get("canonical_source")))
    if entry is None:
        raise NotShareable(f"{name!r}: source {rule.get('canonical_source')!r} is not in the catalogue")
    licence = str(entry.get("licence") or "")
    open_terms = licence and not re.search(r"(?i)\bNC\b|-NC-|-ND-|LicenseRef|proprietary", licence)
    if str(entry.get("redistribute")).lower() not in ("yes", "true") or not open_terms:
        raise NotShareable(f"{name!r}: source {entry.get('name')!r} ({licence or 'no licence'}) is not redistributed")


def shown_rules(base: str, tool: str, query: str, n: int) -> list[dict[str, Any]]:
    """The first n rules of /api/search?query, as check_shareable takes them."""
    params = dict(urllib.parse.parse_qsl(query, keep_blank_values=False)) | {"limit": str(n)}
    hits = json.loads(fetch(f"{base}/api/search?" + urllib.parse.urlencode(params)))["results"][:n]
    if tool != "sigharvest":
        return list(hits)
    return [json.loads(fetch(f"{base}/api/rule/{h['logic_hash']}")) | {"logic_hash": h["logic_hash"]} for h in hits]


def resolve(base: str, path: str, tool: str = "sigharvest") -> str:
    """The address of a shot: {first:QUERY} replaced, after checking that every rule it shows may be published."""

    def first(m: re.Match[str]) -> str:
        hits = shown_rules(base, tool, m.group(1), 1)
        if not hits:
            raise NotShareable(f"no search hit for {m.group(1)!r}: pick another query in SHOTS")
        check_shareable(tool, hits[0])
        return str(hits[0]["logic_hash"])

    resolved = re.sub(r"\{first:([^}]+)\}", first, path)
    if resolved.startswith("/search?"):
        catalogue = _suri_catalogue() if tool != "sigharvest" else None
        for rule in shown_rules(base, tool, resolved.split("?", 1)[1], VISIBLE):
            check_shareable(tool, rule, catalogue)
    return resolved


def settle(page: Page) -> None:
    page.wait_for_load_state("networkidle")
    page.evaluate("document.fonts.ready")
    page.add_style_tag(content="*,*::before,*::after{transition:none!important;animation:none!important;caret-color:transparent!important}")
    page.wait_for_timeout(250)


def optimise(png: bytes) -> bytes:
    from PIL import Image

    img = Image.open(io.BytesIO(png)).convert("RGB")
    out = io.BytesIO()
    img.quantize(colors=256, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE).save(out, "PNG", optimize=True)
    return out.getvalue()


def social(browser: Browser, base: str, tool: str, out: Path) -> None:
    hero = out / "overview-dark.png"
    if not hero.exists():
        sys.exit(f"{hero}: take the overview shot first")
    pitch, chips, accent = SOCIAL[tool]
    shot = base64.b64encode(hero.read_bytes()).decode()
    page = browser.new_page(viewport={"width": 1280, "height": 640}, device_scale_factor=1)
    fonts = {
        k: "data:font/woff2;base64," + base64.b64encode(fetch(f"{base}/static/fonts/{f}.woff2")).decode()
        for k, f in (("text", "AtkinsonHyperlegibleNext"), ("display", "Archivo-Display"))
    }
    html = SOCIAL_HTML.format(base=base, name=tool, pitch=pitch, chips=chips, accent=accent, shot=shot, **fonts)
    page.set_content(html, wait_until="networkidle")
    page.evaluate("document.fonts.ready")
    dest = out.parent / "social-preview.png"
    dest.write_bytes(optimise(page.screenshot()))
    page.close()
    print(f"{dest.relative_to(ROOT) if dest.is_relative_to(ROOT) else dest}  {dest.stat().st_size // 1000} KB")


def main() -> int:
    tool_guess = next((t for t in SHOTS if t in ROOT.name), "sigharvest")
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--tool", choices=sorted(SHOTS), default=tool_guess)
    ap.add_argument("--url", help="web UI address (default http://127.0.0.1:PORT of the tool)")
    ap.add_argument("--out", type=Path, default=ROOT / "docs" / "screenshots")
    ap.add_argument("--only", nargs="*", metavar="NAME", help="only these shots (social-preview included)")
    ap.add_argument("--themes", nargs="*", default=["light", "dark"], choices=["light", "dark"])
    a = ap.parse_args()
    base = (a.url or f"http://127.0.0.1:{PORTS[a.tool]}").rstrip("/")
    shots = {k: v for k, v in SHOTS[a.tool].items() if not a.only or k in a.only}
    try:  # every address first: nothing is written when one shot would show a rule that is not redistributed
        urls = {name: base + resolve(base, path, a.tool) for name, path in shots.items()}
    except NotShareable as exc:
        sys.exit(f"refused: {exc}. Pick a query in SHOTS that shows only redistributable rules.")
    a.out.mkdir(parents=True, exist_ok=True)
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch()
        for theme in a.themes:
            ctx = browser.new_context(
                viewport={"width": WIDTH, "height": HEIGHT},
                device_scale_factor=SCALE,
                color_scheme=theme,
                bypass_csp=True,
            )
            page = ctx.new_page()
            for name, url in urls.items():
                full = name in FULL
                page.set_viewport_size({"width": WIDTH, "height": HEIGHT} if full else {"width": CROP_WIDTH, "height": CROP_HEIGHT + 200})
                resp = page.goto(url, wait_until="domcontentloaded")
                if resp is None or resp.status >= 400:
                    sys.exit(f"{url}: HTTP {resp.status if resp else '?'}")
                settle(page)
                leak = LEAKS.search(page.inner_text("body"))
                if leak:
                    sys.exit(f"{url}: the page shows a local path ({leak.group(0)!r}); fix the demo workspace or the UI first")
                clip = None
                box = None if full else page.locator("#main").bounding_box()
                if box:
                    clip = {"x": box["x"], "y": box["y"], "width": box["width"], "height": min(box["height"], CROP_HEIGHT)}
                data = optimise(page.screenshot(animations="disabled", clip=clip) if clip else page.screenshot(animations="disabled"))
                dest = a.out / f"{name}-{theme}.png"
                dest.write_bytes(data)
                note = "" if len(data) <= BUDGET else f"  (over {BUDGET // 1000} KB)"
                print(f"{dest.relative_to(ROOT) if dest.is_relative_to(ROOT) else dest}  {len(data) // 1000} KB{note}")
            ctx.close()
        if not a.only or "social-preview" in a.only:
            social(browser, base, a.tool, a.out)
        browser.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
