"""site build: static, CSP-safe pages from release files only."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from typer.testing import CliRunner

from suriharvest.cli import app
from tests.test_pipeline import run, write
from tests.test_release import released, ws  # noqa: F401 - fixtures


def _tree(d: Path) -> dict[str, str]:
    return {str(p.relative_to(d)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(d.rglob("*")) if p.is_file()}


def test_site_build_from_release_files(released: Path, tmp_path: Path):  # noqa: F811
    write(
        tmp_path / "repoA" / "xss.rules",
        'alert tcp any any -> any 9 (msg:"<script>alert(1)</script> odd"; content:"q"; sid:1000777; rev:1;)',
    )
    run("update")
    rel = tmp_path / "rel"
    run(
        "release",
        "build",
        str(rel),
        "--engine",
        "suricata-7",
        "--build-epoch",
        "1763100000",
        "--download-base",
        "https://example.invalid/dl",
    )
    args = ["--release", str(rel), "--tag", "rules-2026-11-14", "--download-base", "https://example.invalid/dl"]
    args += ["--base-url", "/suriharvest/", "--site-url", "https://owner.example.invalid", "--build-epoch", "1763100000"]
    out = run("site", "build", str(tmp_path / "s1"), *args)
    assert "pages" in out
    site = tmp_path / "s1"
    for name in ("index.html", "search.html", "sources.html", "changes.html", "validation.html", "notice.html", "404.html"):
        html = (site / name).read_text()
        assert '<meta http-equiv="Content-Security-Policy"' in html and "script-src 'self'" in html
        assert not re.search(r"<script(?![^>]*\bsrc=)", html), name  # no inline script
        assert " style=" not in html and "<style" not in html, name  # no inline style
        assert 'href="/suriharvest/static/style.css"' in html
        assert "/suriharvest/static/icons.svg#" in html
        assert 'href="/static/' not in html  # every path under the base url
    for f in ("static/style.css", "static/site.js", "static/theme.js", "static/icons.svg", ".nojekyll"):
        assert (site / f).is_file(), f
    assert any((site / "static" / "fonts").iterdir())
    sec = (site / ".well-known" / "security.txt").read_text().splitlines()  # RFC 9116, one year from the build epoch
    assert "Contact: mailto:security@threat-hunting.eu" in sec and "Preferred-Languages: en" in sec
    assert "Expires: 2026-11-14T06:00:00Z" in sec
    assert "Canonical: https://owner.example.invalid/suriharvest/.well-known/security.txt" in sec
    idx = json.loads((site / "search-index.json").read_text())
    assert idx["fields"] == ["msg", "gid", "sid", "source", "licence", "engines"]
    msgs = [r[0] for r in idx["rules"]]
    assert any(m.startswith("ET MALWARE Foo") for m in msgs)
    assert not any("repo B" in m for m in msgs)  # only what the release publishes
    index = (site / "index.html").read_text()
    assert "https://example.invalid/dl/suricata-7.rules" in index and "rules-2026-11-14" in index
    assert "<script>alert(1)" not in "".join(p.read_text() for p in site.glob("*.html"))
    # licences link to their text, every page names the non-affiliation, the trademarks and
    # where to ask for a correction or a removal
    sources = (site / "sources.html").read_text()
    assert re.search(r'<a href="https://spdx\.org/licenses/[A-Za-z0-9.+-]+\.html" rel="noopener">', sources)
    for name in ("index.html", "sources.html", "notice.html"):
        html = (site / name).read_text()
        assert "Not affiliated with or endorsed by SigmaHQ, OISF, Proofpoint/Emerging Threats or MITRE." in html
        assert "trademarks of the Open Information Security Foundation" in html and "trademarks of Proofpoint, Inc." in html
        assert "/suriharvest/issues" in html
    # deterministic
    run("site", "build", str(tmp_path / "s2"), *args)
    assert _tree(site) == _tree(tmp_path / "s2")


def test_site_build_needs_a_release(tmp_path: Path):
    r = CliRunner().invoke(app, ["site", "build", str(tmp_path / "s"), "--release", str(tmp_path)])
    assert r.exit_code != 0 and "summary.json" in r.output
