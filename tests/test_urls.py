"""Source URLs in published files never carry credentials, query strings or local paths."""

from __future__ import annotations

import gzip
import io
import json
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from suriharvest.release import _notice, _public_link, _recipes
from suriharvest.urls import redact_url
from tests.test_pipeline import run, ws  # noqa: F401 - fixture
from tests.test_release import released  # noqa: F401 - fixture


@pytest.mark.parametrize(
    ("url", "want"),
    [
        ("https://user:hunter2@example.org/a/rules.tar.gz", "https://example.org/a/rules.tar.gz"),
        ("https://token@example.org:8443/x.rules", "https://example.org:8443/x.rules"),
        ("https://example.org/x.rules?key=abc123&v=7#frag", "https://example.org/x.rules"),
        ("https://example.org/${secret}/x.tar.gz", "https://example.org/${secret}/x.tar.gz"),
        ("https://example.org/x.tar.gz?code=${secret}", "https://example.org/x.tar.gz"),
        ("git@github.com:org/repo.git", "github.com:org/repo.git"),
        ("/srv/rules/local", None),
        ("./relative/dir", None),
        ("C:\\rules\\local", None),  # a Windows drive is not git's host:path
        ("D:/rules/local", None),
        ("\\\\server\\share\\rules", None),
        ("", None),
        (None, None),
    ],
)
def test_redact_url(url, want):
    assert redact_url(url) == want


def test_redact_url_keeps_placeholders_for_recipes():
    url = "https://${user}:${secret}@example.org/dl/${suricata_version}/r.tar.gz?key=${secret}&tracking=abc#x"
    assert redact_url(url, keep_placeholders=True) == "https://${user}:${secret}@example.org/dl/${suricata_version}/r.tar.gz?key=${secret}"
    assert redact_url("https://bob:pw@example.org/r?key=literal", keep_placeholders=True) == "https://example.org/r"


def test_notice_prefers_homepage_and_never_shows_the_fetch_url():
    row = SimpleNamespace(url="https://u:p@example.org/r.rules?token=s3cr3t", licence="MIT")
    with_home = SimpleNamespace(homepage="https://example.org/project")
    text = _notice(["a", "b"], {"a": row, "b": row}, {"a": with_home, "b": SimpleNamespace(homepage=None)})
    assert "| a | MIT | https://example.org/project |" in text
    assert "| b | MIT | https://example.org/r.rules |" in text
    assert "s3cr3t" not in text and "u:p@" not in text
    assert _public_link(SimpleNamespace(url="/srv/someone/rules"), None) == ""


def test_recipes_redact_but_keep_placeholders(tmp_path: Path):
    cat = tmp_path / "cat.yaml"
    cat.write_text(
        yaml.safe_dump(
            {
                "sources": [
                    {
                        "name": "keyed",
                        "type": "http-tarball",
                        "url": "https://me:pw@example.org/${secret}/r.tar.gz?key=${secret}&sig=abc",
                        "redistribute": "no",
                        "auth": "KEYED_TOKEN",
                    },
                    {"name": "plain", "type": "http-file", "url": "https://example.org/p.rules?t=zzz", "redistribute": "unknown"},
                ]
            }
        )
    )
    out = tmp_path / "recipes.tar.gz"
    _recipes(out, cat, 0)
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(out.read_bytes()))) as tf:
        files = {m.name: tf.extractfile(m).read().decode() for m in tf.getmembers()}
    blob = "".join(files.values())
    assert "pw@" not in blob and "sig=abc" not in blob and "zzz" not in blob
    update = yaml.safe_load(files["recipes/update.yaml"])["sources"]
    assert update == ["https://example.org/%(secret-code)s/r.tar.gz?key=%(secret-code)s", "https://example.org/p.rules"]
    assert "URL: https://example.org/${secret}/r.tar.gz?key=${secret}" in files["recipes/keyed/README.md"]


def test_release_files_do_not_leak_local_paths(released: Path, tmp_path: Path):  # noqa: F811
    out = tmp_path / "rel"
    run("release", "build", str(out), "--engine", "suricata-7", "--build-epoch", "0")
    summary = json.loads((out / "summary.json").read_text())
    assert all(s["url"] is None for s in summary["sources"])  # every test source is a local folder
    for name in ("summary.json", "NOTICE.md"):
        assert str(tmp_path) not in (out / name).read_text(), name


def test_public_link_and_export_manifest(ws, tmp_path):  # noqa: F811
    from suriharvest.urls import public_link

    assert public_link("https://example.org/home", "https://u:p@example.org/r?k=v") == "https://example.org/home"
    assert public_link(None, "https://u:p@example.org/r?k=v") == "https://example.org/r"
    assert public_link("/not/a/url", "https://example.org/r") == ""  # a homepage exists: never fall back to the fetch URL
    run("export", "--out", str(tmp_path / "x"), "--unit", "logic", "--remap-colliding-sids")
    rows = [json.loads(x) for x in (tmp_path / "x" / "manifest.jsonl").read_text().splitlines()]
    assert rows and all(r["url"] is None for r in rows)  # local folders never leave the machine
