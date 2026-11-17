"""Large selections on an SQLite with a low bound-variable limit (python.org / uv / Windows builds keep the
upstream default of 32,766; this test lowers it to 999 so a few thousand rules show the same failure)."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from suriharvest import db
from tests.test_engine_offline import fake_engine, rule
from tests.test_pipeline import run, write

N = 2500


@pytest.fixture
def big(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(db, "MAX_SQL_VARIABLES", 999)
    root = tmp_path / "ws"
    monkeypatch.setenv("SURIHARVEST_HOME", str(root))
    monkeypatch.chdir(tmp_path)
    run("init", str(root), "--engine", f"suricata-7={fake_engine(tmp_path, '7.0.17')}")
    write(tmp_path / "many" / "many.rules", *(rule(3_000_000 + i) for i in range(N)))
    write(tmp_path / "more" / "more.rules", *(rule(3_000_000 + i, "nocase; ") for i in range(0, N, 2)))  # clashing sids
    srcs = [
        {
            "name": "many",
            "type": "local",
            "url": str(tmp_path / "many"),
            "licence": "MIT",
            "copyright": "Copyright (c) 2026 Test Publisher",
            "redistribute": "yes",
        },
        {
            "name": "more",
            "type": "local",
            "url": str(tmp_path / "more"),
            "licence": "MIT",
            "copyright": "Copyright (c) 2026 Test Publisher",
            "redistribute": "yes",
        },
    ]
    (root / "sources.yaml").write_text(yaml.safe_dump({"sources": srcs}))
    monkeypatch.chdir(root)
    return root


def test_update_build_export_release_and_web_with_a_low_variable_limit(big: Path, tmp_path: Path):
    import sqlite3

    from suriharvest.db import make_engine

    with make_engine(big / "probe.db").connect() as c:  # the limit really is in force
        assert c.connection.dbapi_connection.getlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER) == 999
    out = run("update")
    assert "rules" in out
    built = run("profile", "build", "default")
    assert "remapped" in built
    run("export", "--out", str(tmp_path / "exp"), "--unit", "logic", "--remap-colliding-sids")
    assert (tmp_path / "exp" / "suricata.rules").read_text().count("\nalert") >= N
    run("release", "build", str(tmp_path / "rel"), "--engine", "suricata-7", "--build-epoch", "0")
    from suriharvest.config import find_workspace
    from suriharvest.web.app import create_app

    c = TestClient(create_app(find_workspace(), allowed_hosts={"testserver"}))
    for path in (
        "/",
        "/search?q=r3000&all=1",
        "/search?q=remapped:yes",
        "/api/search?all=1&per_page=200",
        "/builds",
        "/profiles/default/new",
    ):
        r = c.get(path)
        assert r.status_code == 200, (path, r.text[:300])
