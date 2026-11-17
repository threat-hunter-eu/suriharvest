"""Search filters and facets read logic_group_values: same answers as parsing each row's JSON, kept in step with
the index, filled by the migration from an existing database, and the web search caches follow verdict changes."""

from __future__ import annotations

import sqlite3
from collections import Counter
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import bindparam, func, select, text

from suriharvest import search
from suriharvest.config import Workspace
from suriharvest.db import alembic_config, session_factory
from suriharvest.models import VALUE_KINDS, LogicGroup, Source
from suriharvest.web import ui
from suriharvest.web.app import _counts, create_app
from tests.test_pipeline import run, ws  # noqa: F401 - fixture

FILTER_OF = {"buffers": "buffer", "sources": "source", "flags": "flag", "loads_in": "loads", "fails_in": "fails", "mitre": "mitre"}


def _json_has(kind: str, value: str):  # type: ignore[no-untyped-def]
    """The filter as it was before logic_group_values: json_each and lower() on every row (the reference)."""
    sql = f"EXISTS (SELECT 1 FROM json_each(logic_groups.{kind}) WHERE lower(json_each.value) = lower(:v))"
    return text(sql).bindparams(bindparam("v", value, unique=True))


def _queries(c: sqlite3.Connection) -> list[str]:
    """Every value each list column holds, as stored and in upper case, alone and with other filters; plus misses."""
    qs = ["", "ioc:no", "severity:major", "cat:INFO", "perf:low", "source:nosuch", "buffer:nosuch", "mitre:t9999"]
    for kind in VALUE_KINDS:
        for (v,) in c.execute(f"SELECT DISTINCT j.value FROM logic_groups, json_each(logic_groups.{kind}) j"):
            key = FILTER_OF[kind]
            if kind == "flags" and v.startswith("dialect:"):
                qs.append(v.upper())
            qs += [f"{key}:{v}", f"{key}:{v.upper()}", f"{key}:{v} ioc:yes", f"{key}:{v} app:http"]
    srcs = [n for (n,) in c.execute("SELECT name FROM sources")]
    qs.append("source:" + ",".join(srcs))
    return qs


def _reference_facets(s, ids: list[int]) -> dict[str, Counter]:  # type: ignore[no-untyped-def]
    out = {}
    for kind in ("sources", "flags", "loads_in", "fails_in"):
        rows = s.execute(
            text(
                f"SELECT j.value, count(*) FROM logic_groups, json_each(logic_groups.{kind}) j "
                "WHERE logic_groups.id IN (SELECT value FROM json_each(:ids)) GROUP BY j.value"
            ).bindparams(ids=str(ids))
        ).all()
        out[kind] = Counter(dict(rows))
    sev = s.execute(
        select(func.lower(LogicGroup.severity), func.count()).where(LogicGroup.id.in_(ids)).group_by(func.lower(LogicGroup.severity))
    ).all()
    out["severity"] = Counter(dict(sev))
    return out


def test_filters_and_facets_match_the_json_reference(ws: Path, monkeypatch: pytest.MonkeyPatch):  # noqa: F811
    w = Workspace(ws)
    c = sqlite3.connect(w.db_path)
    queries = _queries(c)
    assert len(queries) > 40
    sf = session_factory(w.db_path)
    with sf() as s:
        srcs = {x.name: x for x in s.scalars(select(Source))}
        for q in queries:
            for every in (False, True):
                stmt = search.build(search.parse_query(q), families=not every, include_junk=every)
                order = [LogicGroup.score.desc(), LogicGroup.id]
                got = list(s.scalars(stmt.with_only_columns(LogicGroup.id).order_by(*order)))
                page = [g.id for g in search.page_rows(s, stmt, order, 3, 1)]
                total, lines, facets = _counts(s, stmt.subquery(), srcs)
                with monkeypatch.context() as m:
                    m.setattr(search, "_has", _json_has)
                    ref_stmt = search.build(search.parse_query(q), families=not every, include_junk=every)
                    want = list(s.scalars(ref_stmt.with_only_columns(LogicGroup.id).order_by(*order)))
                assert got == want, q
                assert page == want[1:4], q
                assert total == len(want), q
                assert lines == (s.scalar(select(func.sum(LogicGroup.copies)).where(LogicGroup.id.in_(want))) or 0), q
                if not want:
                    assert facets == {}, q
                    continue
                ref = _reference_facets(s, want)
                assert Counter(dict(facets["source"])) == ref["sources"], q
                assert Counter(dict(facets["flags"])) == ref["flags"], q
                assert Counter(dict(facets["loads"])) == ref["loads_in"], q
                assert Counter(dict(facets["fails"])) == ref["fails_in"], q
                assert Counter(dict(facets["severity"])) == ref["severity"], q


def test_severity_filters_ignore_case_like_lower(ws: Path):  # noqa: F811
    """NOCASE comparisons (no per-row lower()) find the same rows as lower(column) = value."""
    w = Workspace(ws)
    c = sqlite3.connect(w.db_path)
    c.execute("UPDATE logic_groups SET severity = 'MaJoR' WHERE id = (SELECT min(id) FROM logic_groups)")
    c.commit()
    sf = session_factory(w.db_path)
    with sf() as s:
        for q in ("severity:major", "severity:MAJOR"):
            got = {g.id for g in s.scalars(search.build(search.parse_query(q), families=False, include_junk=True))}
            want = {i for (i,) in c.execute("SELECT id FROM logic_groups WHERE lower(severity) = 'major'")}
            assert got == want and got
        everything = search.build(search.parse_query(""), families=False, include_junk=True)
        stmt = ui.apply_extra(everything, [("severity", "major,none")], remapped=set(), lic_sources={})
        got = {g.id for g in s.scalars(stmt)}
        want = {i for (i,) in c.execute("SELECT id FROM logic_groups WHERE lower(severity) = 'major' OR severity IS NULL")}
        assert got == want


def _values(path: Path) -> list[tuple]:
    return sqlite3.connect(path).execute("SELECT group_id, kind, pos, value, lvalue FROM logic_group_values ORDER BY 1, 2, 3").fetchall()


def test_migration_fills_values_from_an_existing_index_and_downgrades(ws: Path):  # noqa: F811
    """A database indexed by the previous schema (0001) gets the table filled on upgrade, without a reindex."""
    from alembic import command

    w = Workspace(ws)
    built = _values(w.db_path)
    c = sqlite3.connect(w.db_path)
    want = c.execute(
        " UNION ALL ".join(
            f"SELECT g.id, '{k}', j.key, j.value, lower(j.value) FROM logic_groups g, json_each(g.{k}) j" for k in VALUE_KINDS
        )
        + " ORDER BY 1, 2, 3"
    ).fetchall()
    assert built == want and built  # what `index` wrote
    cfg = alembic_config(w.db_path)
    command.downgrade(cfg, "0001")
    assert not c.execute("SELECT name FROM sqlite_master WHERE name LIKE 'logic_group_values%'").fetchall()
    with pytest.raises(Exception, match="doctor"):
        session_factory(w.db_path)  # the code refuses a database behind its schema
    from typer.testing import CliRunner

    from suriharvest.cli import app

    r = CliRunner().invoke(app, ["search", "x"])
    assert r.exit_code == 2 and "doctor" in r.output  # a read-only command refuses
    run("sync")  # a command that writes upgrades under the lock
    assert _values(w.db_path) == want
    command.downgrade(cfg, "0001")
    run("doctor")  # the upgrade alone (no reindex) fills the table from logic_groups
    assert _values(w.db_path) == want
    assert c.execute("SELECT version_num FROM alembic_version").fetchone()[0] == "0002"


def test_web_search_counts_follow_verdicts(ws: Path):  # noqa: F811
    """The search page keeps totals and facets per query; a verdict set without a reindex must not reuse them."""
    import re

    client = TestClient(create_app(Workspace(ws), allowed_hosts={"testserver"}))

    def shown() -> int:
        m = re.search(r'<p class="total mb-0"><strong>([0-9,]+) rule', client.get("/search?q=ioc:no").text)
        assert m
        return int(m.group(1).replace(",", ""))

    before = shown()
    assert before == client.get("/api/search?q=ioc:no").json()["total"] and before > 1
    victim = client.get("/api/search?q=ioc:no").json()["results"][0]["logic_hash"]
    run("triage", victim, "drop")
    assert shown() == before - 1  # dropped rules are hidden by default
    run("triage", victim, "clear")
    assert shown() == before


def test_web_readers_setting(ws: Path, monkeypatch: pytest.MonkeyPatch):  # noqa: F811
    monkeypatch.setenv("SURIHARVEST_WEB_READERS", "1")
    client = TestClient(create_app(Workspace(ws), allowed_hosts={"testserver"}))
    for path in ("/", "/search?q=ioc:no", "/search?q=ioc:no&page=2", "/sources", "/api/search?q=", "/export"):
        assert client.get(path).status_code == 200, path  # one reader: a page that reads twice does not wait on itself
    for bad in ("0", "65", "two"):
        monkeypatch.setenv("SURIHARVEST_WEB_READERS", bad)
        with pytest.raises(ValueError, match="SURIHARVEST_WEB_READERS"):
            create_app(Workspace(ws))
