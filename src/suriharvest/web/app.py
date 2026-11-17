"""Web UI: FastAPI + Jinja2, no JS build.

Local by default: binds 127.0.0.1, accepts only local Host headers (DNS rebinding), every POST must be
same-origin and carry the per-process CSRF token, bodies are capped, and a strict CSP forbids inline scripts and
styles. Binding elsewhere requires a token (HTTP Basic, any user name) read from an environment variable.
Writes (exclusions) take the workspace lock briefly; while an update holds it they answer 503.

Pages (sidebar): Overview /, Search /search, Sources /sources, Builds & changes /builds, Profiles & exclusions
/profiles, Export /export, About & licences /about; Jobs & health /jobs in the sidebar footer.
"""

from __future__ import annotations

import base64
import contextlib
import hmac
import json
import logging
import os
import secrets
import shlex
import shutil
import tempfile
import threading
import zipfile
from collections import Counter, OrderedDict
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlsplit

from fastapi import FastAPI, Form, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import case, func, literal, null, select, text, union_all
from sqlalchemy.orm import Session, sessionmaker
from starlette.exceptions import HTTPException as StarletteHTTPException

from suriharvest import __version__
from suriharvest.config import Workspace, load_sources
from suriharvest.db import get_meta, head_revision, in_list, session_factory
from suriharvest.lock import LockBusy, workspace_lock
from suriharvest.models import (
    Exclusion,
    LogicGroup,
    LogicGroupValue,
    NearDuplicate,
    Occurrence,
    Profile,
    ProfileBuild,
    Quarantine,
    RuleKey,
    RuleVersion,
    Source,
    SyncLog,
    UpdateRun,
    ValidationResult,
    Verdict,
)
from suriharvest.portable import rmtree
from suriharvest.urls import redact_url
from suriharvest.web import ui

HERE = Path(__file__).parent
MAX_BODY = 1024 * 1024
# GET routes that do real work (exports, feeds, the JSON API): refused when a browser says another site asked.
EXPENSIVE_GET = ("/export", "/feed/", "/api/")
# Ruleset downloads built on request: at most EXPORT_RUNNING at a time, EXPORT_WAITING more queue, the rest get 429.
EXPORT_RUNNING = 1
EXPORT_WAITING = 2
EXPORT_WAIT_SECONDS = 300
# Finished downloads being sent: at most EXPORT_SENDING at once (each holds an open, already deleted temp file), and
# a client that takes more than SEND_IDLE_SECONDS to accept the next chunk is disconnected.
EXPORT_SENDING = 4
SEND_IDLE_SECONDS = 60.0
log = logging.getLogger("suriharvest.web")
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}  # tests add "testserver" (TestClient) via allowed_hosts
PAGE = 50
API_MAX_PER_PAGE = 200
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; "
    "object-src 'none'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'"
)
SORTS = {
    "best": "Best match",
    "severity": "Severity",
    "sources": "Most sources",
    "recent": "Recently changed",
    "sid": "sid",
}
SEV_ORDER = case(
    (LogicGroup.severity.collate("NOCASE") == "critical", 0),
    (LogicGroup.severity.collate("NOCASE") == "major", 1),
    (LogicGroup.severity.collate("NOCASE") == "minor", 2),
    (LogicGroup.severity.collate("NOCASE") == "informational", 3),
    else_=4,
)
FAIL_WORDS = {
    "unknown_keyword": "keyword or buffer this Suricata does not know",
    "disabled_protocol": "app-layer protocol turned off in suricata.yaml",
    "missing_file": "dataset or lua file not shipped with the source",
    "unsafe_path": "dataset file path is absolute or outside the source (never checked, never published)",
    "syntax": "syntax this Suricata rejects",
    "pcre": "pcre this Suricata rejects",
}
JOB_SECTION = {"update": "overview", "source": "sources", "build": "profiles"}


def _web_readers() -> int:
    """SURIHARVEST_WEB_READERS: requests that read the database at the same time (default 2, 1 to 64)."""
    raw = os.environ.get("SURIHARVEST_WEB_READERS", "2")
    if not raw.isdigit() or not 1 <= int(raw) <= 64:
        raise ValueError("SURIHARVEST_WEB_READERS must be a number from 1 to 64")
    return int(raw)


def create_app(ws: Workspace, *, token: str | None = None, allowed_hosts: set[str] | None = None) -> FastAPI:
    # Up to 20 connections (each keeps its own SQLite page cache, so not one per server thread): downloads build in
    # a child process with its own connection, so no long request holds one; a pool wait that times out is a 503.
    db_sessions: sessionmaker[Session] = session_factory(ws.db_path, pool_size=8, max_overflow=12, pool_timeout=20)
    # Requests work on the database WEB_READERS at a time (background jobs do not count). Each row SQLite returns
    # hands the GIL to another thread and back, so many requests reading at once in one process are slower in
    # total than a few: measured on a core workspace, 10 clients of filtered searches went from 11 to 2x req/s.
    readers = threading.BoundedSemaphore(_web_readers())
    holding = threading.local()

    @contextmanager
    def sessions() -> Iterator[Session]:
        """A session for a request; waits for a reader slot (a 503 after 20 s). Re-entrant within one thread."""
        if getattr(holding, "n", 0):
            holding.n += 1
            try:
                with db_sessions() as s:
                    yield s
            finally:
                holding.n -= 1
            return
        if not readers.acquire(timeout=20):
            raise HTTPException(503, "the server is busy: try again in a moment")
        holding.n = 1
        try:
            with db_sessions() as s:
                yield s
        finally:
            holding.n = 0
            readers.release()

    csrf = secrets.token_urlsafe(32)
    hosts = LOCAL_HOSTS | (allowed_hosts or set())
    app = FastAPI(title="suriharvest", docs_url=None, redoc_url=None, openapi_url=None)
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    tpl = Jinja2Templates(directory=HERE / "templates")
    from suriharvest import project

    tpl.env.globals.update(
        version=__version__,
        csrf=csrf,
        workspace=ui.display_path(ws.root),
        repo_url=project.repo_url(),
        issues_url=project.issues_url(),
        contact_email=project.CONTACT_EMAIL,
        not_affiliated=project.NOT_AFFILIATED,
        trademarks=project.TRADEMARKS,
    )
    tpl.env.filters.update(
        short=lambda h, n=10: (h or "")[:n],
        fromjson=json.loads,
        num=ui.num,
        reltime=ui.reltime,
        fulltime=ui.fulltime,
        rule_html=ui.rule_html,
        wcls=ui.width_class,
        heat=ui.heat_class,
        lic_short=ui.licence_short,
        eng_short=ui.short_engine,
        eng_label=ui.engine_label,
        toggle=ui.toggle,
    )
    tpl.env.globals.update(
        src_lic=lambda src: (
            (ui.licence_short(src.licence), ui.licence_class(src.licence, src.redistribute)) if src is not None else ("unknown", "none")
        )
    )
    tpl.env.filters["mark"] = ui.mark
    tpl.env.filters["redact_url"] = lambda u: redact_url(u) or "local source"
    # A link built from sources.yaml (homepage) is shown only when it is http(s): never javascript:, data: or a path.
    tpl.env.filters["web_link"] = lambda u: (
        u if u and urlsplit(u.strip()).scheme in ("http", "https") and urlsplit(u.strip()).netloc else ""
    )
    tpl.env.globals["rule_lic"] = ui.rule_licence
    tpl.env.globals["friendly_error"] = ui.friendly_error
    tpl.env.globals.update(
        IOC_WORDS=ui.IOC_WORDS,
        since=lambda days: (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%d"),
        qurl=lambda base, **over: "/search?" + urlencode({k: v for k, v in {**base, **over}.items() if v not in (None, "", 0)}),
    )
    tpl.env.globals.update(LIC_TITLES=ui.LIC_TITLES, LIC_WORDS=ui.LIC_WORDS, CLASSTYPES=ui.CLASSTYPES, urlencode=urlencode)
    from suriharvest.web.jobs import Busy, Jobs

    jobs = Jobs()
    exports = ExportQueue()
    app.state.exports = exports  # tests and diagnostics: queue and send counters
    sweep_stale_downloads()
    export_cache: OrderedDict[tuple[Any, ...], tuple[Any, ...]] = OrderedDict()
    export_lock = threading.Lock()
    # Search totals and facets by query: a page change, a sort change or the same query again reuses them. The key
    # holds what they depend on besides the query (counts_key), so an index rebuild or a verdict change misses.
    counts_cache: OrderedDict[tuple[Any, ...], tuple[int, int, dict[str, Any]]] = OrderedDict()
    counts_lock = threading.Lock()
    summary_cache: OrderedDict[tuple[Any, ...], str] = OrderedDict()  # (version id, fields) -> search-row summary
    summary_lock = threading.Lock()
    tpl.env.globals["jobs"] = jobs
    cache: dict[str, Any] = {}

    @app.middleware("http")
    async def guard(request: Request, call_next):  # type: ignore[no-untyped-def]
        raw = request.headers.get("host") or ""
        host = raw[: raw.find("]") + 1] if raw.startswith("[") else raw.rsplit(":", 1)[0]
        if host not in hosts:
            return PlainTextResponse(
                f"host {host!r} not allowed: start `suriharvest serve` with --allow-host {host or 'NAME'} (needed with --host 0.0.0.0)",
                status_code=421,
            )
        if token is not None and not _authorised(request, token):
            return PlainTextResponse("authentication required", status_code=401, headers={"WWW-Authenticate": 'Basic realm="suriharvest"'})
        if request.method not in ("GET", "HEAD"):
            origin = request.headers.get("origin") or request.headers.get("referer")
            if not origin or urlsplit(origin).netloc != request.headers.get("host"):
                return PlainTextResponse("cross-site request refused", status_code=403)
            # A body must announce its size: a chunked body has no Content-Length and was parsed in full before.
            # Without either header a request has no body; the server holds a body to its length.
            if request.headers.get("transfer-encoding"):
                return PlainTextResponse("a request body needs a Content-Length (no chunked uploads)", status_code=411)
            length = request.headers.get("content-length") or "0"
            if not length.isascii() or not length.isdigit() or len(length) > 12 or int(length) > MAX_BODY:
                return PlainTextResponse("request too large", status_code=413)
        elif request.url.path.startswith(EXPENSIVE_GET) and not _same_origin_get(request):
            # `<img src=http://127.0.0.1:8077/export/download?q=...>` on another site must not start exports
            return PlainTextResponse("cross-site request refused", status_code=403)
        try:
            resp = await call_next(request)
        except Exception as e:  # noqa: BLE001 - answer every request; an escaped exception reset the keep-alive connection
            resp = _error_response(e)
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "same-origin"
        return resp

    def check_csrf(value: str | None) -> None:
        if not value or not hmac.compare_digest(value, csrf):
            raise HTTPException(403, "missing or stale form token: reload the page")

    # -----------------------------------------------------------------------------------------------------------
    # shared state for the sidebar and every page (cached by index time and last build)

    def engine_names() -> list[str]:
        return [e.name for e in ws.settings().engines]

    def status(s: Session) -> dict[str, Any]:
        indexed = get_meta(s, "indexed_at")
        last_build_id = s.scalar(select(func.max(ProfileBuild.id)))
        n_ex = s.scalar(select(func.count()).select_from(Exclusion))
        key = (indexed, last_build_id, n_ex)
        if cache.get("status_key") == key:
            st = dict(cache["status"])
        else:
            n_rules = s.scalar(select(func.count()).select_from(LogicGroup)) or 0
            versions = {}
            for e in engine_names():
                row = s.execute(
                    select(ValidationResult.engine_version, ValidationResult.checked_at)
                    .where(ValidationResult.engine == e)
                    .order_by(ValidationResult.checked_at.desc())
                    .limit(1)
                ).first()
                versions[e] = (row[0].split()[0] if row and row[0] else None, row[1] if row else None)
            first = s.scalars(select(Profile).order_by(Profile.id).limit(1)).first()
            badge = 0
            if first is not None and last_build_id:
                from suriharvest.profiles import last_build, new_since_last_build

                if last_build(s, first) is not None:
                    try:
                        badge = len(new_since_last_build(s, first))
                    except Exception:  # noqa: BLE001 - a broken profile query must not break every page
                        badge = 0
            st = {
                "indexed": indexed,
                "n_rules": n_rules,
                "engines": [(e, ui.short_engine(e), versions[e][0], versions[e][1]) for e in engine_names()],
                "new_badge": badge,
                "first_profile": first.name if first else None,
            }
            cache["status_key"], cache["status"] = key, dict(st)
        srcs = list(sources_map(s).values())
        latest = select(func.max(SyncLog.id)).group_by(SyncLog.source_id)  # each source's last sync
        last = {
            sid_: (st_, err)
            for sid_, st_, err in s.execute(select(SyncLog.source_id, SyncLog.status, SyncLog.error).where(SyncLog.id.in_(latest)))
        }
        st["n_sources"] = sum(1 for r in srcs if r.enabled)
        st["failing"] = [
            (r.name, (last[r.id][1] or "")[:160]) for r in srcs if r.enabled and r.id in last and last[r.id][0] not in ("ok", "running")
        ]
        st["empty"] = not st["n_rules"]
        return st

    def render(request: Request, name: str, section: str, status_code: int = 200, **ctx: Any) -> HTMLResponse:
        with sessions() as s:
            st = status(s)
        return tpl.TemplateResponse(
            request, name, {"section": section, "st": st, "running": jobs.current(), **ctx}, status_code=status_code
        )

    def back(request: Request, fallback: str) -> RedirectResponse:
        ref = request.headers.get("referer") or ""
        parts = urlsplit(ref)
        dest = (
            parts.path + (f"?{parts.query}" if parts.query else "")
            # "//host/x" or "/\\host/x" would leave the site (a protocol-relative redirect).
            if parts.netloc == request.headers.get("host") and parts.path.startswith("/") and not parts.path.startswith(("//", "/\\"))
            else fallback
        )
        return RedirectResponse(dest, status_code=303)

    def sources_map(s: Session) -> dict[str, Source]:
        """name -> source, read once per session (several parts of one page need it; every row read from SQLite
        hands the GIL to another request thread and back, so a busy server pays for each one)."""
        if "sources" not in s.info:
            s.info["sources"] = {r.name: r for r in s.scalars(select(Source).order_by(Source.id))}
        return s.info["sources"]

    def lic_sources(s: Session) -> dict[str, set[str]]:
        return ui.licence_groups(s, list(sources_map(s).values()))

    def remapped_map() -> dict[str, tuple[int, int]]:
        """logic hash -> (original sid, exported sid) for rules whose sid was remapped (sid clash)."""
        from suriharvest.sidmap import SidMap

        f = ws.sid_map_file
        mtime = f.stat().st_mtime if f.exists() else 0
        if cache.get("sidmap_key") != mtime:
            m = SidMap(f) if f.exists() else SidMap(None)
            cache["sidmap"] = {h: (e.original, e.sid) for h, e in m.entries.items() if e.sid != e.original}
            cache["sidmap_key"] = mtime
        return cache["sidmap"]

    def query_stmt(s: Session, q: str, *, every: bool = False, junk: bool = False):  # type: ignore[no-untyped-def]
        """The search statement for a query string with the web extras (cve:, flowbits:, metadata: ...)."""
        from suriharvest.search import build, check_size, parse_query

        check_size(q)
        try:
            base, extra = ui.split_query(q, engine_names())
        except ValueError as e:
            from suriharvest.search import QueryError

            raise QueryError(str(e)) from e
        if "dialect:snort" in base.lower():
            junk = True
        stmt = build(parse_query(base), families=not every, include_junk=junk)
        try:
            return ui.apply_extra(stmt, extra, remapped=set(remapped_map()), lic_sources=lic_sources(s))
        except ValueError as e:
            from suriharvest.search import QueryError

            raise QueryError(str(e)) from e

    def feed_url(request: Request, profile: str, engine: str | None) -> str:
        base = str(request.base_url).rstrip("/")
        eng = ui.short_engine(engine) if engine else ui.short_engine(engine_names()[0]) if engine_names() else "all"
        return f"{base}/feed/{profile}/suricata-{eng}.tar.gz" if eng.isdigit() else f"{base}/feed/{profile}/{eng}.tar.gz"

    def profile_cards(s: Session, request: Request) -> list[dict[str, Any]]:
        from suriharvest.profiles import exclusion_file, exclusions, last_build

        cards = []
        for t in s.scalars(select(Profile).order_by(Profile.id)):
            b = last_build(s, t)
            cards.append(
                {
                    "t": t,
                    "b": b,
                    "n_excl": len(exclusions(s, t)),
                    "efile": exclusion_file(ws, t).relative_to(ws.root),
                    "feed": feed_url(request, t.name, t.engine),
                    "new": (cache.get("status") or {}).get("new_badge", 0)
                    if t.name == (cache.get("status") or {}).get("first_profile")
                    else None,
                }
            )
        return cards

    # -----------------------------------------------------------------------------------------------------------
    # pages

    def overview_key(s: Session) -> tuple[Any, ...]:
        """What the overview aggregates depend on: the index, the last update run, the sources' licences, the
        engines and the sid map. Unchanged key -> the cached numbers are still right."""
        f = ws.sid_map_file
        return (
            get_meta(s, "indexed_at"),
            s.scalar(select(func.max(UpdateRun.id))),
            tuple(s.execute(select(Source.name, Source.licence, Source.redistribute, Source.enabled).order_by(Source.id)).all()),
            tuple(engine_names()),
            f.stat().st_mtime if f.exists() else 0,
        )

    def rule_summaries(s: Session, rows: list[LogicGroup]) -> dict[str, str]:
        """The one-line summary of each row (logic hash -> text). A summary depends only on the rule version and
        the fields below, so it is kept (summary_cache); only the versions not seen yet are read and parsed."""
        from suriharvest.summary import summarize

        keys = {g.logic_hash: (g.canonical_version_id, g.app_layer, g.ioc_type, g.ioc_value, g.msg) for g in rows}
        with summary_lock:
            out = {h: summary_cache[k] for h, k in keys.items() if k in summary_cache}
        todo = [g for g in rows if g.logic_hash not in out]
        if not todo:
            return out
        raws = dict(
            s.execute(select(RuleVersion.id, RuleVersion.raw).where(in_list(RuleVersion.id, [g.canonical_version_id for g in todo]))).all()
        )
        for g in todo:
            try:
                out[g.logic_hash] = summarize(
                    raws.get(g.canonical_version_id, ""), app_layer=g.app_layer, ioc_type=g.ioc_type, ioc_value=g.ioc_value, msg=g.msg
                ).short
            except Exception:  # noqa: BLE001 - a summary must never break the page
                out[g.logic_hash] = ""
        with summary_lock:
            for g in todo:
                summary_cache[keys[g.logic_hash]] = out[g.logic_hash]
            while len(summary_cache) > 20_000:
                summary_cache.popitem(last=False)
        return out

    def counts_key(s: Session) -> tuple[Any, ...]:
        """What a result set depends on besides its query: the index, the verdicts (set without a rebuild), the
        sources' licences (licence:), the engines (loads:/fails:) and the sid map (remapped:)."""
        f = ws.sid_map_file
        return (
            get_meta(s, "indexed_at"),
            *s.execute(select(func.count(), func.max(Verdict.updated_at)).select_from(Verdict)).one(),
            tuple((r.name, r.licence, r.redistribute) for r in sources_map(s).values()),
            tuple(engine_names()),
            f.stat().st_mtime if f.exists() else 0,
        )

    def cached_counts(s: Session, sub: Any, srcs: dict[str, Source], q: str, every: bool, junk: bool) -> tuple[int, int, dict[str, Any]]:
        key = (q, every, junk, *counts_key(s))
        with counts_lock:
            hit = counts_cache.get(key)
            if hit is not None:
                counts_cache.move_to_end(key)
                return hit
        got = _counts(s, sub, srcs)
        with counts_lock:
            counts_cache[key] = got
            while len(counts_cache) > 256:
                counts_cache.popitem(last=False)
        return got

    def overview_numbers(s: Session) -> dict[str, Any]:
        key = overview_key(s)
        if cache.get("overview_key") == key:
            return cache["overview"]
        rep = json.loads(get_meta(s, "index_report") or "{}")
        total = s.scalar(select(func.count()).select_from(LogicGroup)) or 0
        occ = s.scalar(select(func.count()).select_from(Occurrence).where(Occurrence.present.is_(True))) or 0
        apps = s.execute(
            select(LogicGroup.app_layer, func.count()).group_by(LogicGroup.app_layer).order_by(func.count().desc()).limit(12)
        ).all()
        iocs = s.execute(
            select(LogicGroup.ioc_type, func.count())
            .where(LogicGroup.is_ioc.is_(True))
            .group_by(LogicGroup.ioc_type)
            .order_by(func.count().desc())
        ).all()
        loads: Counter[str] = Counter(
            dict(s.execute(text("SELECT j.value, count(*) FROM logic_groups, json_each(logic_groups.loads_in) j GROUP BY j.value")).all())
        )
        fails: Counter[str] = Counter(
            dict(s.execute(text("SELECT j.value, count(*) FROM logic_groups, json_each(logic_groups.fails_in) j GROUP BY j.value")).all())
        )
        engines = []
        for e in engine_names():
            checked = s.scalar(select(func.max(ValidationResult.checked_at)).where(ValidationResult.engine == e))
            ver = s.scalar(select(ValidationResult.engine_version).where(ValidationResult.engine == e).limit(1))
            reasons = s.execute(
                select(ValidationResult.category, func.count())
                .join(RuleVersion, RuleVersion.content_hash == ValidationResult.content_hash)
                .join(LogicGroup, LogicGroup.canonical_version_id == RuleVersion.id)
                .where(ValidationResult.engine == e, ValidationResult.status != "ok")
                .group_by(ValidationResult.category)
                .order_by(func.count().desc())
            ).all()
            engines.append(
                {
                    "name": e,
                    "short": ui.short_engine(e),
                    "version": (ver or "").split()[0] if ver else None,
                    "checked": checked,
                    "loads": loads.get(e, 0),
                    "fails": fails.get(e, 0),
                    "unchecked": max(0, total - loads.get(e, 0) - fails.get(e, 0)),
                    "reasons": [(c or "other", FAIL_WORDS.get(c or "", (c or "other").replace("_", " ")), n) for c, n in reasons],
                }
            )
        srcs = sources_map(s)
        canon = s.execute(
            select(LogicGroup.canonical_source, func.count()).group_by(LogicGroup.canonical_source).order_by(func.count().desc())
        ).all()
        gpl = dict(
            s.execute(
                select(LogicGroup.canonical_source, func.count()).where(LogicGroup.msg.like("GPL %")).group_by(LogicGroup.canonical_source)
            ).all()
        )
        lic_counts: Counter[str] = Counter()
        lic_names: dict[str, set[str]] = {}
        for name, n in canon:
            src = srcs.get(name)
            if src is None:
                continue
            low = (src.licence or "").lower()
            if "bsd" in low and "gpl" in low:
                lic_counts["permissive"] += n - gpl.get(name, 0)
                lic_counts["copyleft"] += gpl.get(name, 0)
                lic_names.setdefault("permissive", set()).add("BSD")
                lic_names.setdefault("copyleft", set()).add("GPL-2.0 (ET GPL rules)")
            else:
                cls = ui.licence_class(src.licence, src.redistribute)
                lic_counts[cls] += n
                lic_names.setdefault(cls, set()).add(ui.licence_short(src.licence))
        starts = []
        first_eng = engine_names()[0] if engine_names() else None
        for label, q in [
            (
                f"Critical and major rules{' that load in ' + ui.engine_label(first_eng) if first_eng else ''}",
                "severity:critical,major" + (f" loads:{ui.short_engine(first_eng)}" if first_eng else ""),
            ),
            ("Rules for a CVE", "cve:*"),
            ("Malware command and control", "classtype:command-and-control"),
            ("Rules needing a flowbit that nothing sets", "flag:missing_setter"),
            ("TLS certificate and JA3 indicators", "app:tls ioc:yes"),
            ("Sid clashes that were remapped", "remapped:yes"),
        ]:
            try:
                stmt = query_stmt(s, q)
                n = s.scalar(select(func.count()).select_from(stmt.subquery())) or 0
            except Exception:  # noqa: BLE001
                n = 0
            if n or q == "cve:*":
                starts.append((label, q, n))
        # last changed (metadata updated_at, else created_at) by year, and the signature_severity split: one scan
        today = datetime.now(UTC)
        cutoff = (today - timedelta(days=365)).strftime("%Y-%m-%d")
        by_year: dict[int, int] = {}
        undated = recent = 0
        sev_counts: Counter[str] = Counter()
        year = func.substr(LogicGroup.updated, 1, 4)
        for y, sv, n, n_recent in s.execute(
            select(
                year, func.lower(LogicGroup.severity), func.count(), func.sum(case((LogicGroup.updated >= cutoff, 1), else_=0))
            ).group_by(year, func.lower(LogicGroup.severity))
        ).all():
            recent += n_recent or 0
            if y and str(y).isdigit() and 1990 <= int(y) <= today.year:
                by_year[int(y)] = by_year.get(int(y), 0) + n
            else:
                undated += n
            sev_counts[sv if sv in ("critical", "major", "minor", "informational") else "unrated"] += n
        ages = ui.age_chart(by_year, undated, recent, total, today.year)
        severity = ui.composition(
            list(sev_counts.items()),
            ("critical", "major", "minor", "informational", "unrated"),
            lambda k: "/search?" + urlencode({"q": "severity:" + (k if k != "unrated" else "none")}),
            "seg-",
        )
        numbers = {
            "rep": rep,
            "ages": ages,
            "severity": severity,
            "total": total,
            "occ": occ,
            "apps": apps,
            "iocs": iocs,
            "engines": engines,
            "canon": canon,
            "lic_counts": lic_counts,
            "lic_names": {k: sorted(v) for k, v in lic_names.items()},
            "starts": starts[:5],
        }
        cache["overview_key"], cache["overview"] = key, numbers
        return numbers

    def warm() -> None:
        """Compute the sidebar status and the overview numbers once in the background when `serve` starts, so the
        first visit is not the one that waits for them (one to three seconds on a full corpus)."""
        try:
            with sessions() as s:
                status(s)  # the sidebar of every page (its "new to review" count reads the whole profile once)
                overview_numbers(s)
                first = s.scalars(select(Profile).order_by(Profile.id).limit(1)).first()
                if first is not None:
                    builds_ctx(s, first, "previous", "latest", "added", 1)  # the diff shown by Builds & changes
        except Exception:
            log.debug("overview warm-up failed", exc_info=True)

    app.state.warm = warm

    @app.get("/", response_class=HTMLResponse)
    def overview(request: Request) -> HTMLResponse:
        with sessions() as s:
            o = overview_numbers(s)
            srcs = sources_map(s)
            runs = list(s.scalars(select(UpdateRun).order_by(UpdateRun.id.desc()).limit(1)))
            run = runs[0] if runs else None
            changes = []
            if run and run.changes:
                sample = [("new", r) for r in (run.changes.get("new_sample") or [])[:4]] + [
                    ("removed", r) for r in (run.changes.get("gone_sample") or [])[:2]
                ]
                info = {
                    g.logic_hash: g
                    for g in s.scalars(select(LogicGroup).where(in_list(LogicGroup.logic_hash, [r["logic_hash"] for _, r in sample])))
                }
                for kind, r in sample:
                    changes.append((kind, r, info.get(r["logic_hash"])))
            cards = profile_cards(s, request)
            remapped = remapped_map()
            history = [
                int((r.counts or {}).get("unique_logic") or 0)
                for r in reversed(
                    list(s.scalars(select(UpdateRun).where(UpdateRun.finished_at.is_not(None)).order_by(UpdateRun.id.desc()).limit(24)))
                )
            ]
            trend = ui.spark([n for n in history if n > 0])
        apps, canon = o["apps"], o["canon"]
        app_top = max((n for _, n in apps), default=1) or 1
        src_top = max((n for _, n in canon), default=1) or 1
        return render(
            request,
            "overview.html",
            "overview",
            rep=o["rep"],
            total=o["total"],
            occ=o["occ"],
            apps=apps,
            app_top=app_top,
            iocs=o["iocs"],
            engines=o["engines"],
            canon=canon[:7],
            n_canon=len(canon),
            src_top=src_top,
            srcs=srcs,
            lic_counts=o["lic_counts"],
            lic_names=o["lic_names"],
            run=run,
            changes=changes,
            cards=cards,
            remapped=len(remapped),
            starts=o["starts"],
            ages=o["ages"],
            severity=o["severity"],
            trend=trend,
        )

    @app.get("/search", response_class=HTMLResponse)
    def search_page(
        request: Request,
        q: str = "",
        all: int = 0,
        junk: int = 0,
        page: int = 1,
        sort: str = "best",
        view: str = "cards",
        layout: str = "",
    ) -> HTMLResponse:
        from suriharvest.search import QueryError, page_rows

        page = max(1, min(page, 1_000_000))
        sort = sort if sort in SORTS else "best"
        # view=table is the shared name (docs/conventions.md); layout=table is sigharvest's old one, accepted here too.
        view = "table" if "table" in (view, layout) else "cards"
        error = None
        total, rows, lines, facets = 0, [], 0, {}
        alone = None
        hints: list[str] = []
        remapped = remapped_map()
        with sessions() as s:
            srcs = sources_map(s)
            try:
                stmt = query_stmt(s, q, every=bool(all), junk=bool(junk))
                sub = stmt.subquery()
                total, lines, facets = cached_counts(s, sub, srcs, q, bool(all), bool(junk))
                order = {
                    "best": [LogicGroup.score.desc(), LogicGroup.id],
                    "severity": [SEV_ORDER, LogicGroup.score.desc(), LogicGroup.id],
                    "sources": [LogicGroup.n_sources.desc(), LogicGroup.score.desc(), LogicGroup.id],
                    "recent": [LogicGroup.updated.is_(None), LogicGroup.updated.desc(), LogicGroup.id],
                    "sid": [LogicGroup.sid, LogicGroup.id],
                }[sort]
                rows = page_rows(s, stmt, order, PAGE, (page - 1) * PAGE)
                if not total and q.strip():
                    hints = ui.value_hints(s, q)
                    words = [t for t in ui.tokens_of(q) if ":" not in t and not t.startswith(("score", "updated"))]
                    if words and len(words) < len(ui.tokens_of(q)):
                        wq = " ".join(words)
                        alone = (wq, s.scalar(select(func.count()).select_from(query_stmt(s, wq).subquery())) or 0)
            except QueryError as e:
                error = str(e)
            summaries = rule_summaries(s, rows)
            first = s.scalars(select(Profile).order_by(Profile.id).limit(1)).first()
        base = {"q": q, "sort": sort, "view": view} | ({"all": 1} if all else {}) | ({"junk": 1} if junk else {})
        pages = (total + PAGE - 1) // PAGE
        prev_url = "/search?" + urlencode({**base, "page": page - 1}) if page > 1 else None
        next_url = "/search?" + urlencode({**base, "page": page + 1}) if page < pages else None
        lic = {g.logic_hash: ui.rule_licence(srcs.get(g.canonical_source), g.msg) for g in rows}
        return render(
            request,
            "search.html",
            "search",
            q=q,
            rows=rows,
            total=total,
            lines=lines,
            error=error,
            all=all,
            junk=junk,
            page=page,
            pages=pages,
            prev_url=prev_url,
            next_url=next_url,
            facets=facets,
            sort=sort,
            sorts=SORTS,
            view=view,
            base=base,
            summaries=summaries,
            lics=lic,
            remapped=remapped,
            tokens=ui.tokens_of(q),
            words=[t for t in ui.tokens_of(q) if ":" not in t and ">" not in t and "<" not in t],
            filters_only=" ".join(t if " " not in t else f'"{t}"' for t in ui.tokens_of(q) if ":" in t or ">" in t or "<" in t),
            open_attn=any(
                t in ui.tokens_of(q)
                for t in ("flag:missing_setter", "flag:needs_files", "enabled:no", "remapped:yes", "flag:deprecated", "flag:retired")
            ),
            open_syntax=any(t.startswith("dialect:") for t in ui.tokens_of(q)),
            alone=alone,
            hints=hints,
            engines=engine_names(),
            first_profile=first.name if first else None,
        )

    @app.get("/rule/{logic_hash}", response_class=HTMLResponse)
    def rule_page(request: Request, logic_hash: str) -> HTMLResponse:
        from suriharvest.sidalloc import owner
        from suriharvest.summary import rev_diff, summarize

        with sessions() as s:
            g = s.scalar(select(LogicGroup).where(LogicGroup.logic_hash == logic_hash))
            if g is None:
                raise HTTPException(404, "rule-not-found")
            v = s.get(RuleVersion, g.canonical_version_id)
            srcs = sources_map(s)
            copies = s.execute(
                select(
                    Source.name,
                    Source.url,
                    Occurrence.path,
                    Occurrence.line_no,
                    Occurrence.enabled,
                    RuleVersion.content_hash,
                    RuleVersion.rev,
                    RuleVersion.msg,
                    RuleVersion.logic_hash,
                )
                .join(Occurrence, Occurrence.source_id == Source.id)
                .join(RuleVersion, RuleVersion.id == Occurrence.version_id)
                .where(RuleVersion.logic_hash == g.logic_hash, Occurrence.present.is_(True))
                .order_by(Source.priority, Source.name)
                .limit(100)
            ).all()
            ns, gid, sid = g.rule_key.split(":")
            history = s.execute(
                select(
                    RuleVersion.rev,
                    RuleVersion.msg,
                    RuleVersion.logic_hash,
                    func.min(Occurrence.first_seen),
                    func.max(Occurrence.present),
                    RuleVersion.raw,
                )
                .join(Occurrence, Occurrence.version_id == RuleVersion.id)
                .join(Source, Source.id == Occurrence.source_id)
                .where(RuleVersion.sid == int(sid), RuleVersion.gid == int(gid), Source.sid_namespace == ns)
                .group_by(RuleVersion.id)
                .order_by(func.min(Occurrence.first_seen))
            ).all()
            revs = []
            prev_raw = None
            for rev, _msg, lh, first, live, raw in history:
                revs.append({"rev": rev, "lh": lh, "first": first, "live": live, "what": rev_diff(prev_raw, raw)})
                prev_raw = raw
            revs.reverse()
            key = s.get(RuleKey, g.rule_key)
            family = list(
                s.scalars(
                    select(LogicGroup)
                    .where(LogicGroup.family_id == g.family_id, LogicGroup.id != g.id)
                    .order_by(LogicGroup.score.desc())
                    .limit(10)
                )
            )
            validation = (
                s.execute(
                    select(
                        ValidationResult.engine,
                        ValidationResult.engine_version,
                        ValidationResult.status,
                        ValidationResult.category,
                        ValidationResult.error,
                        ValidationResult.checked_at,
                    )
                    .where(ValidationResult.content_hash == v.content_hash)
                    .order_by(ValidationResult.checked_at.desc())
                ).all()
                if v
                else []
            )
            setters: list[tuple[str, list[Any]]] = []
            setter_sid: dict[str, int] = {}
            if v and v.flowbits_check:
                for bit in v.flowbits_check[:10]:
                    cand = s.execute(
                        select(LogicGroup.logic_hash, LogicGroup.sid, LogicGroup.msg, LogicGroup.canonical_source, LogicGroup.loads_in)
                        .join(RuleVersion, RuleVersion.id == LogicGroup.canonical_version_id)
                        .where(RuleVersion.flowbits_set.contains(f'"{bit}"'), LogicGroup.logic_hash != g.logic_hash)
                        .order_by(LogicGroup.score.desc())
                        .limit(3)
                    ).all()
                    setters.append((bit, cand))
                    if cand:
                        setter_sid[bit.split(":", 1)[1]] = cand[0].sid
            needed_by: list[tuple[str, list[Any]]] = []
            if v and v.flowbits_set:
                for bit in v.flowbits_set[:10]:
                    users = s.execute(
                        select(LogicGroup.logic_hash, LogicGroup.sid, LogicGroup.msg, LogicGroup.canonical_source)
                        .join(RuleVersion, RuleVersion.id == LogicGroup.canonical_version_id)
                        .where(RuleVersion.flowbits_check.contains(f'"{bit}"'), LogicGroup.logic_hash != g.logic_hash)
                        .order_by(LogicGroup.score.desc())
                        .limit(5)
                    ).all()
                    needed_by.append((bit, users))
            near_rows = s.execute(
                select(NearDuplicate.a, NearDuplicate.b, NearDuplicate.jaccard).where(
                    (NearDuplicate.a == g.logic_hash) | (NearDuplicate.b == g.logic_hash)
                )
            ).all()
            other = {(b if a == g.logic_hash else a): j for a, b, j in near_rows}
            similar = (
                [(x, other[x.logic_hash]) for x in s.scalars(select(LogicGroup).where(in_list(LogicGroup.logic_hash, other)))]
                if other
                else []
            )
            similar.sort(key=lambda t: -t[1])
            from suriharvest.profiles import Matcher, exclusions

            profile_status = []
            for t in s.scalars(select(Profile).order_by(Profile.id)):
                ex = Matcher.build(s, exclusions(s, t)).match(g)
                if ex is not None:
                    profile_status.append((t.name, "excluded", ex))
                elif t.engine and t.engine in (g.fails_in or []):
                    profile_status.append((t.name, "fails", None))
                else:
                    profile_status.append((t.name, "included", None))
            summary = summarize(
                v.raw if v else "", app_layer=g.app_layer, ioc_type=g.ioc_type, ioc_value=g.ioc_value, setters=setter_sid, msg=g.msg
            )
        meta = v.rule_metadata if v else {}
        cves = sorted(
            {
                ("CVE-" + r.split(",", 1)[1].strip().upper().removeprefix("CVE-"))
                for r in (v.references if v else [])
                if r.lower().startswith("cve,")
            }
            | {c.upper().replace("_", "-") for c in meta.get("cve", [])}
        )
        refs = []
        for r in v.references if v else []:
            kind, _, val = r.partition(",")
            val = val.strip()
            kind = kind.strip().lower()
            if kind == "cve":
                c = "CVE-" + val.upper().removeprefix("CVE-")
                refs.append((f"NVD {c}", f"https://nvd.nist.gov/vuln/detail/{c}"))
            elif kind == "url":
                refs.append((val[:60], val if val.startswith(("http://", "https://")) else "https://" + val))
            elif kind == "md5" or kind == "sha256":
                refs.append((f"{kind} {val[:16]}…", None))
            else:
                refs.append((f"{kind} {val}", None))
        alloc = owner(g.gid, g.sid, g.msg)
        lic = ui.rule_licence(srcs.get(g.canonical_source), g.msg)
        remap = remapped_map().get(g.logic_hash)
        canonical = next((c for c in copies if c.name == g.canonical_source and c.content_hash == (v.content_hash if v else None)), None)
        return render(
            request,
            "rule.html",
            "search",
            g=g,
            v=v,
            copies=copies,
            revs=revs,
            key=key,
            family=family,
            validation=validation,
            setters=setters,
            needed_by=needed_by,
            similar=similar[:5],
            profile_status=profile_status,
            summary=summary,
            meta=meta,
            cves=cves,
            refs=refs,
            alloc=alloc,
            rlic=lic,
            srcs=srcs,
            remap=remap,
            canonical=canonical,
            engines=engine_names(),
        )

    def sources_numbers(s: Session) -> tuple[Any, ...]:
        """Per-source counts and last sync results of the Sources page, cached until the index, the sources or a
        sync log change (the counts scan every rule and occurrence)."""
        key = (overview_key(s), s.scalar(select(func.max(SyncLog.id))), s.scalar(select(func.max(Source.id))))
        if cache.get("sources_key") == key:
            return cache["sources"]
        rows = s.execute(
            select(Source, func.count(Occurrence.id))
            .outerjoin(Occurrence, (Occurrence.source_id == Source.id) & Occurrence.present.is_(True))
            .group_by(Source.id)
            .order_by(Source.priority, Source.name)
        ).all()
        canon = dict(s.execute(select(LogicGroup.canonical_source, func.count()).group_by(LogicGroup.canonical_source)).all())
        dial: dict[str, dict[str, int]] = {}
        for src_name, d, n in s.execute(
            text(
                "SELECT g.canonical_source, substr(j.value, 9), count(*) FROM logic_groups g, json_each(g.flags) j "
                "WHERE j.value LIKE 'dialect:%' GROUP BY 1, 2"
            )
        ):
            dial.setdefault(src_name, {})[d] = n
        last = {}
        for src_id, st_, err, at in s.execute(
            select(SyncLog.source_id, SyncLog.status, SyncLog.error, SyncLog.started_at).order_by(SyncLog.id)
        ):
            last[src_id] = (st_, err, at)
        for src, _ in rows:
            s.expunge(src)  # detached with every column loaded: safe to share between requests
        result = (rows, canon, dial, last)
        cache["sources_key"], cache["sources"] = key, result
        return result

    @app.get("/sources", response_class=HTMLResponse)
    def sources_page(request: Request, health: str = "") -> HTMLResponse:
        if health not in ("", "ok", "failing"):
            raise HTTPException(400, "health must be ok or failing")
        configs = {c.name: c for c in load_sources(ws)}
        with sessions() as s:
            rows, canon, dial, last = sources_numbers(s)
        known = {src.name for src, _ in rows}
        pending = [c for c in configs.values() if c.name not in known]
        missing = {name: c.auth for name, c in configs.items() if c.auth and not os.environ.get(c.auth)}

        def failed(src: Source) -> bool:
            return bool(src.enabled and src.id in last and last[src.id][0] not in ("ok", "running"))

        n_ok = sum(1 for src, _ in rows if src.enabled and last.get(src.id, ("",))[0] == "ok")
        n_fail = sum(1 for src, _ in rows if failed(src))
        n_all = len(rows)
        n_disabled = sum(1 for src, _ in rows if not src.enabled)
        if health:
            rows = [(src, n) for src, n in rows if failed(src) == (health == "failing")]
            pending = []
        return render(
            request,
            "sources.html",
            "sources",
            rows=rows,
            canon=canon,
            last=last,
            configs=configs,
            dial=dial,
            pending=pending,
            missing=missing,
            n_ok=n_ok,
            n_fail=n_fail,
            n_all=n_all,
            n_disabled=n_disabled,
            health=health,
        )

    @app.get("/sources/{name}", response_class=HTMLResponse)
    def source_page(request: Request, name: str) -> HTMLResponse:
        configs = {c.name: c for c in load_sources(ws)}
        with sessions() as s:
            src = s.scalar(select(Source).where(Source.name == name))
            if src is None:
                raise HTTPException(404, f"no source {name!r} in the index")
            n_rules = (
                s.scalar(select(func.count()).select_from(Occurrence).where(Occurrence.source_id == src.id, Occurrence.present.is_(True)))
                or 0
            )
            unique = s.scalar(select(func.count()).select_from(LogicGroup).where(LogicGroup.canonical_source == name)) or 0
            only_here = (
                s.scalar(
                    text(
                        "SELECT count(*) FROM logic_groups WHERE json_array_length(sources) = 1 AND json_extract(sources, '$[0]') = :n"
                    ).bindparams(n=name)
                )
                or 0
            )
            quarantine = s.execute(
                select(Quarantine.path, Quarantine.line_no, Quarantine.error, Quarantine.raw)
                .where(Quarantine.source_id == src.id, Quarantine.present.is_(True))
                .limit(50)
            ).all()
            n_quar = (
                s.scalar(select(func.count()).select_from(Quarantine).where(Quarantine.source_id == src.id, Quarantine.present.is_(True)))
                or 0
            )
            overlap = s.execute(
                text(
                    "SELECT j.value, count(*) FROM logic_groups g, json_each(g.sources) j WHERE EXISTS "
                    "(SELECT 1 FROM json_each(g.sources) k WHERE k.value = :n) AND j.value != :n GROUP BY j.value ORDER BY 2 DESC LIMIT 10"
                ).bindparams(n=name)
            ).all()
            engines = []
            for e in engine_names():
                ok = s.scalar(
                    text(
                        "SELECT count(*) FROM logic_groups g WHERE g.canonical_source = :n "
                        "AND EXISTS (SELECT 1 FROM json_each(g.loads_in) j WHERE j.value = :e)"
                    ).bindparams(n=name, e=e)
                )
                bad = s.scalar(
                    text(
                        "SELECT count(*) FROM logic_groups g WHERE g.canonical_source = :n "
                        "AND EXISTS (SELECT 1 FROM json_each(g.fails_in) j WHERE j.value = :e)"
                    ).bindparams(n=name, e=e)
                )
                engines.append((e, ok or 0, bad or 0))
            log = list(s.scalars(select(SyncLog).where(SyncLog.source_id == src.id).order_by(SyncLog.id.desc()).limit(15)))
        return render(
            request,
            "source.html",
            "sources",
            src=src,
            cfg=configs.get(name),
            n_rules=n_rules,
            unique=unique,
            only_here=only_here,
            quarantine=quarantine,
            n_quar=n_quar,
            overlap=overlap,
            engines=engines,
            log=log,
            missing=(
                configs.get(name).auth if configs.get(name) and configs[name].auth and not os.environ.get(configs[name].auth) else None
            ),
        )

    def builds_ctx(s: Session, t: Profile | None, old: str, new: str, tab: str, page: int) -> dict[str, Any]:
        from suriharvest.profiles import diff_builds, get_build

        ctx: dict[str, Any] = {"t": t, "tab": tab, "page": page}
        if t is None:
            return ctx
        builds = list(s.scalars(select(ProfileBuild).where(ProfileBuild.profile_id == t.id).order_by(ProfileBuild.id.desc()).limit(20)))
        b_new = get_build(s, t, new)
        b_old = (
            get_build(s, t, old)
            if old != "previous"
            else (s.get(ProfileBuild, b_new.summary.get("previous_build")) if b_new and b_new.summary.get("previous_build") else None)
        )
        # A diff of two finished builds never changes: computed once per pair (reading two manifests of tens of
        # thousands of rules costs most of a second), the last few pairs kept.
        dkey = (b_old.id if b_old else None, b_new.id if b_new else None, b_new.path if b_new else None)
        if dkey in diff_cache:
            ctx.update(builds=builds, new=b_new, old=b_old, d=diff_cache[dkey])
            return review_ctx(s, t, ctx, tab, page)
        d = diff_builds(b_old, b_new) if b_new else None
        if d is not None and b_old is None and b_new is not None:
            from suriharvest.profiles import _manifest

            man = _manifest(Path(b_new.path))
            d.added = sorted(
                (
                    {
                        "logic_hash": h,
                        "sid": m.get("sid"),
                        "exported_sid": m.get("exported_sid"),
                        "msg": m.get("msg"),
                        "source": m.get("source"),
                    }
                    for h, m in man.items()
                ),
                key=lambda x: x["sid"] or 0,
            )
        ctx.update(builds=builds, new=b_new, old=b_old, d=d)
        if b_new is not None:
            while len(diff_cache) >= 4:
                diff_cache.pop(next(iter(diff_cache)))
            diff_cache[dkey] = d
        return review_ctx(s, t, ctx, tab, page)

    def review_ctx(s: Session, t: Profile, ctx: dict[str, Any], tab: str, page: int) -> dict[str, Any]:
        from suriharvest.profiles import last_build, new_since_last_build

        if tab == "review":
            rows = sorted(new_since_last_build(s, t), key=lambda g: (-g.score, g.sid)) if last_build(s, t) else []
            ctx["review"] = rows[(page - 1) * 200 : page * 200]
            ctx["review_total"] = len(rows)
        return ctx

    diff_cache: dict[tuple[Any, ...], Any] = {}

    @app.get("/builds", response_class=HTMLResponse)
    def builds_page(
        request: Request, profile: str = "", old: str = "previous", new: str = "latest", tab: str = "added", page: int = 1
    ) -> HTMLResponse:
        tab = tab if tab in ("review", "added", "removed", "changed") else "added"
        with sessions() as s:
            profiles = list(s.scalars(select(Profile).order_by(Profile.id)))
            t = next((p for p in profiles if p.name == profile), profiles[0] if profiles else None)
            if profile and (t is None or t.name != profile):
                raise HTTPException(404, f"no profile {profile!r}")
            ctx = builds_ctx(s, t, old, new, tab, max(1, page))
            runs = list(s.scalars(select(UpdateRun).order_by(UpdateRun.id.desc()).limit(30)))
        return render(request, "builds.html", "builds", profiles=profiles, runs=runs, **ctx)

    @app.get("/runs/{run_id}", response_class=HTMLResponse)
    def run_page(request: Request, run_id: int) -> HTMLResponse:
        with sessions() as s:
            run = s.get(UpdateRun, run_id)
            if run is None:
                raise HTTPException(404, "no such run")
        return render(request, "run.html", "builds", run=run)

    @app.get("/profiles/{name}/diff", response_class=HTMLResponse)
    def profile_diff(request: Request, name: str, old: str = "previous", new: str = "latest", tab: str = "added") -> HTMLResponse:
        from suriharvest.profiles import get_build

        with sessions() as s:
            t = _tgt(s, name)
            a, b = get_build(s, t, old), get_build(s, t, new)
            if a is None or b is None:
                raise HTTPException(404, "two builds are needed for a diff")
            profiles = list(s.scalars(select(Profile).order_by(Profile.id)))
            ctx = builds_ctx(s, t, old, new, tab if tab in ("added", "removed", "changed") else "added", 1)
            runs = list(s.scalars(select(UpdateRun).order_by(UpdateRun.id.desc()).limit(30)))
        return render(request, "builds.html", "builds", profiles=profiles, runs=runs, **ctx)

    @app.get("/profiles/{name}/new", response_class=HTMLResponse)
    def profile_new(request: Request, name: str, page: int = 1) -> HTMLResponse:
        with sessions() as s:
            t = _tgt(s, name)
            profiles = list(s.scalars(select(Profile).order_by(Profile.id)))
            ctx = builds_ctx(s, t, "previous", "latest", "review", max(1, page))
            runs = list(s.scalars(select(UpdateRun).order_by(UpdateRun.id.desc()).limit(30)))
        return render(request, "builds.html", "builds", profiles=profiles, runs=runs, **ctx)

    @app.get("/profiles", response_class=HTMLResponse)
    def profiles_page(request: Request) -> HTMLResponse:
        with sessions() as s:
            cards = profile_cards(s, request)
        return render(request, "profiles.html", "profiles", cards=cards, hint_engine=(engine_names() or [None])[-1])

    @app.get("/jobs", response_class=HTMLResponse)
    def jobs_page(request: Request) -> HTMLResponse:
        from suriharvest.db import current_revision

        with sessions() as s:
            indexed = get_meta(s, "indexed_at")
            versions = {}
            for e in engine_names():
                versions[e] = s.scalar(select(ValidationResult.engine_version).where(ValidationResult.engine == e).limit(1))
        return render(
            request,
            "jobs.html",
            "jobs",
            schema=current_revision(ws.db_path),
            head=head_revision(),
            engines=ws.settings().engines,
            versions=versions,
            indexed=indexed,
            current=jobs.current(),
            recent=jobs.recent(20),
        )

    @app.get("/about", response_class=HTMLResponse)
    def about_page(request: Request) -> HTMLResponse:
        with sessions() as s:
            srcs = list(s.scalars(select(Source).order_by(Source.priority, Source.name)))
        return render(
            request,
            "about.html",
            "about",
            home=ui.display_path(ws.root),
            srcs=srcs,
            engines=ws.settings().engines,
            remap_base=ws.settings().remap_base,
        )

    # old addresses
    def _redirect_to(dest: str):  # type: ignore[no-untyped-def]
        def handler() -> RedirectResponse:
            return RedirectResponse(dest, status_code=303)

        return handler

    for old_path, new_path in (("/workflow", "/"), ("/runs", "/builds#runs"), ("/help", "/about"), ("/doctor", "/jobs")):
        app.add_api_route(old_path, _redirect_to(new_path), methods=["GET"])

    # -----------------------------------------------------------------------------------------------------------
    # profiles: named rulesets

    def _tgt(s: Session, name: str):  # type: ignore[no-untyped-def]
        from suriharvest.profiles import ProfileError, get

        try:
            return get(s, name)
        except ProfileError as e:
            raise HTTPException(404, str(e)) from e

    @app.get("/profiles/{name}")
    def profile_page(name: str) -> RedirectResponse:
        return RedirectResponse(f"/profiles/{name}/exclusions", status_code=303)

    @app.get("/profiles/{name}/exclusions", response_class=HTMLResponse)
    def exclusions_page(request: Request, name: str, q: str = "", page: int = 1, msg: str = "") -> HTMLResponse:
        """Exclusions of a profile: add by name, or search the profile's rules and tick what to exclude."""
        from suriharvest.profiles import LIGHT, Matcher, exclusion_file, exclusions, last_build, load_files
        from suriharvest.search import QueryError

        try:
            with workspace_lock(ws.data, "web: read exclusions", wait=0), sessions() as s:
                load_files(s, ws)
        except LockBusy:
            pass
        page = max(1, min(page, 1_000_000))
        rows, total, error, state = [], 0, None, {}
        with sessions() as s:
            t = _tgt(s, name)
            exs = exclusions(s, t)
            b = last_build(s, t)
            if q.strip():
                from suriharvest.search import build as build_query
                from suriharvest.search import parse_query

                try:
                    stmt = build_query(parse_query(f"{t.query} {q}"), families=False, include_junk=False, include_dropped=True)
                    if not (t.options or {}).get("include_disabled"):
                        stmt = stmt.where(LogicGroup.enabled_anywhere.is_(True))
                    total = s.scalar(select(func.count()).select_from(stmt.subquery())) or 0
                    rows = list(
                        s.execute(
                            stmt.with_only_columns(*LIGHT)
                            .order_by(LogicGroup.score.desc(), LogicGroup.sid)
                            .limit(200)
                            .offset((page - 1) * 200)
                        )
                    )
                    m = Matcher.build(s, exs)
                    for r in rows:
                        ex = m.match(r)
                        if ex is not None:
                            state[r.logic_hash] = f"excluded by {ex.kind}: {ex.value}"
                except QueryError as e:
                    error = str(e)
        from suriharvest.overrides import describe
        from suriharvest.overrides import entries as override_entries

        hits = ((b.summary or {}).get("overrides_hits") or {}) if b else {}
        overrides = [
            {
                "entry": f"{sec} #{i}",
                "kind": e["kind"],
                "value": e["value"],
                "does": describe(sec, e),
                "hits": hits.get(f"{sec} #{i}", "-"),
                "reason": e.get("reason") or "",
            }
            for sec, lst in override_entries(t).items()
            for i, e in enumerate(lst, 1)
        ]
        return render(
            request,
            "exclusions.html",
            "profiles",
            t=t,
            b=b,
            exclusions=exs,
            q=q,
            rows=rows,
            total=total,
            page=page,
            error=error,
            state=state,
            msg=msg,
            efile=exclusion_file(ws, t).relative_to(ws.root),
            overrides=overrides,
        )

    @app.post("/profiles/{name}/exclusions/by-name")
    def exclude_by_name(
        request: Request,
        name: str,
        value: str = Form(...),
        kind: str = Form("msg_contains"),
        reason: str = Form(""),
        scope: str = Form("profile"),
        token: str = Form(None),
    ) -> RedirectResponse:
        from suriharvest.profiles import ProfileError, add_exclusion, load_files, save_files

        check_csrf(token)
        try:
            with workspace_lock(ws.data, "web: exclusion", wait=5), sessions() as s:
                load_files(s, ws)
                t = _tgt(s, name)
                _, n = add_exclusion(s, None if scope == "all" else t, kind, value.strip(), reason.strip() or None, author="web")
                save_files(s, ws)
        except LockBusy as e:
            raise HTTPException(503, str(e)) from e
        except ProfileError as e:
            raise HTTPException(400, str(e)) from e
        return RedirectResponse(
            f"/profiles/{name}/exclusions?"
            + urlencode({"msg": f"added: {kind} {value.strip()!r} matches {n} rules (applies at the next build)"}),
            status_code=303,
        )

    @app.post("/profiles/{name}/exclusions/selected")
    def exclude_selected(
        request: Request,
        name: str,
        keys: list[str] = Form([]),
        reason: str = Form(""),
        q: str = Form(""),
        whole: str = Form(""),
        token: str = Form(None),
    ) -> RedirectResponse:
        """Tick-and-exclude from a search, or exclude the whole search as a standing query exclusion."""
        from suriharvest.profiles import ProfileError, add_exclusion, load_files, save_files

        check_csrf(token)
        try:
            with workspace_lock(ws.data, "web: exclusion", wait=5), sessions() as s:
                load_files(s, ws)
                t = _tgt(s, name)
                if whole and q.strip():
                    _, n = add_exclusion(s, t, "query", q.strip(), reason.strip() or "excluded search", author="web")
                    note = f"every rule matching {q.strip()!r} is excluded ({n} now, future ones too)"
                else:
                    for k in keys[:5000]:
                        add_exclusion(s, t, "rule_key", k, reason.strip() or "picked in search", author="web")
                    note = f"{len(keys[:5000])} rules excluded"
                save_files(s, ws)
        except LockBusy as e:
            raise HTTPException(503, str(e)) from e
        except ProfileError as e:
            raise HTTPException(400, str(e)) from e
        return RedirectResponse(
            f"/profiles/{name}/exclusions?" + urlencode({"q": q, "msg": note + " (applies at the next build)"}), status_code=303
        )

    @app.post("/profiles/{name}/exclusions")
    def profile_exclude(
        request: Request,
        name: str,
        kind: str = Form(...),
        value: str = Form(...),
        reason: str = Form(""),
        scope: str = Form("profile"),
        token: str = Form(None),
    ) -> RedirectResponse:
        from suriharvest.profiles import ProfileError, add_exclusion, load_files, save_files

        check_csrf(token)
        try:
            with workspace_lock(ws.data, "web: exclusion", wait=5), sessions() as s:
                load_files(s, ws)  # apply hand edits of the file before writing it
                t = _tgt(s, name)
                add_exclusion(s, None if scope == "all" else t, kind, value, reason.strip() or None, author="web")
                save_files(s, ws)
        except LockBusy as e:
            raise HTTPException(503, str(e)) from e
        except ProfileError as e:
            raise HTTPException(400, str(e)) from e
        return back(request, f"/profiles/{name}/exclusions")

    @app.post("/profiles/{name}/exclude-selected")
    def profile_exclude_selected(
        request: Request, name: str, keys: list[str] = Form([]), h: list[str] = Form([]), reason: str = Form(""), token: str = Form(None)
    ) -> RedirectResponse:
        """Exclude ticked rules: rule keys (keys=), or logic hashes from the search selection (h=)."""
        from suriharvest.profiles import ProfileError, add_exclusion, load_files, save_files

        check_csrf(token)
        try:
            with workspace_lock(ws.data, "web: exclusion", wait=5), sessions() as s:
                load_files(s, ws)  # apply hand edits of the file before writing it
                t = _tgt(s, name)
                if h:
                    keys = keys + list(s.scalars(select(LogicGroup.rule_key).where(in_list(LogicGroup.logic_hash, h))))
                for k in dict.fromkeys(keys[:2000]):
                    add_exclusion(s, t, "rule_key", k, reason.strip() or "picked in review", author="web")
                save_files(s, ws)
        except LockBusy as e:
            raise HTTPException(503, str(e)) from e
        except ProfileError as e:
            raise HTTPException(400, str(e)) from e
        if h:
            return RedirectResponse(
                f"/profiles/{name}/exclusions?"
                + urlencode({"msg": f"{len(set(keys))} rules excluded from {name} (applies at the next build)"}),
                status_code=303,
            )
        return back(request, f"/profiles/{name}/exclusions")

    @app.post("/profiles/{name}/exclusions/{ex_id}/delete")
    def profile_unexclude(request: Request, name: str, ex_id: int, token: str = Form(None)) -> RedirectResponse:
        from suriharvest.profiles import ProfileError, load_files, remove_exclusion, save_files

        check_csrf(token)
        try:
            with workspace_lock(ws.data, "web: exclusion", wait=5), sessions() as s:
                load_files(s, ws)  # apply hand edits of the file before writing it
                remove_exclusion(s, ex_id)
                save_files(s, ws)
        except LockBusy as e:
            raise HTTPException(503, str(e)) from e
        except ProfileError as e:
            raise HTTPException(404, str(e)) from e
        return back(request, f"/profiles/{name}/exclusions")

    @app.post("/profiles/{name}/build")
    def profile_build(request: Request, name: str, token: str = Form(None)) -> RedirectResponse:
        check_csrf(token)
        with sessions() as s:
            _tgt(s, name)

        def work(job):  # type: ignore[no-untyped-def]
            from suriharvest.pipeline import apply_source_settings
            from suriharvest.profiles import load_files, make_build

            with workspace_lock(ws.data, "web: profile build", wait=0), db_sessions() as s:
                apply_source_settings(s, ws, job.say)
                fs = load_files(s, ws)
                if fs.added or fs.removed:
                    job.say(f"exclusion file edited by hand: +{fs.added} -{fs.removed} applied")
                b = make_build(s, ws, _tgt(s, name))
                job.say(
                    f"build {name} #{b.id}: {b.rules:,} rules, {b.excluded:,} excluded; "
                    + (
                        f"+{b.summary['added']} -{b.summary['removed']} ~{b.summary.get('changed', 0)} since the previous build"
                        if b.summary.get("previous_build")
                        else f"first build of profile {name}"
                    )
                )
                job.result = {"build": b.id}

        return _start("build", f"Build {name}", work, f"/builds?profile={name}")

    def _start(kind: str, title: str, fn, link: str) -> RedirectResponse:  # type: ignore[no-untyped-def]
        try:
            job = jobs.start(kind, title, fn, link)
        except Busy as e:
            raise HTTPException(409, f"{e}: wait for it to finish") from e
        return RedirectResponse(f"/jobs/{job.id}", status_code=303)

    @app.post("/jobs/update")
    def job_update(request: Request, token: str = Form(None)) -> RedirectResponse:
        """Download new rules from every enabled source, parse, validate, index, then rebuild auto-build profiles."""
        check_csrf(token)

        def work(job):  # type: ignore[no-untyped-def]
            from suriharvest.pipeline import update

            try:
                with workspace_lock(ws.data, "web: update", wait=0), db_sessions() as s:
                    res = update(s, ws, job.say)
                    job.result = {"run": res.run.id, "status": res.run.status}
                    for gt in res.run.gates:
                        job.say(f"gate {gt['status']}: {gt['name']}: {gt['detail']}")
            except LockBusy as e:
                job.status = "failed"
                job.say(f"workspace busy: {e}")
                return
            job.say("update finished: review the new rules, then export")

        return _start("update", "Download new rules", work, "/builds")

    @app.post("/jobs/source/{src_name}")
    def job_source(request: Request, src_name: str, token: str = Form(None)) -> RedirectResponse:
        """Download one source now, then validate, index and rebuild profiles."""
        check_csrf(token)
        cfg = next((c for c in load_sources(ws) if c.name == src_name), None)
        if cfg is None:
            raise HTTPException(404, f"no source {src_name}")

        def work(job):  # type: ignore[no-untyped-def]
            from suriharvest.pipeline import refresh_sources

            try:
                with workspace_lock(ws.data, f"web: download {src_name}", wait=0), db_sessions() as s:
                    out = refresh_sources(s, ws, [cfg], job.say)
            except LockBusy as e:
                job.status = "failed"
                job.say(f"workspace busy: {e}")
                return
            if out.failed:
                job.status = "failed"
                return
            job.say(f"{src_name} downloaded: review the new rules, then export")

        return _start("source", f"Download {src_name}", work, f"/sources/{src_name}")

    @app.get("/jobs/{job_id}", response_class=HTMLResponse)
    def job_page(request: Request, job_id: str) -> HTMLResponse:
        job = jobs.jobs.get(job_id)
        if job is None:
            raise HTTPException(404, "no such job (jobs are kept while the server runs)")
        return render(request, "job.html", JOB_SECTION.get(job.kind, "jobs"), job=job)

    @app.get("/api/jobs/{job_id}")
    def job_api(job_id: str) -> JSONResponse:
        job = jobs.jobs.get(job_id)
        if job is None:
            raise HTTPException(404, "no such job")
        return JSONResponse(job.as_dict())

    # -----------------------------------------------------------------------------------------------------------
    # read-only JSON API (docs/web.md "JSON API")

    @app.get("/api/search")
    def api_search(
        q: str = "",
        offset: int | None = Query(None, ge=0, le=100_000_000),
        limit: int | None = Query(None, ge=1, le=API_MAX_PER_PAGE),
        page: int = Query(1, ge=1, le=1_000_000),
        per_page: int = Query(PAGE, ge=1, le=API_MAX_PER_PAGE),
        all: int = 0,
        junk: int = 0,
    ) -> JSONResponse:
        """{"query", "total", "offset", "limit", "results"}, as `suriharvest search --json` (docs/conventions.md).
        `page`/`per_page` are still read when `offset`/`limit` are not given."""
        from suriharvest.search import QueryError, page_rows, row_dict

        limit = limit if limit is not None else per_page
        offset = offset if offset is not None else (page - 1) * limit

        with sessions() as s:
            try:
                stmt = query_stmt(s, q, every=bool(all), junk=bool(junk))
                total = s.scalar(select(func.count()).select_from(stmt.subquery())) or 0
                rows = page_rows(s, stmt, [LogicGroup.score.desc(), LogicGroup.id], limit, offset)
            except QueryError as e:
                raise HTTPException(400, str(e)) from None  # {"detail": ...}, as every /api/ error
            out = [row_dict(g) for g in rows]
            hints = ui.value_hints(s, q) if not total else []
        return JSONResponse(
            {
                "query": q,
                "total": total,
                "offset": offset,
                "limit": limit,
                "results": out,
            }
            | ({"warnings": hints} if hints else {})
        )

    @app.get("/api/stats")
    def api_stats() -> JSONResponse:
        from suriharvest.search import corpus_stats

        with sessions() as s:
            rep = corpus_stats(s)
        rep["version"] = __version__
        return JSONResponse(rep)

    # -----------------------------------------------------------------------------------------------------------
    # export

    def build_of(s: Session, name: str, build_id: int | None = None) -> tuple[Profile, ProfileBuild]:
        from suriharvest.profiles import last_build

        t = _tgt(s, name)
        b = s.get(ProfileBuild, build_id) if build_id else last_build(s, t)
        if b is None or b.profile_id != t.id:
            raise HTTPException(404, "no such build" if build_id else f"profile {name} has no build yet: build it on the Profiles page")
        return t, b

    def build_hashes(b: ProfileBuild) -> list[str]:
        from suriharvest.profiles import built_hashes

        return sorted(built_hashes(b))

    def failing_in(s: Session, engine: str | None) -> set[str]:
        if not engine:
            return set()
        return set(
            s.scalars(
                select(LogicGroup.logic_hash).where(
                    text("EXISTS (SELECT 1 FROM json_each(logic_groups.fails_in) j WHERE j.value = :e)").bindparams(e=engine)
                )
            )
        )

    def export_counts(s: Session, hashes: list[str], eng: str, srcs: dict[str, Source]) -> tuple[Any, ...]:
        """Counts shown on the export page: total, kept, failing, per engine, licence split, IOC kinds."""
        engs = engine_names()
        hs = set(hashes)
        per_engine = [(e, len(hs - failing_in(s, e))) for e in engs]
        bad = failing_in(s, eng) & hs
        keep = hs - bad
        # licence split of what would be downloaded
        lic: Counter[str] = Counter()
        names: dict[str, set[str]] = {}
        if keep:
            for src_name, msg_gpl, n in s.execute(
                text(
                    "SELECT canonical_source, msg LIKE 'GPL %', count(*) FROM logic_groups "
                    "WHERE logic_hash IN (SELECT value FROM json_each(:hs)) GROUP BY 1, 2"
                ).bindparams(hs=json.dumps(sorted(keep)))
            ):
                label, cls = ui.rule_licence(srcs.get(src_name), "GPL " if msg_gpl else "")
                lic[cls] += n
                names.setdefault(cls, set()).add(label)
        ioc = dict(
            s.execute(
                text(
                    "SELECT ioc_type, count(*) FROM logic_groups WHERE is_ioc AND logic_hash IN (SELECT value FROM json_each(:hs)) GROUP BY 1"
                ).bindparams(hs=json.dumps(sorted(keep)))
            ).all()
        )
        return len(hashes), len(keep), len(bad), per_engine, lic, {k: sorted(v) for k, v in names.items()}, ioc

    @app.get("/export", response_class=HTMLResponse)
    def export_page(
        request: Request,
        profile: str = "",
        q: str = "",
        h: list[str] = Query([]),
        engine: str = "",
        format: str = "rules",
        share: int = 0,
        remap: int = 1,
    ) -> HTMLResponse:
        from suriharvest.search import QueryError

        fmt = format if format in ("rules", "by-source", "update", "datasets") else "rules"
        with sessions() as s:
            profiles = list(s.scalars(select(Profile).order_by(Profile.id)))
            cards = profile_cards(s, request)
            srcs = sources_map(s)
            scope = "selected" if h else "search" if q else "profile"
            t = next((p for p in profiles if p.name == profile), profiles[0] if profiles else None)
            b = None
            hashes: list[str] = []
            error = None
            engs = engine_names()
            eng = engine if engine in engs else (t.engine if (scope == "profile" and t and t.engine in engs) else (engs[0] if engs else ""))
            # The page's counts depend on the index, the scope and the engine only: cached (the
            # export page re-read every matching rule on each request).
            if scope == "profile" and t is not None:
                from suriharvest.profiles import last_build

                b = last_build(s, t)
            ckey = (get_meta(s, "indexed_at"), scope, q, b.id if b else None, tuple(h[:5000]) if scope == "selected" else (), eng)
            with export_lock:
                hit = export_cache.get(ckey)
                if hit is not None:
                    export_cache.move_to_end(ckey)
            if hit is not None:
                total_n, keep_n, bad_n, per_engine, lic, names, ioc = hit
            elif scope == "profile" and t is not None:
                hashes = build_hashes(b) if b else []
            elif scope == "search":
                try:
                    hashes = list(s.scalars(query_stmt(s, q).with_only_columns(LogicGroup.logic_hash).limit(100_000)))
                except QueryError as e:
                    error = str(e)
            else:
                hashes = list(h[:5000])
            if hit is None:
                total_n, keep_n, bad_n, per_engine, lic, names, ioc = export_counts(s, hashes, eng, srcs)
                if error is None:
                    with export_lock:
                        export_cache[ckey] = (total_n, keep_n, bad_n, per_engine, lic, names, ioc)
                        while len(export_cache) > 32:
                            export_cache.popitem(last=False)
        size = None
        if b is not None and (Path(b.path) / "suricata.rules").is_file():
            size = (Path(b.path) / "suricata.rules").stat().st_size
        params: dict[str, Any] = {"engine": eng, "fmt": {"by-source": "zip", "datasets": "datasets"}.get(fmt, "rules")}
        if scope == "profile" and t is not None:
            params["profile"] = t.name
        elif scope == "search":
            params["q"] = q
        if share:
            params["share"] = 1
        if not remap:
            params["remap"] = 0
        dl = "/export/download?" + urlencode(params) + ("".join("&h=" + x for x in h[:200]) if scope == "selected" else "")
        cli = ["suriharvest", "export", "--out", "out/"]
        if scope == "profile" and t is not None:
            cli = ["suriharvest", "profile", "build", t.name]
        if scope != "profile":
            if remap:
                cli.append("--remap-colliding-sids")
            if share:
                cli.append("--redistributable-only")
            if fmt == "by-source":
                cli.append("--by-source")
            if fmt == "datasets":
                cli.append("--iocs-as-datasets")
        if scope == "search":
            # options first, then `--`: a query that starts with "-" stays the query when the line is pasted
            cli += ["--", shlex.quote(q)]
        return render(
            request,
            "export.html",
            "export",
            profiles=profiles,
            cards=cards,
            scope=scope,
            t=t,
            b=b,
            q=q,
            h=h[:200],
            n_selected=len(h),
            total=total_n,
            keep=keep_n,
            bad=bad_n,
            engine=eng,
            per_engine=per_engine,
            fmt=fmt,
            share=share,
            remap=remap,
            lic_counts=lic,
            lic_names=names,
            ioc=ioc,
            size=size,
            dl=dl,
            feed=feed_url(request, t.name, eng) if t else None,
            cli=" ".join(cli),
            error=error,
        )

    def streamed(dest: Path, tmp: Path, media: str, filename: str) -> Response:
        """Send a finished download. The build slot is released when this returns; the send counts in its own
        bound (exports.sending) until the body is sent, the client goes away, or it stalls."""
        try:
            exports.start_send()
            size = dest.stat().st_size
        except BaseException:
            rmtree(tmp, ignore_errors=True)
            raise
        return _TimedStream(
            _stream_then_remove(dest, tmp),
            done=exports.end_send,
            media_type=media,
            headers={"Content-Disposition": f'attachment; filename="{filename}"', "Content-Length": str(size)},
        )

    def isolated(fn: Any, *args: Any, prefix: str = "suriharvest-web-") -> tuple[Any, Path]:
        """Build a download in a child process (web/downloads.py) inside a fresh temp folder: (result, folder).
        The folder is removed here on failure, by the stream otherwise."""
        from suriharvest.export import SidCollision
        from suriharvest.web.downloads import run_isolated

        tmp = Path(tempfile.mkdtemp(prefix=prefix))
        try:
            return run_isolated(fn, *args, tmp=str(tmp)), tmp
        except SidCollision as e:
            rmtree(tmp, ignore_errors=True)
            raise HTTPException(409, str(e)) from e
        except BaseException:
            rmtree(tmp, ignore_errors=True)
            raise

    def _download(request: Request, profile: str, q: str, h: list[str], engine: str, fmt: str, share: int, remap: int) -> Response:
        with exports.slot(request):  # refused (429) before any database work when the queue is full
            return _build_download(profile, q, h, engine, fmt, share, remap)

    def _build_download(profile: str, q: str, h: list[str], engine: str, fmt: str, share: int, remap: int) -> Response:
        from suriharvest.search import QueryError
        from suriharvest.web.downloads import build_export, build_stripped

        fmt = fmt if fmt in ("rules", "zip", "datasets") else "rules"
        engs = engine_names()
        with sessions() as s:
            plain = None
            if profile:
                t, b = build_of(s, profile)
                hashes = build_hashes(b)
                eng = engine if engine in engs else (t.engine or "")
                bad = failing_in(s, eng) & set(hashes)
                label = f"{t.name}-{b.id}" + (f"-suricata-{ui.short_engine(eng)}" if eng else "")
                built = Path(b.path) / "suricata.rules"
                if fmt == "rules" and not bad and not share and remap and built.is_file():
                    plain = built
            elif h:
                hashes, eng = list(h[:5000]), engine if engine in engs else ""
                bad = failing_in(s, eng) & set(hashes)
                label = f"suriharvest-selection-{len(hashes)}"
            elif q:
                try:
                    hashes = list(s.scalars(query_stmt(s, q).with_only_columns(LogicGroup.logic_hash).limit(100_000)))
                except QueryError as e:
                    raise HTTPException(400, str(e)) from e
                eng = engine if engine in engs else ""
                bad = failing_in(s, eng) & set(hashes)
                label = "suriharvest-search"
            else:
                raise HTTPException(400, "nothing to export: give a profile, a search (q=) or rules (h=)")
            keep = [x for x in hashes if x not in bad]
            if not keep:
                raise HTTPException(400, "no rule to export")
        # The session is closed before the build: the child opens its own, so a download holds no pooled connection.
        if plain is not None:
            dest, tmp = isolated(build_stripped, str(plain), label)
            return streamed(Path(dest), tmp, "text/plain; charset=utf-8", f"{label}.rules")
        (dest, media), tmp = isolated(build_export, str(ws.root), keep, fmt, bool(share), bool(remap), label)
        return streamed(Path(dest), tmp, media, Path(dest).name)

    @app.get("/export/download")
    def export_download(
        request: Request,
        profile: str = "",
        q: str = "",
        h: list[str] = Query([]),
        engine: str = "",
        fmt: str = "rules",
        share: int = 0,
        remap: int = 1,
    ) -> Response:
        """A ruleset file: a profile's latest build, a search, or picked rules (h=, at most 200 in a GET)."""
        return _download(request, profile, q, h[:200], engine, fmt, share, remap)

    @app.post("/export/download")
    def export_download_post(
        request: Request,
        h: list[str] = Form([]),
        engine: str = Form(""),
        fmt: str = Form("rules"),
        share: int = Form(0),
        remap: int = Form(1),
        token: str = Form(None),
    ) -> Response:
        """The search selection bar posts the ticked rules (any number up to 5,000)."""
        check_csrf(token)
        if not h:
            raise HTTPException(400, "tick at least one rule")
        return _download(request, "", "", h, engine, fmt, share, remap)

    @app.get("/feed/{profile}/{fname}")
    def feed(request: Request, profile: str, fname: str) -> Response:
        """The profile's latest build as a suricata-update source: rules/suricata.rules, the dataset files its rules
        load (rules/datasets/<source>/..., where the rewritten relative paths point) and NOTICE.md in a tar.gz."""

        if not fname.endswith(".tar.gz"):
            raise HTTPException(404, "feeds are <engine>.tar.gz, e.g. suricata-8.tar.gz")
        want = fname[: -len(".tar.gz")]
        engs = engine_names()
        eng = next((e for e in engs if want in (e, f"suricata-{ui.short_engine(e)}", ui.short_engine(e))), None)
        if eng is None and want not in ("all", "any"):
            raise HTTPException(404, f"no engine {want!r}: use one of {', '.join('suricata-' + ui.short_engine(e) for e in engs) or 'all'}")
        with exports.slot(request):
            return _feed(profile, fname, eng)

    def _feed(profile: str, fname: str, eng: str | None) -> Response:
        from suriharvest.web.downloads import build_feed

        with sessions() as s:
            t, b = build_of(s, profile)
            hashes = build_hashes(b)
            bad = failing_in(s, eng) & set(hashes)
            plain = Path(b.path) / "suricata.rules"
            keep = None if (not bad and plain.is_file()) else [x for x in hashes if x not in bad]
            used = {r.get("source") for r in _read_manifest(Path(b.path))}
            notice = [
                "# Rule sources and licences\n",
                f"suriharvest build #{b.id} of profile {t.name}, {b.created_at:%Y-%m-%d %H:%M} UTC.\n\n",
            ]
            for src in s.scalars(select(Source).order_by(Source.priority, Source.name)):
                if src.name in used:
                    notice.append(
                        f"- {src.name}: {src.licence or 'no licence stated'} (redistribute: {src.redistribute}); {redact_url(src.url) or 'local source'}\n"
                    )
        epoch = int(b.created_at.timestamp())
        dest, tmp = isolated(build_feed, str(ws.root), b.path, keep, "".join(notice), epoch, "feed.tar.gz", prefix="suriharvest-feed-")
        return streamed(Path(dest), tmp, "application/gzip", f"{profile}-{fname}")

    @app.get("/profiles/{name}/builds/{build_id}/{fname}")
    def profile_file(name: str, build_id: int, fname: str) -> Response:
        from fastapi.responses import FileResponse

        if fname not in ("suricata.rules", "excluded.jsonl", "manifest.jsonl", "changes.json", "datasets.rules"):
            raise HTTPException(404, "no such file")
        with sessions() as s:
            t = _tgt(s, name)
            b = s.get(ProfileBuild, build_id)
            if b is None or b.profile_id != t.id:
                raise HTTPException(404, "no such build")
        path = Path(b.path) / fname
        if not path.is_file():
            raise HTTPException(404, "file not in this build")
        return FileResponse(path, filename=f"{name}-{build_id}-{fname}", media_type="text/plain")

    @app.get("/profiles/{name}/export/{build_id}")
    def build_sources(name: str, build_id: int) -> RedirectResponse:
        return RedirectResponse("/export?" + urlencode({"profile": name, "format": "by-source"}), status_code=303)

    @app.get("/profiles/{name}/export/{build_id}/download")
    def build_export(request: Request, name: str, build_id: int, sources: list[str] = Query([]), fmt: str = "rules") -> Response:
        """Rules of the chosen sources from a build: one file (fmt=rules) or a zip with a file per source."""
        with sessions() as s:
            _, b = build_of(s, name, build_id)
        known = set((b.summary.get("by_source") or {}).keys())
        chosen = [x for x in (sources or sorted(known)) if x in known]
        if not chosen:
            raise HTTPException(400, "choose at least one source")
        folder = Path(b.path) / "by-source"
        safe = "-".join(chosen)[:80]
        with exports.slot(request):
            return _build_files(name, build_id, chosen, folder, safe, fmt)

    def _build_files(name: str, build_id: int, chosen: list[str], folder: Path, safe: str, fmt: str) -> Response:
        """Files written by the build, put together on disk (zip) or streamed one after another (rules)."""
        from suriharvest.dataset_files import dataset_tree

        tmp = Path(tempfile.mkdtemp(prefix="suriharvest-web-"))
        try:
            if fmt == "zip":
                dest, media = tmp / f"{name}-{build_id}-{safe}.zip", "application/zip"
                with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
                    for x in chosen:
                        zf.write(folder / f"{x}.rules", f"{x}.rules")
                    for rel, f in dataset_tree(folder):
                        if rel.split("/")[1] in chosen:
                            zf.write(f, rel)
            else:
                dest, media = tmp / f"{name}-{build_id}-{safe}.rules", "text/plain; charset=utf-8"
                with dest.open("wb") as out:
                    out.write(f"# suriharvest build {build_id} of {name}, sources: {', '.join(chosen)}\n".encode())
                    for x in chosen:
                        with (folder / f"{x}.rules").open("rb") as f:
                            shutil.copyfileobj(f, out, 1 << 20)
        except BaseException:
            rmtree(tmp, ignore_errors=True)
            raise
        return streamed(dest, tmp, media, dest.name)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> Response:
        # an out-of-range or malformed parameter is a 400 with one readable sentence, as in sigharvest
        return await http_error(request, StarletteHTTPException(400, validation_message(exc.errors())))

    @app.exception_handler(OverflowError)
    async def number_out_of_range(request: Request, exc: OverflowError) -> Response:
        # a run or build id beyond SQLite's 64-bit integers (/runs/99999999999999999999) names nothing: a 404, not a 500
        return await http_error(request, StarletteHTTPException(404, "not found: that number is out of range"))

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> Response:
        # Unknown routes too (Starlette's own 404/405): an HTML page, JSON under /api/; the exception's headers
        # (Retry-After of a 429/503) are kept. The JSON is FastAPI's `{"detail": "..."}`, the same shape as
        # sigharvest's /api/ errors (docs/conventions.md).
        if request.url.path.startswith("/api/"):
            resp: Response = JSONResponse({"detail": str(exc.detail)}, status_code=exc.status_code)
        else:
            section = "search" if request.url.path.startswith("/rule/") else ""
            resp = render(request, "error.html", section, status_code=exc.status_code, status=exc.status_code, detail=exc.detail)
        resp.headers.update(getattr(exc, "headers", None) or {})
        return resp

    return app


def validation_message(errors: Any) -> str:
    """A short sentence for invalid form or query fields, without echoing input (the same text as sigharvest)."""
    parts: list[str] = []
    for error in errors:
        field = str(error.get("loc", ["", "value"])[-1]).replace("_", " ")
        kind = str(error.get("type", ""))
        context = error.get("ctx") or {}
        if kind == "missing" or (kind == "string_too_short" and context.get("min_length") == 1):
            text = f"{field} is required"
        elif kind == "string_too_long":
            text = f"{field} must be at most {context.get('max_length')} characters"
        elif kind == "string_too_short":
            text = f"{field} must be at least {context.get('min_length')} characters"
        elif kind in ("greater_than_equal", "less_than_equal", "greater_than", "less_than"):
            limit = next(iter(context.values()), "")
            text = f"{field} must be {kind.replace('_', ' ').replace('equal', 'or equal to')} {limit}"
        else:
            text = f"{field} is invalid"
        if text not in parts:
            parts.append(text)
    return ("Invalid request: " + "; ".join(parts[:5]) + ".") if parts else "Invalid request."


def _read_manifest(path: Path) -> list[dict[str, Any]]:
    f = path / "manifest.jsonl"
    if not f.exists():
        return []
    return [json.loads(x) for x in f.read_text(encoding="utf-8").splitlines() if x.strip()]


_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def _counts(s: Session, sub: Any, srcs: dict[str, Source]) -> tuple[int, int, dict[str, Any]]:
    """The total, the rule lines and the facet counts of a result set, in ONE statement.

    The filtered rows are read once into a materialised CTE (its narrow columns only); each facet groups that CTE,
    and the list facets (loads, fails, source, flags) count the matching logic_group_values rows instead of parsing
    every row's JSON. Ties in a facet are ordered by value."""
    m = (
        select(
            sub.c.id,
            sub.c.severity,
            sub.c.app_layer,
            sub.c.ioc_type,
            sub.c.classtype,
            sub.c.canonical_source,
            sub.c.msg.like("GPL %").label("gpl"),
            sub.c.enabled_anywhere,
            sub.c.copies,
        )
        .cte("m")
        .prefix_with("MATERIALIZED")
    )
    n = func.count()

    def part(name: str, k: Any, n_: Any, *, k2: Any = None, src: Any = m, group: tuple[Any, ...] = (), limit: int | None = None) -> Any:
        q = select(
            literal(name).label("f"),
            (k if k is not None else null()).label("k"),
            (k2 if k2 is not None else null()).label("k2"),
            n_.label("n"),
        )
        q = q.select_from(src)
        if group:
            q = q.group_by(*group)
        if limit:
            q = q.order_by(n.desc(), *group).limit(limit)
        return select(q.subquery())

    def listed(kind: str, limit: int) -> Any:
        # `group_id IN (SELECT id FROM m)`, not a join: SQLite then walks m and reads each group's values by primary
        # key; a join may be planned the other way round (every value of the kind, probing m), which is far slower.
        v = LogicGroupValue
        vals = select(v.value).where(v.kind == kind, v.group_id.in_(select(m.c.id))).subquery()
        return part(kind, vals.c.value, n, src=vals, group=(vals.c.value,), limit=limit)

    parts = [
        part("total", None, n, k2=func.coalesce(func.sum(m.c.copies), 0)),
        part("disabled", None, func.coalesce(func.sum(case((m.c.enabled_anywhere.is_(False), 1), else_=0)), 0)),
        part("severity", m.c.severity, n, group=(m.c.severity,)),
        listed("loads_in", 40),
        listed("fails_in", 40),
        part("app", m.c.app_layer, n, group=(m.c.app_layer,), limit=20),
        part("kind", m.c.ioc_type, n, group=(m.c.ioc_type,), limit=12),
        part("classtype", m.c.classtype, n, group=(m.c.classtype,), limit=30),
        listed("sources", 60),
        listed("flags", 60),
        part("licence", m.c.canonical_source, n, k2=m.c.gpl, group=(m.c.canonical_source, m.c.gpl)),
    ]
    got: dict[str, list[tuple[Any, Any, int]]] = {}
    for f, k, k2, cnt in s.execute(union_all(*parts)):
        got.setdefault(f, []).append((k, k2, cnt))
    (_, lines, total) = got["total"][0]
    if not total:
        return 0, 0, {}
    pairs = {
        f: [(k, c) for k, _, c in got.get(f, [])]
        for f in ("severity", "loads_in", "fails_in", "app", "kind", "classtype", "sources", "flags")
    }
    out: dict[str, Any] = {}
    # severity is grouped as stored and folded here as SQLite's lower() would (ASCII only): lower() in the query
    # allocates per row, and SQLite's allocator lock is shared by every search running in the server.
    sev: Counter[str | None] = Counter()
    for k, c in pairs["severity"]:
        sev[k.translate(_ASCII_LOWER) if k is not None else None] += c
    rank = {"critical": 0, "major": 1, "minor": 2, "informational": 3}
    by_count = sorted(sev.items(), key=lambda kv: (-kv[1], kv[0] is not None, kv[0] or ""))[:12]
    out["severity"] = sorted(by_count, key=lambda kv: rank.get(kv[0] or "", 4))
    out["loads"] = pairs["loads_in"]
    out["fails"] = pairs["fails_in"]
    out["app"] = pairs["app"]
    out["kind"] = pairs["kind"]
    out["classtype"] = pairs["classtype"]
    out["source"] = pairs["sources"]
    out["flags"] = dict(pairs["flags"])
    out["disabled"] = got["disabled"][0][2]
    lic: Counter[str] = Counter()
    for name, gpl, c in got.get("licence", []):
        lic[ui.rule_licence(srcs.get(name), "GPL " if gpl else "")[1]] += c
    out["licence"] = lic.most_common()
    return total, lines or 0, out


def _authorised(request: Request, token: str) -> bool:
    header = request.headers.get("authorization") or ""
    if header.lower().startswith("basic "):
        try:
            _, _, password = base64.b64decode(header[6:]).decode().partition(":")
        except (ValueError, UnicodeDecodeError):
            return False
        return hmac.compare_digest(password.encode(), token.encode())
    if header.lower().startswith("bearer "):
        return hmac.compare_digest(header[7:].encode("utf-8", "surrogateescape"), token.encode())
    return False


def _same_origin_get(request: Request) -> bool:
    """False when the browser says another site (or another port of this host) asked for this GET. Clients that
    send neither header (suricata-update, curl) are allowed."""
    site = request.headers.get("sec-fetch-site")
    if site is not None and site not in ("same-origin", "none"):
        return False
    origin = request.headers.get("origin")
    return origin is None or urlsplit(origin).netloc == request.headers.get("host")


def _error_response(e: Exception) -> Response:
    """An exception that escaped a route, answered as a normal response (the raw 500 reset the
    keep-alive connection, so the client's next request failed too)."""
    from sqlalchemy.exc import OperationalError
    from sqlalchemy.exc import TimeoutError as PoolTimeout

    if isinstance(e, PoolTimeout):
        return PlainTextResponse("server busy, try again shortly", status_code=503, headers={"Retry-After": "5"})
    if isinstance(e, OperationalError) and ("fts5" in str(e) or "unterminated string" in str(e)):
        return PlainTextResponse("the search text could not be read; remove quotes or special characters", status_code=400)
    log.exception("unhandled error", exc_info=e)
    return PlainTextResponse("internal error (details in the server log)", status_code=500)


class _FileChunks:
    """Chunks of a finished download; `tmp` (its folder) is removed however the response ends. On POSIX the open
    file stays readable after the folder is deleted, so the folder goes at once. Windows cannot delete an open file:
    there the folder goes in close(), which the response calls when it ends, also when the client went away before
    the first chunk (a generator that never started would not run its `finally`). close() is idempotent."""

    def __init__(self, path: Path, tmp: Path) -> None:
        self._f = path.open("rb")
        self._tmp = tmp
        self._early = os.name != "nt"
        if self._early:
            rmtree(tmp, ignore_errors=True)

    def __iter__(self) -> _FileChunks:
        return self

    def __next__(self) -> bytes:
        chunk = b"" if self._f.closed else self._f.read(1 << 20)
        if not chunk:
            self.close()
            raise StopIteration
        return chunk

    def close(self) -> None:
        self._f.close()
        if not self._early:
            rmtree(self._tmp, ignore_errors=True)


def _stream_then_remove(path: Path, tmp: Path) -> _FileChunks:
    return _FileChunks(path, tmp)


def sweep_stale_downloads(max_age: float = 3600.0) -> int:
    """Remove download folders (suriharvest-web-*, suriharvest-feed-*) older than `max_age` seconds left in the
    temp folder by a server that was killed mid-download. Run when the app starts."""
    import stat
    import time

    now, n = time.time(), 0
    uid = os.getuid() if hasattr(os, "getuid") else None
    for p in Path(tempfile.gettempdir()).glob("suriharvest-*"):
        try:
            # The temp folder is shared: never follow a link someone planted, and only remove our own folders.
            st = os.lstat(p)
            if not stat.S_ISDIR(st.st_mode) or not p.name.startswith(("suriharvest-web-", "suriharvest-feed-")):
                continue
            if (uid is not None and st.st_uid != uid) or now - st.st_mtime <= max_age:
                continue
            rmtree(p, ignore_errors=True)
            n += 1
        except OSError:
            continue
    return n


class _TimedStream(StreamingResponse):
    """A streamed download whose every send must finish within SEND_IDLE_SECONDS (a client that stops reading is
    disconnected instead of keeping the open temp file forever); `done` runs and the chunks are closed (the file
    closed, its folder removed) however the response ends, even if it never started."""

    def __init__(self, chunks: Iterator[bytes], *, done: Any, **kw: Any) -> None:
        super().__init__(chunks, **kw)
        self._chunks, self._done = chunks, done

    async def stream_response(self, send: Any) -> None:
        import anyio

        async def timed(message: Any) -> None:
            with anyio.fail_after(SEND_IDLE_SECONDS):
                await send(message)

        await super().stream_response(timed)

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        try:
            await super().__call__(scope, receive, send)
        finally:
            close = getattr(self._chunks, "close", None)
            if close is not None:
                with contextlib.suppress(ValueError, OSError):  # a generator still running in a worker thread
                    close()
            self._done()


class ExportQueue:
    """Ruleset downloads built on request: `running` at a time, `waiting` more wait for a slot,
    beyond that 429 with Retry-After at once. Bounds CPU and memory however many clients ask."""

    def __init__(
        self,
        running: int = EXPORT_RUNNING,
        waiting: int = EXPORT_WAITING,
        wait_seconds: float = EXPORT_WAIT_SECONDS,
        sending: int = EXPORT_SENDING,
    ):
        self._slots = threading.BoundedSemaphore(running)
        self._lock = threading.Lock()
        self._admitted = 0
        self._max = running + waiting
        self._wait = wait_seconds
        self.sending = 0
        self._max_sending = sending

    def _sending_full(self) -> HTTPException:
        return HTTPException(429, "other downloads are being sent; try again shortly", headers={"Retry-After": "15"})

    def start_send(self) -> None:
        with self._lock:
            if self.sending >= self._max_sending:
                raise self._sending_full()
            self.sending += 1

    def end_send(self) -> None:
        with self._lock:
            self.sending -= 1

    @contextmanager
    def slot(self, request: Request) -> Iterator[None]:
        """Every route that builds a download takes a slot, so the cross-site check lives here too: it cannot be
        missed by a route the EXPENSIVE_GET prefixes do not cover."""
        if not _same_origin_get(request):
            raise HTTPException(403, "cross-site request refused")
        with self._lock:
            if self.sending >= self._max_sending:  # refused before the build: its file could not be sent
                raise self._sending_full()
            if self._admitted >= self._max:
                raise HTTPException(429, "other downloads are being built; try again shortly", headers={"Retry-After": "15"})
            self._admitted += 1
        try:
            if not self._slots.acquire(timeout=self._wait):
                raise HTTPException(503, "the download queue did not move; try again later", headers={"Retry-After": "30"})
            try:
                yield
            finally:
                self._slots.release()
        finally:
            with self._lock:
                self._admitted -= 1
