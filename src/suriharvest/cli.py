"""Command line interface."""

from __future__ import annotations

import contextlib
import json
import os
import shlex
import shutil
import sys
import time
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from suriharvest import __version__
from suriharvest.cli_help import EPILOG, HelpGroup
from suriharvest.config import (
    DEFAULT_DATASET_SID_BASE,
    ConfigError,
    Workspace,
    find_workspace,
    load_sources,
    preset_sources,
    save_sources,
    write_default_settings,
)
from suriharvest.db import SchemaBehind, current_revision, get_meta, head_revision, session_factory
from suriharvest.lock import LockBusy, workspace_lock
from suriharvest.models import LogicGroup, Occurrence, Quarantine, RuleKey, RuleVersion, Source, SyncLog, ValidationResult, utcnow
from suriharvest.portable import rmtree, setup_stdio


def _hide_flag_type() -> None:
    """typer >= 0.2x prints a `<bool>` type next to every on/off flag in --help (`--refresh <bool>`), which reads
    as if the flag took a value: show nothing there for flags, as click does."""
    try:
        from typer.core import TyperOption
    except ImportError:  # pragma: no cover - older or newer typer layout
        return
    shown = getattr(TyperOption, "display_type_rich", None)
    if shown is None or getattr(shown, "_suriharvest", False):  # pragma: no cover
        return

    def display_type_rich(self, ctx):  # type: ignore[no-untyped-def]
        return None if self.is_flag else shown(self, ctx)

    display_type_rich._suriharvest = True  # type: ignore[attr-defined]
    TyperOption.display_type_rich = display_type_rich  # type: ignore[method-assign]


_hide_flag_type()

app = typer.Typer(
    cls=HelpGroup,
    no_args_is_help=True,
    add_completion=False,
    epilog=EPILOG,
    help="Public Suricata rule aggregator: collect, deduplicate, validate and build rulesets from free sources.",
)
sources_app = typer.Typer(no_args_is_help=True, help="List and edit sources.yaml.")
app.add_typer(sources_app, name="sources")


def _n(count: int, one: str, many: str | None = None) -> str:
    """`1 exclusion`, `2 exclusions`."""
    return f"{count} {one if count == 1 else (many or one + 's')}"


def _version_flag(value: bool) -> None:
    if value:
        print(f"suriharvest {__version__}")
        raise typer.Exit()


@app.callback()
def _main(
    version: Annotated[
        bool, typer.Option("--version", callback=_version_flag, is_eager=True, help="Print the installed version and exit.")
    ] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Also print debug messages (on stderr).")] = False,
) -> None:
    """Public Suricata rule aggregator: collect, deduplicate, validate and build rulesets from free sources."""
    if verbose:
        import logging

        logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
        logging.getLogger("suriharvest").setLevel(logging.DEBUG)


profile_app = typer.Typer(no_args_is_help=True, help="Profiles (named rulesets): exclusions, suggestions, builds, diffs.")
app.add_typer(profile_app, name="profile")
release_app = typer.Typer(no_args_is_help=True, help="Publishable release files (flat, reproducible, checksummed).")
app.add_typer(release_app, name="release")
runs_app = typer.Typer(no_args_is_help=True, help="Update runs: list, show, accept a failed run as the new baseline.")
app.add_typer(runs_app, name="runs")
site_app = typer.Typer(no_args_is_help=True, help="Static site from release files (GitHub Pages).")
app.add_typer(site_app, name="site")
con = Console(soft_wrap=True)
# soft_wrap: messages are not re-wrapped by Rich (the terminal wraps long lines), so a path or a command in an error
# or hint stays one copy-pasteable line in a pipe or a log (as in sigharvest)
err = Console(stderr=True, soft_wrap=True)


def ws() -> Workspace:
    return find_workspace()


def not_a_workspace(w: Workspace) -> str:
    where = "SURIHARVEST_HOME" if os.environ.get("SURIHARVEST_HOME") else "this folder"
    return (
        f"not a suriharvest workspace: {w.root} ({where}) has no sources.yaml or suriharvest.yaml; "
        "cd into your workspace, set SURIHARVEST_HOME to it, or create one with `suriharvest init DIR`"
    )


def session(w: Workspace, *, migrate: bool = False) -> Session:
    """migrate=True for the commands that write (init, update, sync), called under the workspace lock: they upgrade
    the schema themselves. Read-only commands refuse an old schema and say `run suriharvest doctor`."""
    if not w.initialised:
        fail(not_a_workspace(w))
    try:
        return session_factory(w.db_path, migrate=migrate)()
    except SchemaBehind as e:
        fail(str(e))
        raise


def fail(msg: str, code: int = 2) -> None:
    """Exit codes (docs/conventions.md): 1 = the command ran but did not reach its goal (nothing matched a key, a
    source or a gate failed); 2 = bad option or argument, not a workspace, the workspace is busy, an I/O error."""
    err.print(f"[red]error:[/] {msg}", highlight=False)
    raise typer.Exit(code)


# ---------------------------------------------------------------------------------------------------------------


@app.command()
def init(
    path: Annotated[Path, typer.Argument(help="workspace folder")] = Path("."),
    preset: Annotated[
        str, typer.Option(help="core (tier core), community (core + community) or all: which catalog sources are enabled")
    ] = "core",
    catalog: Annotated[Path | None, typer.Option(help="source catalog YAML (default: the bundled one)")] = None,
    tier: Annotated[list[str] | None, typer.Option("--tier", help="enable exactly these tiers (repeatable; overrides --preset)")] = None,
    redistributable_only: Annotated[bool, typer.Option(help="enable only sources with redistribute: yes")] = False,
    ruleset_version: Annotated[
        str | None,
        typer.Option(
            "--ruleset-version",
            "--suricata-version",
            help="ruleset requested from sources: fills ${suricata_version} in source URLs (default: the newest engine's version)",
        ),
    ] = None,
    engine: Annotated[
        list[str] | None,
        typer.Option("--engine", help="NAME=IMAGE_OR_BINARY (repeatable): validation engines; a value with / or @ is a docker image"),
    ] = None,
    refresh: Annotated[bool, typer.Option(help="rewrite sources.yaml and suriharvest.yaml of an existing workspace (keeps data)")] = False,
) -> None:
    """Create a workspace: sources.yaml from the catalog, suriharvest.yaml, a default profile and the database."""
    import re

    from suriharvest.config import TIERS, EngineConfig, default_ruleset_version, highest_engine_version
    from suriharvest.profiles import ProfileError
    from suriharvest.profiles import create as create_profile

    if ruleset_version is not None and not re.fullmatch(r"[0-9]{1,3}(\.[0-9]{1,3}){0,2}", ruleset_version.strip(), re.ASCII):
        fail(f"--ruleset-version must be a Suricata version such as 7, 8.0 or 7.0.10, got {ruleset_version!r}")
    ruleset_version = ruleset_version.strip() if ruleset_version else None
    w = Workspace(path.resolve())
    w.root.mkdir(parents=True, exist_ok=True)
    if w.sources_file.exists() and not refresh:
        fail(f"{w.sources_file} already exists (--refresh rewrites it)")
    engines = []
    for spec in engine or []:
        name, sep, target = spec.partition("=")
        if not sep or not name or not target:
            fail(f"--engine must be NAME=IMAGE_OR_BINARY, got {spec!r}")
        image = ("/" in target and not target.startswith("/")) or "@" in target
        engines.append(EngineConfig(name, binary=None if image else target, image=target if image else None))
    ruleset_version = ruleset_version or default_ruleset_version(engines)
    # A source written for a newer Suricata (min_suricata) is enabled when any engine can load it; the engines
    # below its min_suricata leave its rules out of their builds (validation, release build).
    gate_version = highest_engine_version(engines) or ruleset_version
    try:
        srcs = preset_sources(preset, gate_version, catalog)
        for src in srcs:
            if tier is not None:
                bad = set(tier) - set(TIERS)
                if bad:
                    fail(f"unknown tier(s) {sorted(bad)}; tiers: {', '.join(TIERS)}")
                src.enabled = src.tier in tier and src.synced_status and src.enabled_for(gate_version)
            if redistributable_only and not src.redistributable:
                src.enabled = False
        save_sources(w, srcs)
    except ConfigError as e:
        fail(str(e))
    write_default_settings(w, ruleset_version, engines or None, overwrite=refresh)
    with workspace_lock(w.data, "init"):
        sf = session_factory(w.db_path, migrate=True)
        with sf() as s, contextlib.suppress(ProfileError):  # --refresh: the profile exists
            create_profile(s, "default", engine=(engines[0].name if engines else "local"), description="every enabled rule that loads")
    srcs = load_sources(w)
    con.print(
        f"workspace ready in {w.root}: {sum(x.enabled for x in srcs)} of {len(srcs)} sources enabled, "
        "profile 'default'. Next: [bold]suriharvest update[/]"
    )
    if srcs and not any(x.enabled for x in srcs):
        err.print(
            f"[yellow]warning:[/] no source is enabled (Suricata {gate_version}, preset {preset}): check --ruleset-version, "
            "--engine and --tier (each catalog source has a minimum Suricata version), or enable sources with `suriharvest sources enable`"
        )


@app.command()
def doctor() -> None:
    """Check the workspace and probe the engines; create or upgrade the database (update and sync upgrade it too)."""
    w = ws()
    if not w.initialised:
        fail(not_a_workspace(w))
    problems = 0
    con.print(f"workspace: {w.root}")
    try:
        srcs = load_sources(w)
        con.print(f"[green]ok[/]  sources.yaml: {len(srcs)} sources, {sum(s.enabled for s in srcs)} enabled")
    except (ConfigError, FileNotFoundError) as e:
        con.print(f"[red]bad[/] sources.yaml: {e}")
        problems += 1
    before = current_revision(w.db_path)
    try:
        with workspace_lock(w.data, "doctor (migration)", wait=5):
            session_factory(w.db_path, migrate=True)
    except LockBusy as e:
        fail(str(e))
    after = current_revision(w.db_path)
    note = "created" if before is None else ("upgraded from " + before) if before != after else "current"
    con.print(f"[green]ok[/]  database {w.db_path.name}: schema {after} ({note})")
    with session(w) as s:
        n_versions = s.scalar(select(func.count()).select_from(RuleVersion)) or 0
        indexed = get_meta(s, "indexed_at")
        con.print(f"[green]ok[/]  corpus: {n_versions} rule versions; index built {indexed or 'never'}")
        failed = s.execute(
            select(Source.name, SyncLog.error).join(Source, Source.id == SyncLog.source_id).where(SyncLog.status == "error")
        ).all()
        last_failed = {n: e for n, e in failed}
        for n, e in list(last_failed.items())[:10]:
            con.print(f"[yellow]warn[/] last sync of {n} failed: {e}")
    for eng in w.settings().engines:
        from suriharvest.validate import probe

        try:
            e = probe(eng)
            con.print(f"[green]ok[/]  engine {eng.name}: Suricata {e.version}")
        except Exception as ex:  # noqa: BLE001 - report any engine problem
            con.print(f"[yellow]warn[/] engine {eng.name}: {ex}")
    if not shutil.which("git"):
        con.print("[yellow]warn[/] git not found: git sources cannot sync")
    raise typer.Exit(1 if problems else 0)


# ---------------------------------------------------------------------------------------------------------------
# sources


@sources_app.command("list")
def sources_list() -> None:
    """Sources with their last sync and live rule count."""
    w = ws()
    srcs = load_sources(w)
    counts: dict[str, tuple[int, object]] = {}
    if w.db_path.exists():
        with session(w) as s:
            q = (
                select(Source.name, func.count(Occurrence.id), Source.last_sync_at)
                .outerjoin(Occurrence, (Occurrence.source_id == Source.id) & Occurrence.present.is_(True))
                .group_by(Source.id)
            )
            counts = {n: (c, t) for n, c, t in s.execute(q)}
    t = Table("name", "type", "tier", "prio", "licence", "redist", "status", "on", "rules", "last sync", box=None)
    for src in sorted(srcs, key=lambda x: (x.priority, x.name)):
        c, at = counts.get(src.name, (0, None))
        t.add_row(
            src.name,
            src.type,
            src.tier,
            str(src.priority),
            (src.licence or "-")[:30],
            src.redistribute,
            src.status,
            "yes" if src.enabled else "no",
            str(c),
            str(at or "-")[:16],
        )
    con.print(t)


def _set_enabled(names: list[str], value: bool) -> None:
    w = ws()
    srcs = load_sources(w)
    known = {s.name for s in srcs}
    for n in names:
        if n not in known:
            fail(f"unknown source {n}")
    for s in srcs:
        if s.name in names:
            s.enabled = value
    save_sources(w, srcs)
    con.print(f"{'enabled' if value else 'disabled'}: {', '.join(names)}")


@sources_app.command("enable")
def sources_enable(names: list[str]) -> None:
    """Enable sources in sources.yaml (by name)."""
    _set_enabled(names, True)


@sources_app.command("disable")
def sources_disable(names: list[str]) -> None:
    """Disable sources in sources.yaml (by name)."""
    _set_enabled(names, False)


@sources_app.command("remove")
def sources_remove(name: Annotated[str, typer.Argument(help="source name from `sources list` (not its URL)")]) -> None:
    """Remove a source from sources.yaml. Its rules leave search and the builds at the next update; their history
    stays in the database, so adding the source back does not download it as new."""
    w = ws()
    srcs = load_sources(w)
    if not any(s.name == name for s in srcs):
        fail(f"unknown source {name} (`suriharvest sources list` shows the names)")
    save_sources(w, [s for s in srcs if s.name != name])
    con.print(f"removed {name}")


@sources_app.command("add")
def sources_add(
    name: str,
    url: Annotated[str, typer.Argument(help="URL, git remote, or a local folder")],
    type: Annotated[str, typer.Option("--type", help="git | http-tarball | http-file | local")] = "git",
    licence: Annotated[str | None, typer.Option()] = None,
    redistribute: Annotated[str, typer.Option(help="yes | no | unknown: may the rules be republished?")] = "unknown",
    tier: Annotated[str, typer.Option(help="core | community | experimental | user-fetch")] = "community",
    priority: Annotated[int, typer.Option()] = 50,
    paths: Annotated[list[str] | None, typer.Option("--path", help="glob of rule files (repeatable)")] = None,
    ref: Annotated[str | None, typer.Option(help="git branch or tag")] = None,
    namespace: Annotated[str | None, typer.Option(help="sid namespace (default: the source name)")] = None,
    auth: Annotated[str | None, typer.Option(help="env var holding a token (sent as Bearer, or put in ${secret} of the url)")] = None,
    min_suricata: Annotated[str | None, typer.Option(help="oldest Suricata version the rules are written for")] = None,
    notes: Annotated[str | None, typer.Option()] = None,
    copyright: Annotated[
        str | None, typer.Option(help="the publisher's copyright line (from its LICENSE or feed header), for NOTICE.md")
    ] = None,
) -> None:
    """Add a source to sources.yaml.

    Example: suriharvest sources add my-repo https://github.com/OWNER/REPO --type git --licence MIT --redistribute yes
    --copyright "Copyright (c) 2026 OWNER"

    `release build` needs --copyright when the licence asks for the copyright notice to be kept."""
    from suriharvest.config import SourceConfig
    from suriharvest.sync import SyncError, _check_git_inputs

    w = ws()
    srcs = load_sources(w)
    if any(s.name == name for s in srcs):
        fail(f"source {name} exists")
    try:
        if type == "git":
            _check_git_inputs(url, ref)
        elif type in ("http-file", "http-tarball") and not url.lower().startswith(("https://", "http://")):
            fail(f"{type} sources need an https:// (or http://) URL, got {url!r}")
        elif type == "local" and url.startswith("-"):
            fail(f"refusing local path {url!r}")
    except SyncError as e:
        fail(str(e))
    try:
        src = SourceConfig(
            name=name,
            type=type,
            url=url,
            ref=ref,
            licence=licence,
            redistribute=redistribute,
            tier=tier,
            priority=priority,
            paths=paths or ["**/*.rules"],
            sid_namespace=namespace,
            copyright=copyright,
            auth=auth,
            min_suricata=min_suricata,
            notes=notes,
        )
    except ConfigError as e:
        fail(str(e))
    save_sources(w, [*srcs, src])
    con.print(f"added {name}")


@sources_app.command("check")
def sources_check(
    catalog: Annotated[Path | None, typer.Option(help="catalog YAML (default: the bundled one)")] = None,
    health: Annotated[Path | None, typer.Option(help="write the health YAML here (deterministic)")] = None,
    oisf_index: Annotated[
        str, typer.Option(help="OISF index URL or local file")
    ] = "https://www.openinfosecfoundation.org/rules/index.yaml",
    no_http: Annotated[bool, typer.Option("--no-http", help="skip the download checks")] = False,
    licences: Annotated[
        bool, typer.Option(help="fetch each source's licence text (licence_url or the repo LICENSE) and compare its sha256 with --health")
    ] = False,
    max_http_requests: Annotated[int, typer.Option(help="cap on download checks")] = 200,
    report_file: Annotated[Path | None, typer.Option(help="write a Markdown report here")] = None,
) -> None:
    """Compare the catalog with the OISF index and check every active source answers. Never edits the catalog.
    Exit 0 = fine, 1 = something needs review, 2 = the check itself failed."""
    import httpx
    import yaml

    from suriharvest.catalog_check import check, render_health, render_report

    try:
        index_text = Path(oisf_index).read_text(encoding="utf-8") if Path(oisf_index).exists() else None
        previous = yaml.safe_load(health.read_text(encoding="utf-8")) if health and health.exists() else None
        res = check(
            catalog,
            index_text=index_text,
            oisf_index=oisf_index,
            do_health=not no_http,
            max_http_requests=max_http_requests,
            licences=licences and not no_http,
            previous_health=previous if isinstance(previous, dict) else None,
        )
    except (OSError, httpx.HTTPError, KeyError, TypeError, yaml.YAMLError) as e:
        fail(f"check failed: {e}")
    report = render_report(res)
    print(report, end="")
    if health:
        health.write_text(render_health(res), encoding="utf-8", newline="\n")
    if report_file:
        report_file.write_text(report, encoding="utf-8", newline="\n")
    raise typer.Exit(res.exit_code)


@sources_app.command("import")
def sources_import(
    catalog: Annotated[Path, typer.Argument(help="catalog YAML (same shape as sources.yaml)")],
    enable: Annotated[bool, typer.Option(help="enable the imported sources (default: added disabled, to review first)")] = False,
) -> None:
    """Add the sources of a catalog file that sources.yaml does not have yet (existing entries are not touched)."""
    from suriharvest.config import catalog_sources

    w = ws()
    srcs = load_sources(w)
    have = {x.name for x in srcs}
    try:
        new = [c for c in catalog_sources(catalog) if c.name not in have]
    except ConfigError as e:
        fail(str(e))
    for c in new:
        c.enabled = enable and c.synced_status
    save_sources(w, [*srcs, *new])
    con.print(f"{len(new)} source(s) added{' (disabled: review, then `suriharvest sources enable NAME`)' if not enable else ''}")


# ---------------------------------------------------------------------------------------------------------------
# sync, index


@app.command()
def sync(
    names: Annotated[list[str] | None, typer.Argument(help="sources to sync (default: all enabled)")] = None,
    index: Annotated[bool, typer.Option(help="rebuild the index afterwards")] = True,
) -> None:
    """Fetch sources (all enabled, or the ones named), ingest new and changed rules, then rebuild the index."""
    from suriharvest.pipeline import sync_sources

    w = ws()
    try:
        srcs = [s for s in load_sources(w) if (s.name in names if names else s.active)]
    except ConfigError as e:
        fail(str(e))
    if names and len(srcs) != len(set(names)):
        fail(f"unknown source(s): {sorted(set(names) - {s.name for s in srcs})}")
    try:
        with workspace_lock(w.data, "sync"), session(w, migrate=True) as s:
            out = sync_sources(s, w, srcs, con.print)
            if index:
                _index(s)
    except LockBusy as e:
        fail(str(e))
    if out.failed:
        raise typer.Exit(1)


def _index(s: Session) -> None:
    from suriharvest.pipeline import index_step

    index_step(s, con.print)


@app.command()
def index() -> None:
    """Rebuild the derived index (logic groups, families, scores, search)."""
    w = ws()
    try:
        with workspace_lock(w.data, "index"), session(w) as s:
            _index(s)
    except (LockBusy, SchemaBehind) as e:
        fail(str(e))


# ---------------------------------------------------------------------------------------------------------------
# report, search, show


@app.command()
def stats(as_json: Annotated[bool, typer.Option("--json")] = False) -> None:
    """Corpus funnel: occurrences -> live versions -> unique logics -> families; IOC vs behaviour; validation."""
    from suriharvest.search import corpus_stats

    w = ws()
    with session(w) as s:
        rep = corpus_stats(s)
    if as_json:
        print(json.dumps(rep, indent=2))
        return
    t = Table("measure", "value", box=None)
    for k, v in rep.items():
        t.add_row(k, str(v))
    con.print(t)


@app.command()
def search(
    query: Annotated[str, typer.Argument(help="words and filters, e.g. 'cobalt app:http ioc:no'")] = "",
    per_family: Annotated[
        bool, typer.Option("--per-family/--per-logic", help="one row per rule family (default) or per unique logic")
    ] = True,
    include_junk: Annotated[bool, typer.Option("--include-junk", help="also show rules marked as junk")] = False,
    all_: Annotated[bool, typer.Option("--all", hidden=True, help="deprecated: use --per-logic")] = False,
    junk: Annotated[bool | None, typer.Option("--junk/--no-junk", hidden=True, help="deprecated: use --include-junk")] = None,
    limit: Annotated[int, typer.Option(min=1, max=100_000)] = 30,
    offset: Annotated[int, typer.Option(min=0, max=100_000_000, help="skip this many results")] = 0,
    as_json: Annotated[bool, typer.Option("--json", help='one JSON document: {"total", "offset", "limit", "results"}')] = False,
) -> None:
    """Search the index (filter syntax: docs/cli.md#filter-syntax, e.g. `cve:CVE-2021-44228 ioc:no`)."""
    from suriharvest.search import QueryError, build, check_size, page_rows, parse_query, row_dict
    from suriharvest.sidmap import SidMap
    from suriharvest.web import ui

    for flag, on, new_flag in (("--all", all_, "--per-logic"), ("--junk", junk is not None, "--include-junk")):
        if on:
            err.print(f"[yellow]deprecated:[/] `{flag}` is now `{new_flag}` (docs/conventions.md)", highlight=False)
    per_family = per_family and not all_
    include_junk = include_junk or bool(junk)
    w = ws()
    with session(w) as s:
        try:  # the same filters as the web UI and /api/search (cve:, flowbits:, metadata:, licence:, remapped: ...)
            check_size(query)
            base, extra = ui.split_query(query, [e.name for e in w.settings().engines])
            stmt = build(parse_query(base), families=per_family, include_junk=include_junk)
            remapped = {h for h, e in SidMap(w.sid_map_file).entries.items() if e.sid != e.original}
            stmt = ui.apply_extra(stmt, extra, remapped=remapped, lic_sources=ui.licence_groups(s))
            total = s.scalar(select(func.count()).select_from(stmt.subquery())) or 0
            rows = page_rows(s, stmt, [LogicGroup.score.desc(), LogicGroup.id], limit, offset)
            hints = ui.value_hints(s, query) if not total else []
        except (QueryError, ValueError) as e:
            fail(str(e))
    if as_json:
        doc = {"total": total, "offset": offset, "limit": limit, "results": [row_dict(g) for g in rows]}
        print(json.dumps(doc | ({"warnings": hints} if hints else {})))
        return
    for h in hints:
        err.print(f"[yellow]{h}[/]", highlight=False)
    t = Table("logic", "sid", "score", "app", "src", "fam", "msg", box=None)
    for g in rows:
        t.add_row(
            g.logic_hash[:10],
            str(g.sid),
            str(g.score),
            g.app_layer,
            f"{g.canonical_source}" + (f"+{g.n_sources - 1}" if g.n_sources > 1 else ""),
            str(g.family_size),
            (g.msg or "")[:90],
        )
    con.print(t)
    con.print(f"{total} result(s)" + (" (one per family; --per-logic for every logic)" if per_family else ""))


@app.command()
def show(ref: Annotated[str, typer.Argument(help="logic hash prefix, namespace:gid:sid, or sid")]) -> None:
    """One rule: canonical text, copies by source, rev history, family, validation, dependencies."""
    from suriharvest.search import resolve

    w = ws()
    with session(w) as s:
        groups = resolve(s, ref)
        if not groups:
            hint = ""
            if ref.count(":") == 2:  # a rule key: the namespace is the sid namespace (et), not the source name (et-open)
                _, gid, sid = ref.split(":")
                keys = sorted(set(s.scalars(select(LogicGroup.rule_key).where(LogicGroup.rule_key.like(f"%:{gid}:{sid}")).limit(5))))
                if keys:
                    hint = f" (rule keys with {gid}:{sid}: {', '.join(keys)}; the first part is the sid namespace, not the source name)"
            fail(
                f"nothing found for {ref}{hint}: give a sid, a rule key (namespace:gid:sid) or 8+ characters of a logic hash; "
                f"`suriharvest search` finds them",
                code=1,
            )
        if len(groups) > 1:
            con.print(
                f"{len(groups)} logics match {ref}; showing the best (others: " + ", ".join(g.logic_hash[:10] for g in groups[1:6]) + ")"
            )
        g = groups[0]
        v = s.get(RuleVersion, g.canonical_version_id)
        assert v is not None
        # Rule text is third-party input: escaped or printed without markup (a "[/x]" in a msg would raise MarkupError).
        con.print(f"[bold]{escape(g.msg or '')}[/]  ({g.rule_key} rev {g.rev})")
        con.print(f"logic {g.logic_hash}  semantic {(g.semantic_hash or '-')[:16]}  score {g.score} {g.score_parts}", markup=False)
        con.print(
            f"app {g.app_layer}  buffers {', '.join(g.buffers) or '-'}  classtype {g.classtype or '-'}  "
            f"severity {g.severity or '-'}  mitre {', '.join(g.mitre) or '-'}",
            markup=False,
        )
        if g.is_ioc:
            con.print(f"IOC rule: {g.ioc_type} {g.ioc_value}", markup=False)
        con.print(
            f"flags: {', '.join(g.flags) or '-'}   verdict: {g.verdict or '-'}   "
            f"loads in: {', '.join(g.loads_in) or '-'}   fails in: {', '.join(g.fails_in) or '-'}",
            markup=False,
        )
        con.print("\n" + v.raw + "\n", markup=False, highlight=False)
        # copies
        q = (
            select(
                Source.name,
                Source.priority,
                Occurrence.path,
                Occurrence.line_no,
                Occurrence.enabled,
                RuleVersion.content_hash,
                RuleVersion.rev,
            )
            .join(Occurrence, Occurrence.source_id == Source.id)
            .join(RuleVersion, RuleVersion.id == Occurrence.version_id)
            .where(RuleVersion.logic_hash == g.logic_hash, Occurrence.present.is_(True))
            .order_by(Source.priority, Source.name)
        )
        t = Table("source", "path:line", "on", "copy", "rev", box=None, title="copies")
        for name, _prio, path, line, enabled, ch, rev in s.execute(q).all()[:40]:
            kind = "canonical" if ch == v.content_hash and name == g.canonical_source else "mirror" if ch == v.content_hash else "variant"
            t.add_row(name, escape(f"{path}:{line}"), "yes" if enabled else "no", kind, str(rev))
        con.print(t)
        # rev history of the rule key
        ns, gid, sid = g.rule_key.split(":")
        hist = s.execute(
            select(RuleVersion.rev, RuleVersion.msg, RuleVersion.logic_hash, RuleVersion.first_seen)
            .join(Occurrence, Occurrence.version_id == RuleVersion.id)
            .join(Source, Source.id == Occurrence.source_id)
            .where(RuleVersion.sid == int(sid), RuleVersion.gid == int(gid), Source.sid_namespace == ns)
            .distinct()
            .order_by(RuleVersion.first_seen)
        ).all()
        if len(hist) > 1:
            con.print(f"history of {g.rule_key}: " + "; ".join(f"rev {r} ({lh[:8]})" for r, _m, lh, _t in hist))
        key = s.get(RuleKey, g.rule_key)
        if key is not None and key.ambiguous:
            con.print(f"[yellow]sid {g.rule_key} is ambiguous[/]: {key.n_clusters} unrelated rules use it; it does not link families")
        if g.family_size > 1:
            fam = s.scalars(
                select(LogicGroup)
                .where(LogicGroup.family_id == g.family_id, LogicGroup.id != g.id)
                .order_by(LogicGroup.score.desc())
                .limit(10)
            )
            con.print(
                "family: " + "; ".join(f"{f.logic_hash[:10]} sid {f.sid} [{f.canonical_source}] {(f.msg or '')[:50]}" for f in fam),
                markup=False,
            )
        from suriharvest.models import NearDuplicate

        near = s.execute(
            select(NearDuplicate.a, NearDuplicate.b, NearDuplicate.jaccard).where(
                (NearDuplicate.a == g.logic_hash) | (NearDuplicate.b == g.logic_hash)
            )
        ).all()
        if near:
            con.print("similar (not merged): " + "; ".join(f"{(b if a == g.logic_hash else a)[:10]} ({j:.0%})" for a, b, j in near[:10]))
        if v.flowbits_check or v.flowbits_set or v.files:
            con.print(
                f"needs bits: {', '.join(v.flowbits_check) or '-'}; sets: {', '.join(v.flowbits_set) or '-'}; files: {', '.join(v.files) or '-'}",
                markup=False,
            )
        errs = s.execute(
            select(ValidationResult.engine, ValidationResult.engine_version, ValidationResult.error).where(
                ValidationResult.content_hash == v.content_hash, ValidationResult.status != "ok"
            )
        ).all()
        for e, ver, msg in errs:
            con.print(f"[red]does not load[/] in {escape(e)} ({escape(str(ver))}): {escape(msg or '')}", markup=True, highlight=False)


# ---------------------------------------------------------------------------------------------------------------
# validate, deps, triage, export, quarantine


@app.command()
def validate(
    engine: Annotated[list[str] | None, typer.Option(help="engine name(s) from suriharvest.yaml (default: all)")] = None,
    workers: Annotated[int | None, typer.Option()] = None,
    reindex: Annotated[bool, typer.Option(help="rebuild the index afterwards")] = True,
) -> None:
    """Check that every live rule loads in each engine (suricata -T). Results are cached per engine config."""
    from suriharvest.validate import validate as run

    w = ws()
    engines = [e for e in w.settings().engines if not engine or e.name in engine]
    if not engines:
        fail("no matching engine in suriharvest.yaml")
    try:
        with workspace_lock(w.data, "validate"), session(w) as s:
            for e in engines:
                t0 = time.monotonic()

                def progress(done: int, total: int, t0: float = t0, name: str = e.name) -> None:
                    rate = done / max(time.monotonic() - t0, 1e-3)
                    eta = (total - done) / rate if rate else 0
                    err.print(f"\r{name}: {done}/{total} rules, ETA {eta:.0f}s   ", end="")

                rep = run(s, e, ws=w, workers=workers, progress=progress)
                err.print()
                cats = ", ".join(f"{k} {v}" for k, v in sorted(rep.categories.items(), key=lambda kv: -kv[1]))
                con.print(
                    f"{e.name} (Suricata {rep.version}): {rep.checked} checked, {rep.cached} cached; {rep.ok} ok, {rep.errors} errors"
                    + (f" ({cats})" if cats else "")
                )
            if reindex:
                _index(s)
    except (LockBusy, SchemaBehind) as ex:
        fail(str(ex))


@app.command()
def deps(limit: Annotated[int, typer.Option()] = 30) -> None:
    """Dependencies: bits checked but never set, and external files rules need."""
    w = ws()
    with session(w) as s:
        from suriharvest.index import load_live

        live = load_live(s)
        set_bits = {b for v in live.values() for b in v.flowbits_set}
        missing: dict[str, int] = {}
        files: dict[str, int] = {}
        for v in live.values():
            for b in v.flowbits_check:
                if b not in set_bits:
                    missing[b] = missing.get(b, 0) + 1
            for f in v.files:
                files[f] = files.get(f, 0) + 1
    con.print(f"{len(missing)} bits are checked but never set by any live rule:")
    for b, n in sorted(missing.items(), key=lambda kv: -kv[1])[:limit]:
        con.print(f"  {b}  ({n} rules)")
    con.print(f"{len(files)} external files are referenced:")
    for f, n in sorted(files.items(), key=lambda kv: -kv[1])[:limit]:
        con.print(f"  {f}  ({n} rules)")


@app.command()
def triage(
    ref: Annotated[str, typer.Argument(help="logic hash prefix, namespace:gid:sid, or source name with --scope source")],
    verdict: Annotated[str, typer.Argument(help="keep | review | drop | clear")],
    scope: Annotated[str, typer.Option(help="logic | rule | source")] = "logic",
    note: Annotated[str | None, typer.Option()] = None,
) -> None:
    """Set a triage verdict (an overlay: nothing is deleted)."""
    from suriharvest.search import resolve
    from suriharvest.triage import TriageError, set_verdict

    w = ws()
    with workspace_lock(w.data, "triage", wait=10), session(w) as s:
        if scope == "source":
            key = ref
        else:
            groups = resolve(s, ref)
            if len(groups) != 1:
                fail(f"{ref} matches {len(groups)} logics; give a longer hash")
            key = groups[0].logic_hash if scope == "logic" else groups[0].rule_key
        try:
            n = set_verdict(s, scope, key, verdict, note)
        except TriageError as e:
            fail(str(e))
    con.print(f"{scope} {key}: {verdict} ({n} logic groups)")


def _export_args(arg: str | None, out: Path | None, query: str | None) -> tuple[Path, str]:
    """`export [QUERY] --out PATH`; the old `export OUT [--query Q]` still works for now, with a warning."""
    if out is not None:
        if query is not None:
            fail("give the query once: `suriharvest export QUERY --out PATH`")
        return out, arg or ""
    if arg is None:
        return Path("export"), query or ""
    err.print(
        f"[yellow]deprecated:[/] `export OUT --query Q` is now `export [QUERY] --out OUT`; "
        f"run `suriharvest export --out {shlex.quote(arg)}{' -- ' + shlex.quote(query) if query else ''}`",
        highlight=False,
    )
    return Path(arg), query or ""


@app.command()
def export(
    query_arg: Annotated[str | None, typer.Argument(metavar="[QUERY]", help="search query selecting rules (default: all)")] = None,
    out: Annotated[Path | None, typer.Option("--out", help="output folder (default: export)")] = None,
    query: Annotated[str | None, typer.Option(hidden=True, help="deprecated: the old form `export OUT --query Q`")] = None,
    unit: Annotated[str, typer.Option(help="family (best per family) or logic")] = "family",
    redistributable_only: Annotated[
        bool,
        typer.Option(
            "--redistributable-only/--include-private-sources",
            help="only rules whose source says redistribute: yes (for a file you share or publish)",
        ),
    ] = False,
    profile: Annotated[str | None, typer.Option(help="export the rules a profile selects now (its exclusions applied)")] = None,
    by_source: Annotated[bool, typer.Option(help="also write by-source/<source>.rules")] = False,
    fmt: Annotated[
        str, typer.Option("--format", help="rules (suricata.rules) or suricata-update (local.rules + enable/disable.conf)")
    ] = "rules",
    iocs_as_datasets: Annotated[bool, typer.Option(help="replace single-indicator rules by dataset files + one rule per buffer")] = False,
    sid_base: Annotated[int, typer.Option(help="first sid of generated dataset rules")] = DEFAULT_DATASET_SID_BASE,
    remap_colliding_sids: Annotated[
        bool, typer.Option(help="give rules that share a gid:sid new sids (mapping in manifest.jsonl)")
    ] = False,
    remap_base: Annotated[
        int | None, typer.Option(help="first sid used by --remap-colliding-sids (default: remap_base in suriharvest.yaml)")
    ] = None,
    include_failing: Annotated[
        bool, typer.Option(help="also rules that fail to load in an engine (default: left out, so suricata -T passes)")
    ] = False,
    disabled: Annotated[
        str | None,
        typer.Option(
            help="rules disabled upstream (commented out by every publisher, or flagged deleted): comment (default for a "
            "query: written commented out), omit, or enable (default with --profile)"
        ),
    ] = None,
    include_disabled: Annotated[bool, typer.Option(help="same as --disabled enable")] = False,
) -> None:
    """Write suricata.rules + manifest.jsonl (flowbits setters added, sid collisions refused unless remapped).
    Remapped sids are stable: they are kept in state/sid-map.tsv and reused by every later export and build."""
    from suriharvest.export import SidCollision
    from suriharvest.export import export as run

    out, query = _export_args(query_arg, out, query)
    w = ws()
    base = remap_base if remap_base is not None else w.settings().remap_base
    with session(w) as s:
        _refresh(s, w)
        hashes = None
        excluded = None
        rewrite = None
        check_modified = None
        engine = None
        if profile:
            from suriharvest.profiles import select_rules

            _sync_files(s, w)
            from suriharvest.overrides import Overrides

            prof = _profile(s, profile)
            engine = prof.engine
            ov = Overrides(s, prof)
            sel = select_rules(s, prof, ov)
            rewrite = ov.rewrite if ov.items["modify"] else None
            from suriharvest.profiles import _modified_checker

            check_modified = _modified_checker(w, prof, ov) if ov.items["modify"] else None
            hashes = [g.logic_hash for g in sel.kept]
            excluded = [g for g, _, _ in sel.excluded]
        try:
            from suriharvest.export_formats import managed_sources

            if fmt not in ("rules", "suricata-update"):
                fail("--format must be rules or suricata-update")
            if include_disabled:
                disabled = "enable"
            if disabled is not None and disabled not in ("comment", "omit", "enable"):
                fail("--disabled must be comment, omit or enable")
            managed = managed_sources(s, {c.name: c.oisf_name for c in load_sources(w)}) if fmt == "suricata-update" else None
            rep = run(
                s,
                out,
                query,
                unit=unit,
                redistributable_only=redistributable_only,
                logic_hashes=hashes,
                fmt=fmt,
                managed=managed,
                iocs_as_datasets=iocs_as_datasets,
                sid_base=sid_base,
                remap_sids=remap_colliding_sids,
                remap_base=base,
                sid_map=w.sid_map_file,
                split_by_source=by_source,
                excluded=excluded,
                include_failing=include_failing,
                disabled=disabled,
                rewrite=rewrite,
                check_modified=check_modified,
                ws=w,
                engine=engine,
            )
        except SidCollision as e:
            fail(str(e))
    for why in rep.modify_refused.values():
        con.print(f"  {why}", markup=False, highlight=False)
    if rep.suricata_update is not None:
        su = rep.suricata_update
        con.print(
            f"suricata-update files in {out}: {su.local_rules} rules in suriharvest-local.rules, enable.conf {su.enabled}, "
            f"disable.conf {su.disabled} (managed by suricata-update: {', '.join(su.managed_sources) or 'none'})"
        )
        if su.unmapped:
            con.print(
                f"[yellow]{len(su.unmapped)} source(s) have no suricata-update (OISF) name[/]: {', '.join(su.unmapped[:8])}"
                + (" ..." if len(su.unmapped) > 8 else "")
                + " - their rules are in suriharvest-local.rules; disable the same source in suricata-update if it fetches it too",
                highlight=False,
            )
        if su.et_unmanaged:
            con.print(
                "[yellow]ET Open is in suriharvest-local.rules:[/] run `suricata-update disable-source et/open` (enabled by default) or it loads twice"
            )
        if su.disable_skipped:
            con.print(
                f"  not disabled (another selected rule uses the same gid:sid): {', '.join(su.disable_skipped[:10])}", highlight=False
            )
    else:
        con.print(f"wrote {rep.rules} rules to {out / 'suricata.rules'} ({rep.setters_added} flowbit setters added)")
    if rep.disabled_upstream:
        how = "left out" if disabled == "omit" else "written commented out"
        con.print(f"{rep.disabled_upstream} rules disabled upstream {how} (--disabled enable to turn them on)")
    if rep.remapped:
        con.print(
            f"[yellow]{rep.remapped} rules shared a sid with another rule and got a stable new sid (from {base}; state/sid-map.tsv)[/] "
            "(exported_sid in manifest.jsonl)"
        )
    if rep.datasets is not None and rep.datasets.replaced_rules:
        d = rep.datasets
        con.print(
            f"IOC datasets: {d.replaced_rules} rules replaced by {d.rules_written} dataset rules ({out / 'datasets.rules'}) over "
            + ", ".join(f"{b} {n}" for b, n in d.indicators.items())
            + (f"; [yellow]{d.narrowed} matched subdomains, the datasets match exact names[/]" if d.narrowed else "")
        )
    if rep.skipped_licence:
        con.print(f"left out: {rep.skipped_licence} (--redistributable-only)")
    if rep.skipped_malformed:
        con.print(f"[yellow]left out: {rep.skipped_malformed} malformed rules (sid could not be rewritten)[/]")
    if rep.skipped_failing:
        con.print(f"left out: {rep.skipped_failing} rules that fail to load in an engine (--include-failing keeps them)")
    if rep.missing_setters:
        con.print(f"[yellow]{len(rep.missing_setters)} bits have no setter[/]: {', '.join(rep.missing_setters[:10])}")
    if rep.dataset_files:
        con.print(f"{len(rep.dataset_files)} dataset files written to {out / 'datasets'} (rule paths point there)")
    if rep.dataset_renames:
        con.print(f"[yellow]{len(rep.dataset_renames)} dataset names renamed (defined differently by another rule)[/]")
    if rep.left_out_datasets:
        con.print(
            f"[yellow]left out: {len(rep.left_out_datasets)} dataset rules[/]: "
            + "; ".join(f"{d['gid']}:{d['sid']} {d['reason']}" for d in rep.left_out_datasets[:5])
        )
    if rep.needed_files:
        con.print(f"[yellow]rules need {len(rep.needed_files)} external files[/]: {', '.join(rep.needed_files[:10])}")
    if rep.rules == 0:  # docs/conventions.md: an export that selected nothing did not reach its goal (exit code 1)
        fail("no rules were exported: nothing matches this query or profile (`suriharvest search QUERY` shows what matches)", 1)


@app.command()
def quarantine(limit: Annotated[int, typer.Option()] = 20) -> None:
    """Lines that look like rules but do not parse."""
    w = ws()
    with session(w) as s:
        rows = s.execute(
            select(Source.name, Quarantine.path, Quarantine.line_no, Quarantine.error, Quarantine.raw)
            .join(Source, Source.id == Quarantine.source_id)
            .where(Quarantine.present.is_(True))
            .limit(limit)
        ).all()
        total = s.scalar(select(func.count()).select_from(Quarantine).where(Quarantine.present.is_(True)))
    for name, path, line, error, raw in rows:
        con.print(f"{name}/{path}:{line}: {error}\n    {raw[:160]}", markup=False, highlight=False)
    con.print(f"{total} quarantined line(s)")


@app.command()
def update(
    validate: Annotated[bool, typer.Option(help="validate new rules in every engine")] = True,
    wait: Annotated[float, typer.Option(help="seconds to wait for a busy workspace")] = 0,
    allow_failures: Annotated[bool, typer.Option(help="a failed source alone does not make the exit code 1 (gates still do)")] = False,
    max_failed_sources: Annotated[float, typer.Option(help="gate: % of enabled sources allowed to fail")] = 10.0,
    report_file: Annotated[Path | None, typer.Option(help="also copy the Markdown report here")] = None,
) -> None:
    """Unattended update: sync, validate new rules, index, check gates, rebuild profiles, write reports/runs/<stamp>.md.
    Exit code 1 when a source or a gate failed (for systemd OnFailure / CI)."""
    from suriharvest.pipeline import update as run_update
    from suriharvest.runs import Thresholds

    w = ws()
    try:
        with workspace_lock(w.data, "update", wait=wait), session(w, migrate=True) as s:
            res = run_update(s, w, con.print, validate=validate, thresholds=Thresholds(max_failed_sources=max_failed_sources))
    except LockBusy as e:
        fail(str(e))
    for g in res.run.gates:
        colour = {"pass": "green", "fail": "red", "warn": "yellow"}.get(g["status"], "dim")
        con.print(f"[{colour}]{g['status']:>7}[/] {g['name']}: {g['detail']}", highlight=False)
    con.print(f"update {res.run.id}: [bold]{res.run.status}[/]; report {res.report}")
    if report_file and res.report:
        report_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(res.report, report_file)
    code = res.exit_code
    if allow_failures and res.run.status == "passed":
        code = 0
    raise typer.Exit(code)


@runs_app.command("list")
def runs_list(limit: Annotated[int, typer.Option()] = 15) -> None:
    """Recent update runs."""
    from suriharvest.models import UpdateRun

    w = ws()
    with session(w) as s:
        rows = list(s.scalars(select(UpdateRun).order_by(UpdateRun.id.desc()).limit(limit)))
    t = Table("id", "started", "status", "accepted", "unique logic", "new", "gone", "failed gates", box=None)
    for r in rows:
        failed = ", ".join(g["name"] for g in r.gates if g["status"] == "fail") or "-"
        t.add_row(
            str(r.id),
            f"{r.started_at:%Y-%m-%d %H:%M}",
            r.status,
            "yes" if r.accepted else "",
            f"{r.counts.get('unique_logic', '-')}",
            str(r.changes.get("new_logic", "-")),
            str(r.changes.get("gone_logic", "-")),
            failed,
        )
    con.print(t)


@runs_app.command("show")
def runs_show(run: Annotated[str, typer.Argument(help="run id or 'latest'")] = "latest") -> None:
    """Print a run's report."""
    from suriharvest.runs import get_run, report_file

    w = ws()
    with session(w) as s:
        r = get_run(s, run)
        if r is None:
            fail(f"no run {run}")
        path = report_file(w, r.report_path)
    if path and path.exists():
        print(path.read_text(encoding="utf-8"))
    else:
        con.print(f"run {r.id}: {r.status}; report not found")


@runs_app.command("accept")
def runs_accept(run: Annotated[str, typer.Argument(help="run id or 'latest'")] = "latest") -> None:
    """Make a failed run the baseline for the next gates (an intended change, e.g. a source removed)."""
    from suriharvest.runs import get_run

    w = ws()
    with workspace_lock(w.data, "runs accept"), session(w) as s:
        r = get_run(s, run)
        if r is None:
            fail(f"no run {run}")
        if r.status == "error":
            fail(f"run {r.id} crashed; it has no counts to compare with")
        r.accepted = True
        s.commit()
        con.print(f"run {r.id} accepted as the baseline")


@app.command()
def serve(
    host: Annotated[str, typer.Option(help="bind address; anything but loopback needs --token-env")] = "127.0.0.1",
    port: Annotated[int, typer.Option(min=1, max=65535)] = 8077,
    token_env: Annotated[str | None, typer.Option(help="env var holding the access token (HTTP Basic password or Bearer)")] = None,
    allow_host: Annotated[
        list[str] | None,
        typer.Option(envvar="SURIHARVEST_ALLOWED_HOSTS", help="extra Host header names to accept (e.g. a reverse proxy name)"),
    ] = None,
) -> None:
    """Local web UI on http://127.0.0.1:8077: overview, search and rule pages, sources, builds and changes, profiles and
    exclusions, export, about and licences, jobs and health."""
    import os

    import uvicorn

    from suriharvest.web.app import create_app

    token = None
    if token_env:
        token = os.environ.get(token_env)
        if not token or len(token) < 16:
            fail(f"environment variable {token_env} must hold a token of at least 16 characters")
    if host not in ("127.0.0.1", "localhost", "::1") and token is None:
        fail("binding beyond this machine needs authentication: pass --token-env VAR (see docs/web.md)")
    w = ws()
    try:
        application = create_app(w, token=token, allowed_hosts=set(allow_host or []) | ({host} if host not in ("0.0.0.0", "::") else set()))  # noqa: S104 (a comparison, not a bind)
    except SchemaBehind as e:
        fail(str(e))
    busy = port_unavailable(host, port)
    if busy:
        fail(f"cannot listen on {host} port {port}: {busy} (is another server running? choose another with --port)")
    shown = f"[{host}]" if ":" in host else host
    con.print(f"suriharvest serve on http://{shown}:{port}/ (workspace {w.root}); Ctrl+C stops it")
    import threading

    threading.Thread(target=application.state.warm, name="overview-warm-up", daemon=True).start()
    uvicorn.run(application, host=host, port=port, log_level="warning")


def port_unavailable(host: str, port: int) -> str | None:
    """Why `serve` could not listen on host:port (in use, no such address), or None. Checked before the start banner
    so a busy port is one `error:` line with exit code 2, not a banner followed by a uvicorn error and exit code 3."""
    import socket

    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as e:
        return str(e.strerror or e)
    family, _, _, _, addr = infos[0]
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        if os.name != "nt":  # as uvicorn does; on Windows SO_REUSEADDR would let the bind steal a port in use
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(addr)
        except OSError as e:
            return str(e.strerror or e)
    return None


app.command("web", hidden=True, help="Alias of serve.")(serve)


def _profile(s: Session, name: str):  # type: ignore[no-untyped-def]
    from suriharvest.profiles import ProfileError, get

    try:
        return get(s, name)
    except ProfileError as e:
        fail(str(e))


def _refresh(s: Session, w: Workspace) -> None:
    """sources.yaml -> database (redistribute, enabled, licence) and re-index if needed, before a build/export."""
    from suriharvest.pipeline import apply_source_settings

    try:
        apply_source_settings(s, w, lambda m: None if "up to date" in m else err.print(f"[dim]{m}[/]", highlight=False))
    except ConfigError as e:
        fail(str(e))


def _sync_files(s: Session, w: Workspace) -> None:
    """exclusions/*.yaml <-> database, before reading and after changing exclusions."""
    from suriharvest.profiles import load_files

    r = load_files(s, w)
    if r.added or r.removed:
        con.print(f"exclusion files edited by hand: +{r.added} -{r.removed} applied")
    for e in r.errors:
        con.print(f"[yellow]not applied[/] {e}")


def _check_engine(w: Workspace, engine: str | None) -> None:
    """A profile's engine must be one of suriharvest.yaml's engines: an unknown name would filter nothing."""
    if not engine:
        return
    names = [e.name for e in w.settings().engines]
    if engine not in names:
        fail(
            f"no engine {engine!r} in suriharvest.yaml; pick one of its engines ({', '.join(names) or 'none'}) or add one "
            "under `engines:` in suriharvest.yaml"
        )


@profile_app.command("create")
def profile_create(
    name: str,
    query: Annotated[str, typer.Option(help="candidate rules (search syntax); default every rule")] = "",
    unit: Annotated[str, typer.Option(help="logic (every unique logic) or family (best per family)")] = "logic",
    engine: Annotated[
        str | None, typer.Option(help="engine from suriharvest.yaml this profile runs; rules failing there are left out")
    ] = None,
    description: Annotated[str | None, typer.Option()] = None,
) -> None:
    """Create a profile."""
    from suriharvest.profiles import ProfileError, create

    w = ws()
    _check_engine(w, engine)
    with workspace_lock(w.data, "profile", wait=10), session(w) as s:
        try:
            create(s, name, query=query, unit=unit, engine=engine, description=description)
        except ProfileError as e:
            fail(str(e))
        _sync_files(s, w)
    con.print(f"created profile {name}")


@profile_app.command("set")
def profile_set(
    name: str,
    query: Annotated[str | None, typer.Option()] = None,
    unit: Annotated[str | None, typer.Option()] = None,
    engine: Annotated[str | None, typer.Option()] = None,
    remap_sids: Annotated[bool | None, typer.Option(help="give colliding sids new numbers instead of failing")] = None,
    iocs_as_datasets: Annotated[bool | None, typer.Option()] = None,
    include_disabled: Annotated[bool | None, typer.Option(help="also rules their publisher ships disabled")] = None,
    auto_build: Annotated[bool | None, typer.Option(help="rebuild after every update (default on)")] = None,
    redistributable_only: Annotated[bool | None, typer.Option(help="only rules from sources with redistribute: yes")] = None,
    remap_base: Annotated[int | None, typer.Option(help="first remapped sid for this profile (0: suriharvest.yaml remap_base)")] = None,
    flowbit_setters: Annotated[
        str | None,
        typer.Option(
            help="'suricata-update': excluded rules that set a flowbit an enabled rule checks ship with noalert (import-conf sets it); 'strict': never"
        ),
    ] = None,
    description: Annotated[str | None, typer.Option()] = None,
) -> None:
    """Change a profile's settings."""
    w = ws()
    _check_engine(w, engine)
    with workspace_lock(w.data, "profile", wait=10), session(w) as s:
        t = _profile(s, name)
        opts = dict(t.options or {})
        if query is not None:
            t.query = query
        if unit is not None:
            t.unit = unit
        if engine is not None:
            t.engine = engine or None
        if remap_sids is not None:
            opts["remap_sids"] = remap_sids
        if iocs_as_datasets is not None:
            opts["iocs_as_datasets"] = iocs_as_datasets
        if include_disabled is not None:
            opts["include_disabled"] = include_disabled
        if auto_build is not None:
            opts["auto_build"] = auto_build
        if redistributable_only is not None:
            opts["redistributable_only"] = redistributable_only
        if remap_base is not None:
            opts["remap_base"] = remap_base or None
        if flowbit_setters is not None:
            if flowbit_setters not in ("suricata-update", "strict"):
                fail("--flowbit-setters must be suricata-update or strict")
            opts["flowbit_setters"] = flowbit_setters
        if description is not None:
            t.description = description or None
        t.options = opts
        s.commit()
    con.print(f"profile {name} updated")


@profile_app.command("remove")
def profile_remove(
    name: str,
    yes: Annotated[bool, typer.Option("--yes", help="do not ask")] = False,
    keep_files: Annotated[bool, typer.Option(help="keep data/profiles/<name>/ (the built rulesets)")] = False,
) -> None:
    """Delete a profile: its exclusions, overrides and build records (and its build folders unless --keep-files)."""
    from suriharvest.models import Exclusion, ProfileBuild
    from suriharvest.profiles import exclusion_file, profile_dir

    w = ws()
    if not yes and not typer.confirm(f"delete profile {name} with its exclusions and builds?"):
        raise typer.Exit(1)
    with workspace_lock(w.data, "profile", wait=10), session(w) as s:
        _sync_files(s, w)
        t = _profile(s, name)
        folder, efile = profile_dir(w, t), exclusion_file(w, t)
        n_ex = len(list(s.scalars(select(Exclusion).where(Exclusion.profile_id == t.id))))
        for b in s.scalars(select(ProfileBuild).where(ProfileBuild.profile_id == t.id)):
            s.delete(b)
        for ex in s.scalars(select(Exclusion).where(Exclusion.profile_id == t.id)):
            s.delete(ex)
        s.delete(t)
        s.commit()
    if efile.exists():
        efile.rename(efile.with_name(efile.name + ".removed"))
    if not keep_files and folder.is_dir():
        rmtree(folder)
    con.print(
        f"profile {name} removed ({n_ex} exclusion(s)); {efile.name} kept as {efile.name}.removed"
        + ("" if keep_files else f"; {folder} deleted")
    )


@profile_app.command("list")
def profile_list() -> None:
    """Profiles with their last build."""
    from suriharvest.models import Profile
    from suriharvest.profiles import exclusions, last_build

    w = ws()
    with session(w) as s:
        t = Table("profile", "query", "unit", "engine", "exclusions", "last build", "rules", "excluded", box=None)
        for x in s.scalars(select(Profile).order_by(Profile.name)):
            b = last_build(s, x)
            t.add_row(
                x.name,
                x.query or "(all)",
                x.unit,
                x.engine or "-",
                str(len(exclusions(s, x))),
                f"{b.created_at:%Y-%m-%d %H:%M}" if b else "-",
                str(b.rules) if b else "-",
                str(b.excluded) if b else "-",
            )
    con.print(t)


@profile_app.command("exclude")
def profile_exclude(
    name: Annotated[str, typer.Argument(help="profile, or 'all' for every profile")],
    value: str,
    kind: Annotated[
        str,
        typer.Option(
            help="msg_contains | msg_exact | msg_regex | sid | rule_key | logic | category | classtype | source | query | rule_regex | metadata | file"
        ),
    ] = "msg_contains",
    reason: Annotated[str | None, typer.Option()] = None,
    review: Annotated[str | None, typer.Option(help="revisit after this date (YYYY-MM-DD)")] = None,
) -> None:
    """Exclude rules from a profile (by name by default). Prints how many rules it matches."""
    from datetime import datetime as dt

    from suriharvest.profiles import ProfileError, add_exclusion

    w = ws()
    with workspace_lock(w.data, "profile", wait=10), session(w) as s:
        _sync_files(s, w)  # apply hand edits first, or the file (the truth for its scope) would undo this change
        t = None if name == "all" else _profile(s, name)
        try:
            ex, n = add_exclusion(s, t, kind, value, reason, review_at=dt.fromisoformat(review) if review else None)
        except (ProfileError, ValueError) as e:
            fail(str(e))
        _sync_files(s, w)
        from suriharvest.profiles import preview

        rows = preview(s, kind, value) if n else []
        off = n > 0 and all(not r.enabled_anywhere for r in rows) and not (t is not None and (t.options or {}).get("include_disabled"))
    con.print(f"exclusion {ex.id} ({kind}: {value}) matches {n} rules now")
    if n == 0:
        con.print("[yellow]no rule matches it now[/]: a no-op until such a rule appears (check the value and --kind)")
    elif off:
        con.print(
            "[yellow]every matching rule is shipped disabled upstream[/]: not in the build anyway, so this changes nothing now "
            "(it keeps them out if the publisher enables them later)"
        )


@profile_app.command("unexclude")
def profile_unexclude(exclusion_id: int) -> None:
    """Remove an exclusion by id (see `profile exclusions`)."""
    from suriharvest.profiles import ProfileError, remove_exclusion

    w = ws()
    with workspace_lock(w.data, "profile", wait=10), session(w) as s:
        _sync_files(s, w)
        try:
            remove_exclusion(s, exclusion_id)
        except ProfileError as e:
            fail(str(e))
        _sync_files(s, w)
    con.print(f"exclusion {exclusion_id} removed")


@profile_app.command("exclusions")
def profile_exclusions(name: str) -> None:
    """Exclusions of a profile (and global ones): what each matched at the last build, stale ones flagged."""
    from suriharvest.overrides import describe, entries
    from suriharvest.profiles import exclusions, last_build

    w = ws()
    with workspace_lock(w.data, "profile", wait=10), session(w) as s:
        _sync_files(s, w)
        t = _profile(s, name)
        tab = Table("id", "scope", "kind", "value", "matched", "reason", "review", "note", box=None)
        today = utcnow()
        for ex in exclusions(s, t):
            note = ""
            if ex.last_checked_at and ex.last_matched == 0:
                note = "not among the candidates now"
            if ex.review_at and ex.review_at <= today:
                note = (note + "; " if note else "") + "review due"
            tab.add_row(
                str(ex.id),
                "all" if ex.profile_id is None else t.name,
                ex.kind,
                ex.value[:60],
                str(ex.last_matched),
                (ex.reason or "")[:40],
                f"{ex.review_at:%Y-%m-%d}" if ex.review_at else "",
                note,
            )
        items = entries(t)
        prev = last_build(s, t)
        hits = ((prev.summary or {}).get("overrides_hits") or {}) if prev else {}
    con.print(tab)
    if any(items.values()):
        otab = Table("entry", "selector", "does", "matched at last build", "reason", box=None)
        for sec, lst in items.items():
            for i, e in enumerate(lst, 1):
                otab.add_row(
                    f"{sec} #{i}",
                    f"{e['kind']}: {e['value']}"[:50],
                    describe(sec, e),
                    str(hits.get(f"{sec} #{i}", "-")),
                    (e.get("reason") or "")[:30],
                )
        con.print(f"\noverrides of {name} (exclusions/{name}.yaml):")
        con.print(otab)


@profile_app.command("import-conf")
def profile_import_conf(
    name: str,
    directory: Annotated[Path | None, typer.Argument(help="folder with enable.conf / disable.conf / drop.conf / modify.conf")] = None,
    enable: Annotated[Path | None, typer.Option("--enable", help="suricata-update enable.conf")] = None,
    disable: Annotated[Path | None, typer.Option("--disable", help="suricata-update disable.conf")] = None,
    drop: Annotated[Path | None, typer.Option("--drop", help="suricata-update drop.conf")] = None,
    modify: Annotated[Path | None, typer.Option("--modify", help="suricata-update modify.conf")] = None,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="show what would be imported, change nothing")] = False,
) -> None:
    """Import a suricata-update configuration into a profile: disable.conf -> exclusions, enable.conf -> enable,
    drop.conf -> modify (action drop), modify.conf -> modify (from/to). Lines that cannot be converted are listed."""
    from suriharvest.overrides import OverrideError, add_entries
    from suriharvest.profiles import ProfileError, add_exclusion, exclusions
    from suriharvest.suricata_update_conf import FILES, convert

    files: dict[str, Path] = {}
    if directory is not None:
        if not directory.is_dir():
            fail(f"{directory} is not a folder")
        files |= {n: directory / n for n in FILES if (directory / n).is_file()}
    for n, p in (("enable.conf", enable), ("disable.conf", disable), ("drop.conf", drop), ("modify.conf", modify)):
        if p is not None:
            if not p.is_file():
                fail(f"{p}: no such file")
            files[n] = p
    if not files:
        fail("nothing to import: give a folder or --enable/--disable/--drop/--modify")
    res = convert(files)
    for n in FILES:
        if n in res.counts:
            label = files[n].name if files[n].name == n else f"{files[n].name} (as {n})"
            con.print(f"{label}: {res.counts[n]} line{'s' if res.counts[n] != 1 else ''} converted", markup=False, highlight=False)
    con.print(
        f"-> {_n(len(res.exclusions), 'exclusion')}, {len(res.enable)} enable, {_n(len(res.modify), 'modify entry', 'modify entries')}",
        highlight=False,
    )
    for u in res.unsupported:
        con.print(f"  not imported: {u}", markup=False, highlight=False)
    if res.unsupported:
        con.print(f"[yellow]{len(res.unsupported)} line(s) not imported[/] (listed above); handle them by hand")
    if dry_run:
        con.print("dry run: nothing changed")
        return
    w = ws()
    with workspace_lock(w.data, "profile", wait=10), session(w) as s:
        _sync_files(s, w)
        t = _profile(s, name)
        had = {(e.kind, e.value) for e in exclusions(s, t)}
        try:
            for kind, value, reason in res.exclusions:
                add_exclusion(s, t, kind, value, f"imported from {reason}", author="import-conf")
            n_en = add_entries(t, "enable", res.enable)
            n_mod = add_entries(t, "modify", res.modify)
        except (ProfileError, OverrideError) as e:
            fail(str(e))
        added = len({(k, v) for k, v, _ in res.exclusions} - had)
        # suricata-update turns excluded flowbit setters back on (noalert) when an enabled rule needs them
        if "flowbit_setters" not in (t.options or {}):
            t.options = {**(t.options or {}), "flowbit_setters": "suricata-update"}
        s.commit()
        _sync_files(s, w)
    total = len(res.exclusions) + len(res.enable) + len(res.modify)
    new = added + n_en + n_mod
    con.print(
        f"profile {name}: {new} new entries ({added} exclusions, {n_en} enable, {n_mod} modify), "
        f"{total - new} already present (see exclusions/{name}.yaml)",
        highlight=False,
    )


@profile_app.command("preview")
def profile_preview(value: str, kind: Annotated[str, typer.Option()] = "msg_contains", limit: Annotated[int, typer.Option()] = 20) -> None:
    """Rules an exclusion would match, before adding it."""
    from suriharvest.profiles import ProfileError, preview

    w = ws()
    with session(w) as s:
        try:
            rows = preview(s, kind, value)
        except ProfileError as e:
            fail(str(e))
    for g in rows[:limit]:
        con.print(f"{g.sid:>10}  {g.canonical_source:<14} {(g.msg or '')[:100]}", markup=False, highlight=False)
    con.print(f"{len(rows)} rule(s) match")


@profile_app.command("suggest")
def profile_suggest(name: str) -> None:
    """Groups of rules people usually leave out, with counts and examples (nothing is changed)."""
    from suriharvest.profiles import suggestions

    w = ws()
    with session(w) as s:
        items = suggestions(s, _profile(s, name))
    for x in items:
        con.print(f"[bold]{x.count:>6}[/]  {x.title}: {x.why}", highlight=False)
        if x.kind != "info":
            con.print(
                f"        suriharvest profile exclude {name} '{x.value}' --kind {x.kind} --reason '{x.title}'",
                markup=False,
                highlight=False,
            )
        for e in x.examples:
            con.print(f"          e.g. {e[:100]}", markup=False, highlight=False)
    if not items:
        con.print("no suggestions")


@profile_app.command("new")
def profile_new(name: str, limit: Annotated[int, typer.Option()] = 40) -> None:
    """Rules the profile would get now that are not in its last build (what to review before the next build)."""
    from suriharvest.profiles import new_since_last_build

    w = ws()
    with session(w) as s:
        rows = new_since_last_build(s, _profile(s, name))
    rows.sort(key=lambda g: -g.score)
    for g in rows[:limit]:
        con.print(f"{g.score:>3} {g.sid:>10} {(g.category or '-'):<16} {(g.msg or '')[:90]}", markup=False, highlight=False)
    con.print(f"{len(rows)} rule(s) not in the last build")


def excluded_text(by: dict[str, int]) -> str:
    """`excluded_by` of a build summary for people: "older revision 2,747, does not load 31", or "nothing"."""
    return ", ".join(f"{k} {v:,}" for k, v in sorted(by.items(), key=lambda kv: (-kv[1], kv[0]))) or "nothing"


@profile_app.command("build")
def profile_build(name: str, as_json: Annotated[bool, typer.Option("--json", help="print the build as JSON")] = False) -> None:
    """Write the profile's ruleset (data/profiles/<name>/<time>/): suricata.rules, manifest, excluded.jsonl, changes.json."""
    from suriharvest.profiles import ProfileError, make_build

    w = ws()
    with workspace_lock(w.data, "profile build", wait=30), session(w) as s:
        _refresh(s, w)
        _sync_files(s, w)
        try:
            b = make_build(s, w, _profile(s, name))
        except ProfileError as e:
            fail(str(e))
    sm = b.summary
    if as_json:
        print(json.dumps({"profile": name, "build": b.id, "rules": b.rules, "excluded": b.excluded, "path": b.path, "summary": sm}))
        return
    con.print(
        f"build {name} #{b.id}: {b.rules:,} rules, {b.excluded:,} excluded of {sm['candidates']:,} candidates -> {b.path}",
        markup=False,
        highlight=False,
    )
    con.print(f"  excluded by: {excluded_text(sm['excluded_by'])}", markup=False, highlight=False)
    since = (
        f"since build #{sm['previous_build']}: +{sm['added']:,} -{sm['removed']:,} ~{sm.get('changed', 0):,} rules"
        if sm["previous_build"]
        else f"first build of profile {name}"
    )
    con.print(
        f"  {since}; {sm['flowbit_setters_added']} flowbit setters added; {sm['remapped_sids']} sids remapped",
        markup=False,
        highlight=False,
    )
    if sm["missing_setters"]:
        names = ", ".join(sm["missing_setters"][:10]) + (" ..." if len(sm["missing_setters"]) > 10 else "")
        con.print(f"  [yellow]{len(sm['missing_setters'])} flowbits have no setter in this build[/]: {names}", highlight=False)
    if sm.get("flowbit_setters_back"):
        con.print(
            f"  {len(sm['flowbit_setters_back'])} excluded flowbit setter(s) kept, with noalert, because enabled rules check "
            f"their bit (as suricata-update does after disable.conf): {', '.join(sm['flowbit_setters_back'][:10])}",
            markup=False,
            highlight=False,
        )
    if sm.get("modified") or sm.get("threshold_lines"):
        con.print(f"  overrides: {sm['modified']} rules modified, {sm['threshold_lines']} threshold.config lines")
    if sm.get("threshold_skipped"):
        con.print(
            f"  [yellow]{sm['threshold_skipped']} rule(s) have their own threshold/detection_filter[/]: threshold.config "
            f"entries other than suppress would be ignored by Suricata for them, so none were written "
            f"(e.g. {', '.join(sm.get('threshold_skipped_sample') or [])})",
            highlight=False,
        )
    if sm.get("modify_noalert"):
        con.print(
            f"  {sm['modify_noalert']} noalert rule(s) (flowbit setters) not changed by action modify entries (as suricata-update's drop.conf)"
        )
    for x in sm.get("modify_refused") or []:
        con.print(f"  modify refused: {x}", markup=False, highlight=False)
    if sm.get("modify_unchecked") and sm.get("modified"):
        con.print(f"  [yellow]{sm['modify_unchecked']}[/]", highlight=False)
    for x in sm.get("enable_overridden") or []:
        con.print(f"  exclusion wins over: {x}", markup=False, highlight=False)
    for x in sm.get("overrides_unmatched") or []:
        con.print(f"  matched no rule: {x}", markup=False, highlight=False)


@profile_app.command("builds")
def profile_builds(name: str, limit: Annotated[int, typer.Option()] = 20) -> None:
    """Builds of a profile, newest first."""
    from suriharvest.models import ProfileBuild

    w = ws()
    with session(w) as s:
        t = _profile(s, name)
        rows = list(s.scalars(select(ProfileBuild).where(ProfileBuild.profile_id == t.id).order_by(ProfileBuild.id.desc()).limit(limit)))
    tab = Table("build", "created", "rules", "excluded", "added", "removed", "path", box=None)
    for b in rows:
        tab.add_row(
            str(b.id),
            f"{b.created_at:%Y-%m-%d %H:%M}",
            str(b.rules),
            str(b.excluded),
            str(b.summary.get("added", "-")),
            str(b.summary.get("removed", "-")),
            b.path,
        )
    con.print(tab)


@profile_app.command("diff")
def profile_diff(
    name: str,
    old: Annotated[str, typer.Argument(help="build id or 'previous'")] = "previous",
    new: Annotated[str, typer.Argument(help="build id or 'latest'")] = "latest",
    limit: Annotated[int, typer.Option()] = 50,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """What changed between two builds: rules added, removed, and changed (rev, exported sid, source)."""
    from suriharvest.profiles import diff_builds, get_build

    w = ws()
    with session(w) as s:
        t = _profile(s, name)
        a, b = get_build(s, t, old), get_build(s, t, new)
        if b is not None and a is None and old == "previous":
            if as_json:
                print(json.dumps({"old": None, "new": b.id, "added": [], "removed": [], "changed": []}, indent=2))
            else:
                con.print(f"first build of {name} (build {b.id}, {b.rules:,} rules): nothing to compare yet")
            return
        if a is None or b is None:
            fail(f"build not found: need two builds of {name} ({old}, {new}); see `suriharvest profile builds {name}`")
        d = diff_builds(a, b)
    if as_json:
        print(json.dumps({"old": a.id, "new": b.id, "added": d.added, "removed": d.removed, "changed": d.changed}, indent=2))
        return
    con.print(f"build {a.id} -> {b.id}: +{len(d.added)} -{len(d.removed)} ~{len(d.changed)}")
    for sign, rows in (("+", d.added), ("-", d.removed), ("~", d.changed)):
        for r in rows[:limit]:
            extra = f"  ({r['change']})" if "change" in r else ""
            con.print(
                f"{sign} {r['exported_sid'] or r['sid']:>10} {r['source'] or '-':<20} {(r['msg'] or '')[:90]}{extra}",
                markup=False,
                highlight=False,
            )
        if len(rows) > limit:
            con.print(f"{sign} ... {len(rows) - limit} more")


@release_app.command("build")
def release_build(
    out: Annotated[Path, typer.Argument(help="output folder (must be empty or new)")],
    engine: Annotated[list[str], typer.Option("--engine", help="engine from suriharvest.yaml, e.g. suricata-7 (repeatable)")],
    redistributable_only: Annotated[bool, typer.Option(help="only rules from sources with redistribute: yes")] = True,
    recipes_from: Annotated[Path | None, typer.Option(help="catalog: write recipes.tar.gz for sources not redistributed")] = None,
    download_base: Annotated[str, typer.Option(help="URL prefix of the release files (for index.yaml)")] = "",
    build_epoch: Annotated[int | None, typer.Option(help="UNIX time stamped in the files (default: SOURCE_DATE_EPOCH or 0)")] = None,
    previous: Annotated[Path | None, typer.Option(help="folder with the previous release's summary.json [+ manifest.jsonl.gz]")] = None,
    gates: Annotated[bool, typer.Option("--gates/--no-gates", help="fail on a drop against --previous")] = True,
    max_drop_pct: Annotated[float, typer.Option(help="gate: max % of rules an engine may lose")] = 5.0,
    max_source_drop_pct: Annotated[float, typer.Option(help="gate: max % of rules one source may lose")] = 50.0,
    report_file: Annotated[Path | None, typer.Option(help="also write RELEASE_NOTES.md here")] = None,
) -> None:
    """Build the release files from the current index: per engine suricata-N.rules, by-source files, a
    suricata-update tarball; manifest, summary, changes, collisions, NOTICE, index.yaml, SHA256SUMS.
    Remapped sids come from state/sid-map.tsv (extended when needed). Exit 1 when a release gate fails."""
    import os

    from suriharvest.release import ReleaseError
    from suriharvest.release import build as run

    w = ws()
    epoch = build_epoch if build_epoch is not None else int(os.environ.get("SOURCE_DATE_EPOCH", "0") or 0)
    try:
        with workspace_lock(w.data, "release build", wait=30), session(w) as s:
            _refresh(s, w)
            _sync_files(s, w)
            res = run(
                s,
                w,
                out,
                engines=engine,
                redistributable_only=redistributable_only,
                recipes_from=recipes_from,
                download_base=download_base,
                build_epoch=epoch,
                previous=previous,
                gates=gates,
                max_drop_pct=max_drop_pct,
                max_source_drop_pct=max_source_drop_pct,
            )
    except (ReleaseError, LockBusy) as e:
        fail(str(e))
    for e, v in res.engines.items():
        con.print(f"{e} (Suricata {v.get('version') or '?'}): {v['rules']:,} rules from {len(v['by_source'])} sources")
    ch = res.changes
    if ch.get("added") is not None and previous:
        con.print(f"since the previous release: +{len(ch['added'])} -{len(ch['removed'])} ~{len(ch['modified'])}")
    for g in res.gates:
        colour = {"pass": "green", "fail": "red"}.get(g["status"], "dim")
        con.print(f"[{colour}]{g['status']:>7}[/] {g['name']}: {g['detail']}", highlight=False)
    con.print(f"release files in {out} (content id {res.content_id[:16]})")
    if report_file:
        report_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(out / "RELEASE_NOTES.md", report_file)
    raise typer.Exit(1 if res.failed else 0)


@site_app.command("build")
def site_build(
    out: Annotated[Path, typer.Argument(help="output folder (must be empty or new)")],
    release: Annotated[Path, typer.Option(help="folder with the release files (summary.json, manifest.jsonl.gz, ...)")],
    tag: Annotated[str, typer.Option(help="release tag shown on the pages")] = "",
    download_base: Annotated[str, typer.Option(help="URL prefix of the release files (download links)")] = "",
    base_url: Annotated[str, typer.Option(help="path the site is served under, e.g. /suriharvest/")] = "/",
    site_url: Annotated[str, typer.Option(help="origin of the site, e.g. https://owner.github.io (canonical links)")] = "",
    build_epoch: Annotated[int | None, typer.Option(help="UNIX time stamped in the pages (default: SOURCE_DATE_EPOCH or 0)")] = None,
) -> None:
    """Build a static, read-only site from release files only (no workspace needed): overview, downloads with
    checksums, sources, changes, Suricata check, notice and a client-side search over rule metadata."""
    import os

    from suriharvest.site import SiteError
    from suriharvest.site import build as run

    epoch = build_epoch if build_epoch is not None else int(os.environ.get("SOURCE_DATE_EPOCH", "0") or 0)
    try:
        res = run(out, release, tag=tag, download_base=download_base, base_url=base_url, site_url=site_url, build_epoch=epoch)
    except SiteError as e:
        fail(str(e))
    con.print(f"site in {res.out}: {len(res.pages)} pages, {res.indexed:,} rules in the search index")


def _engine_lines() -> list[str]:
    """The Suricata on PATH (`suricata -V`), then the engines of the workspace by name only. Side-effect free: the
    workspace's engines are never run (a cloned workspace could name any binary or image); `doctor` probes them."""
    import re
    import subprocess

    lines = []
    # an explicit PATH: no current-folder lookup (Windows adds it when path is None)
    binary = shutil.which("suricata", path=os.environ.get("PATH", os.defpath))
    if binary is None:
        lines.append("suricata on PATH: not found")
    else:
        try:
            proc = subprocess.run([binary, "-V"], check=False, capture_output=True, text=True, errors="replace", timeout=20)
            m = re.search(r"version (\S+)", proc.stdout + proc.stderr)
            lines.append(f"suricata on PATH: Suricata {m.group(1)} ({binary})" if m else f"suricata on PATH: {binary} (version unknown)")
        except (OSError, subprocess.SubprocessError) as e:
            lines.append(f"suricata on PATH: {binary} cannot run ({e})")
    lines.append(f"suricata-update: {shutil.which('suricata-update', path=os.environ.get('PATH', os.defpath)) or 'not found'}")
    with contextlib.suppress(Exception):  # no workspace, or settings that do not load: nothing more to list
        w = find_workspace()
        if w.initialised:
            for eng in w.settings().engines:
                lines.append(
                    f"workspace engine {eng.name}: {eng.image or eng.binary or 'suricata'} (not run; `suriharvest doctor` probes it)"
                )
    return lines


@app.command()
def version() -> None:
    """Print the suriharvest version, the database schema revision, Python, the main libraries and the Suricata engines.

    Needs no workspace. `suriharvest --version` prints only the version."""
    import platform
    from importlib.metadata import PackageNotFoundError
    from importlib.metadata import version as installed

    con.print(f"suriharvest {__version__}, schema {head_revision()}", highlight=False)
    con.print(f"Python {platform.python_version()}", highlight=False)
    for package in ("sqlalchemy", "fastapi", "typer", "pyyaml"):
        try:
            con.print(f"{package} {installed(package)}", highlight=False)
        except PackageNotFoundError:
            con.print(f"{package} not installed", highlight=False)
    for line in _engine_lines():
        con.print(line, markup=False, highlight=False)


def main() -> None:
    import logging

    setup_stdio()
    # SQLAlchemy logs "Error closing cursor" with a traceback when Ctrl+C lands in a query; -v keeps it (root handler).
    quiet = logging.getLogger("sqlalchemy")
    if not quiet.handlers:
        quiet.addHandler(logging.NullHandler())
    try:
        app()  # Ctrl+C: Typer exits 130 quietly; completed work is committed, the next run continues from it
    except SchemaBehind as e:
        err.print(f"[red]error:[/] {e}")
        sys.exit(2)
    except Exception as e:
        msg = _expected_error(e)
        if msg is None or "-v" in sys.argv[1:] or "--verbose" in sys.argv[1:]:
            raise
        from rich.markup import escape

        err.print(f"[red]error:[/] {escape(msg)}", highlight=False)
        sys.exit(2)


def _expected_error(e: Exception) -> str | None:
    """The one-line message for a failure that is the user's to fix (a damaged workspace file, a wrong path, a full
    disk), or None for a bug (which keeps its traceback). Exit code 2 (docs/conventions.md)."""
    import errno
    import sqlite3

    from sqlalchemy.exc import DatabaseError as SADatabaseError

    if isinstance(e, ConfigError):
        return str(e)
    if isinstance(e, OSError) and e.errno == errno.ENOSPC:
        return "no space left on the device: free some space and run the command again (completed work is kept)"
    paths = {
        FileNotFoundError: "file or folder not found",
        FileExistsError: "already exists and is not a folder",
        IsADirectoryError: "is a folder, a file was expected",
        NotADirectoryError: "is not a folder",
        PermissionError: "permission denied",
    }
    if type(e) in paths:
        name = getattr(e, "filename", None)
        return f"{name or e}: {paths[type(e)]}"
    if isinstance(e, (sqlite3.DatabaseError, SADatabaseError)):
        text = str(e)
        if "disk is full" in text:
            return "no space left on the device: free some space and run the command again (completed work is kept)"
        if "file is not a database" in text or "malformed" in text:
            return (
                "the workspace database (data/suriharvest.db) is damaged: restore it from a backup, or move it away and run "
                "`suriharvest update` to rebuild it from the sources"
            )
    return None


if __name__ == "__main__":
    main()
