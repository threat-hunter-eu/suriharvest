"""Validation: does a rule load in Suricata version X?

Rules are written to batch files with unique gid:sid (a duplicate sid is an engine error that is not the rule's
fault) and checked with `suricata -T -S <batch>`. Suricata keeps going after a bad rule and reports
`error parsing signature "..." from file F at line N`, preceded by the cause; that maps each error to one rule.
Suricata 8 logs some causes as warnings (`W: ... rule <sid>: ...`, on stdout while errors go to stderr): they are
matched to the error by sid. Suricata 7 cuts log lines at about 2 KB, so the error line of a long rule loses its
`at line N`: the rule is then found by the start of its text. Errors are never moved to a neighbour: when a batch fails,
the rules that got no error are checked again on their own, and a batch that fails without usable error lines is
bisected until the failing rule is alone.

Rules that `load` files (datasets, iprep lists) are checked with the source's files copied into the batch folder,
at the same path relative to the rule file, so they load as they would next to the source's rules.

Results are cache entries keyed by (content_hash, engine name, config hash); the config hash covers the engine
version, its suricata.yaml, the classification/reference/threshold files it points at, and our overrides, so
changing any of them re-validates.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from suriharvest.config import ConfigError, EngineConfig, Workspace, load_sources, source_root, version_tuple
from suriharvest.db import in_list
from suriharvest.identity import sha256_hex
from suriharvest.index import load_live
from suriharvest.models import Occurrence, RuleVersion, Source, ValidationResult, utcnow

BATCH = 4000
# Part of every config hash: bump when the way results are computed changes, so old results are checked again.
# 2: long rules on Suricata 7, causes logged as warnings, dataset files available, docker image in the hash.
VALIDATOR_REVISION = "2"
MAX_RULE_FILE_BYTES = 256 * 1024 * 1024  # a dataset/iprep file copied next to a batch
# Make rules for every protocol loadable: detection of some protocols is off in the default suricata.yaml.
APP_LAYER_ON = [
    "modbus",
    "dnp3",
    "enip",
    "sip",
    "rdp",
    "snmp",
    "rfb",
    "mqtt",
    "http2",
    "ike",
    "krb5",
    "ntp",
    "dhcp",
    "tftp",
    "pgsql",
    "telnet",
    "websocket",
    "ldap",
    "bittorrent-dht",
    "quic",
]
OVERRIDES = [f"app-layer.protocols.{p}.enabled=yes" for p in APP_LAYER_ON] + [
    f"app-layer.protocols.{p}.detection-enabled=yes" for p in APP_LAYER_ON
]
# Lua rules stay disabled: feed content is untrusted and Suricata 7 runs Lua scripts while loading rules.
OVERRIDES += ["security.lua.allow-rules=no", "logging.outputs.0.console.enabled=yes"]
# Suricata (or docker) gets only what it needs from the environment, never source tokens.
ENV_KEEP = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CONTEXT", "XDG_RUNTIME_DIR")
# Windows: without these a child cannot find its system DLLs (SYSTEMROOT), a temp folder or docker's config and
# contexts (USERPROFILE, APPDATA).
ENV_KEEP_NT = (
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
    "PROGRAMFILES",
    "HOMEDRIVE",
    "HOMEPATH",
)


def _env() -> dict[str, str]:
    keep = {*ENV_KEEP, *ENV_KEEP_NT} if os.name == "nt" else set(ENV_KEEP)
    # Windows environment names are case-insensitive (os.environ upper-cases them; compare upper-cased anyway).
    return {k: v for k, v in os.environ.items() if k.upper() in keep}


def _not_found(cfg: EngineConfig) -> str:
    if cfg.image:
        return f"engine {cfg.name}: docker not found on PATH: install Docker, use a local Suricata engine, or run with --no-validate"
    return (
        f"engine {cfg.name}: {cfg.binary or 'suricata'} not found on PATH: install Suricata (or set the engine's binary), "
        "add a Docker engine, or run with --no-validate"
    )


_ERR_LINE = re.compile(r'error parsing signature "(.*)" from file (.+?) at line (\d+)\s*$')
_ERR_START = re.compile(r'error parsing signature "(.*)$')
_RULE_WARN = re.compile(r"\brule (\d+): ")
_SID = re.compile(r"(?:^|[;(\s])sid\s*:\s*(\d+)\s*;")


@dataclass
class Engine:
    cfg: EngineConfig
    version: str
    config_path: str
    config_hash: str

    def run(self, rules_file: Path, workdir: Path) -> tuple[int, str]:
        base = [a.replace("{work}", str(workdir)) for a in self.cfg.command()]
        cmd = [*base, "-T", "-c", self.config_path, "-S", str(rules_file), "-l", str(workdir)]
        for o in OVERRIDES:
            cmd += ["--set", o]
        proc = subprocess.run(
            cmd, check=False, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=1800, cwd=workdir, env=_env()
        )
        return proc.returncode, proc.stdout + proc.stderr


def probe(cfg: EngineConfig) -> Engine:
    cmd = [*cfg.command(mount=False), "-V"]
    try:
        proc = subprocess.run(cmd, check=False, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300, env=_env())
    except FileNotFoundError as e:
        raise RuntimeError(_not_found(cfg)) from e
    except (OSError, subprocess.SubprocessError) as e:
        raise RuntimeError(f"engine {cfg.name}: cannot run Suricata ({e})") from e
    m = re.search(r"version (\S+)", proc.stdout + proc.stderr)
    if proc.returncode != 0 or not m:
        raise RuntimeError(f"engine {cfg.name}: cannot run Suricata ({(proc.stderr or proc.stdout).strip()[:200]})")
    version = m.group(1)
    want = cfg.suricata_version
    if want and version_tuple(want)[:1] != version_tuple(version)[:1]:
        raise RuntimeError(f"engine {cfg.name}: expected Suricata {want}, the engine is {version}")
    config_path = cfg.config or "/etc/suricata/suricata.yaml"
    return Engine(cfg, version, config_path, config_hash(version, config_path, local=not cfg.image, image=cfg.image))


# Files suricata.yaml points at that change whether a rule loads (an unknown classtype is an error).
CONFIG_FILE_KEYS = (
    ("classification-file", "classification.config"),
    ("reference-config-file", "reference.config"),
    ("threshold-file", "threshold.config"),
)


def config_files(config_path: str) -> list[Path]:
    """classification.config, reference.config and threshold.config of a suricata.yaml (configured or default
    paths; relative paths are relative to the yaml's folder). Only files that exist."""
    import yaml

    p = Path(config_path)
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
        data = yaml.safe_load(re.sub(r"(?m)^%YAML.*$", "", text)) or {}
    except (OSError, yaml.YAMLError):
        data = {}
    out = []
    for key, default in CONFIG_FILE_KEYS:
        value = data.get(key) if isinstance(data, dict) else None
        f = Path(str(value)) if value else p.parent / default
        if not f.is_absolute():
            f = p.parent / f
        if f.is_file():
            out.append(f)
    return out


def config_hash(version: str, config_path: str, *, local: bool = True, image: str | None = None) -> str:
    """Cache key part for an engine: version, suricata.yaml, the files it points at, our overrides, the docker image
    (a rebuilt image with the same version can ship another suricata.yaml) and the validator revision."""
    parts = [version.encode(), "\n".join(OVERRIDES).encode(), f"validator {VALIDATOR_REVISION}".encode()]
    if image:
        parts.append(f"image {image}".encode())
    p = Path(config_path)
    if local and p.exists():
        parts.append(p.read_bytes())
        for f in config_files(config_path):
            parts += [str(f).encode(), f.read_bytes()]
    else:
        parts.append(config_path.encode())
    return sha256_hex(b"\n".join(parts))


def categorise(message: str) -> str:
    m = message.lower()
    if "unknown rule keyword" in m:
        return "unknown_keyword"
    if "cannot be used in a signature" in m or ("protocol" in m and "disabled" in m):
        return "disabled_protocol"
    if "fopen" in m or "no such file" in m or "dataset" in m or "iprep" in m:
        return "missing_file"
    if "lua" in m:
        return "lua"
    if "pcre" in m:
        return "pcre"
    if "duplicate" in m:
        return "duplicate_sid"
    return "parse_error"


@dataclass
class Parsed:
    errors: dict[int, str] = field(default_factory=dict)  # line number -> cause
    unplaced: list[tuple[str, str]] = field(default_factory=list)  # (start of the rule text, cause): line number cut off


def _level(line: str) -> str | None:
    if line.startswith("E:") or " E: " in line or "<Error>" in line:
        return "E"
    if line.startswith("W:") or " W: " in line or "<Warning>" in line:
        return "W"
    return None


def parse_errors(output: str) -> Parsed:
    """Errors of a `suricata -T` run. The cause lines before each `error parsing signature` belong to it; warnings
    naming `rule <sid>:` belong to the error of the rule with that sid (Suricata 8 logs some causes that way, on
    another stream, so their position says nothing). An error line cut short (no `at line N`) is kept in `unplaced`."""
    res = Parsed()
    warns: dict[str, list[str]] = {}
    lines = output.splitlines()
    for line in lines:
        if _level(line) == "W":
            msg = re.sub(r"^.*?(W: |<Warning>\s*)", "", line).strip()
            m = _RULE_WARN.search(msg)
            if m:
                warns.setdefault(m.group(1), []).append(msg[:500])
    cause: list[str] = []
    for line in lines:
        if _level(line) != "E":
            continue
        msg = re.sub(r"^.*?(E: |<Error>\s*)", "", line).strip()
        full = _ERR_LINE.search(line)
        cut = None if full else _ERR_START.search(line)
        if full or cut:
            sig = (full or cut).group(1)  # type: ignore[union-attr]
            sids = _SID.findall(sig)
            extra = [w for w in warns.get(sids[-1], []) if w not in cause] if sids and full else []
            text = "; ".join(cause + extra) or "error parsing signature"
            if full:
                res.errors[int(full.group(3))] = text
            else:
                res.unplaced.append((sig, text))
            cause = []
        elif "Loading signatures failed" not in msg:
            cause.append(msg[:500])
    return res


def parse_output(output: str) -> dict[int, str]:
    """line number -> error message (see parse_errors)."""
    return parse_errors(output).errors


def _find_rule(rules: list[tuple[str, str]], start: str, taken: set[int]) -> int | None:
    """The one rule (1-based line) whose text starts with `start` (an error line cut short), else None."""
    key = start.rstrip()[:-8]  # the cut may split a character or an escape
    if len(key) < 64:
        return None
    hits = [i for i, (_, t) in enumerate(rules, start=1) if i not in taken and t.startswith(key)]
    return hits[0] if len(hits) == 1 else None


_SAFE_REL = re.compile(r"[A-Za-z0-9._+/-]+")
_DS_KEYWORDS = ("dataset", "datarep")
_DS_FILE_ARGS = ("load", "state", "save")
_UNSAFE = "\x00"  # placeholder path for a value we cannot read safely: never a valid relative path


def _ds_options_kw(text: str) -> list[tuple[str, int, int, str]]:
    """(keyword, start, end, value) of every dataset/datarep option, in absolute offsets of `text`. Options are split
    exactly like Suricata (and parser.split_options) does it: keywords case-insensitive, `\\;` does not end an option."""
    from suriharvest.parser import _option_spans

    if "data" not in text.lower():  # both keywords contain it (case-insensitive): most rules end here
        return []
    open_, close = text.find("("), text.rfind(")")
    if open_ < 0 or close < open_:
        return []
    body = text[open_ + 1 : close]
    out = []
    for name, a, b in _option_spans(body):
        if name in _DS_KEYWORDS:
            colon = body.index(":", a, b) if ":" in body[a:b] else b
            out.append((name, open_ + 1 + colon + 1, open_ + 1 + b, body[colon + 1 : b]))
    return out


def _ds_options(text: str) -> list[tuple[int, int, str]]:
    """(start, end, value) of every dataset/datarep option (see _ds_options_kw)."""
    return [(a, b, v) for _, a, b, v in _ds_options_kw(text)]


def dataset_defs(text: str) -> list[tuple[str, str | None, str | None]]:
    """(name, type, file) of every dataset/datarep option: what Suricata compares when two rules use one name (a
    different type or `load`/`state` file is a "load mismatch" that fails the whole rule file)."""
    out = []
    for kw, _, _, value in _ds_options_kw(text):
        fields = [x.strip() for x in value.split(",")]
        idx = 1 if kw == "dataset" else 0
        if len(fields) <= idx:
            continue
        typ = path = None
        for f in fields[idx + 1 :]:
            word, _, rest = f.partition(" ")
            if word.lower() == "type":
                typ = rest.strip().lower() or None
            elif word.lower() in ("load", "state"):
                path = rest.strip() or None
        out.append((fields[idx], typ, path))
    return out


def rename_datasets(text: str, new_name: Callable[[str, str | None, str | None], str]) -> str:
    """The rule with the name of every dataset/datarep option replaced by new_name(name, type, file)."""
    defs = iter(dataset_defs(text))
    pieces: list[str] = []
    pos = 0
    for kw, a, b, value in _ds_options_kw(text):
        parts = value.split(",")
        idx = 1 if kw == "dataset" else 0
        if len(parts) > idx:
            name, typ, path = next(defs)
            new = new_name(name, typ, path)
            if new != name:
                lead = parts[idx][: len(parts[idx]) - len(parts[idx].lstrip())]
                trail = parts[idx][len(parts[idx].rstrip()) :]
                parts[idx] = f"{lead}{new}{trail}"
        pieces += [text[pos:a], ",".join(parts)]
        pos = b
    return "".join(pieces) + text[pos:]


def rule_dataset_paths(text: str) -> list[str]:
    """dataset_paths with a cheap pre-check (most rules have no dataset/datarep option)."""
    return dataset_paths(text) if "data" in text.lower() else []


def unsafe_dataset_path(text: str) -> str | None:
    """The first dataset/datarep file path of a rule that must never be opened on the build host (absolute, "..",
    quotes or escapes), else None. Such a rule is not validated (the engine would read or write host files) and
    never published."""
    for p in dataset_paths(text):
        if p == _UNSAFE or not _safe_rel(p):
            return "(unreadable value)" if p == _UNSAFE else p
    return None


def _ds_args(value: str) -> list[tuple[str, str]]:
    """(lower-case argument name, file path) of the file arguments of one dataset/datarep value."""
    found = []
    for part in value.split(","):
        word, _, rest = part.strip().partition(" ")
        if word.lower() in _DS_FILE_ARGS:
            found.append((word.lower(), rest.strip()))
    return found


def dataset_paths(text: str) -> list[str]:
    """Files named by `load`/`state`/`save` in the dataset/datarep options of a rule. A value with quotes or
    escapes cannot be read the way the engine would, so it yields an unusable path (the rule is then left out)."""
    paths: list[str] = []
    for _, _, value in _ds_options(text):
        if any(c in value for c in "\\\"'"):
            paths.append(_UNSAFE)
            continue
        paths += [path or _UNSAFE for _, path in _ds_args(value)]
    return paths


def _safe_rel(path: str) -> bool:
    pp = PurePosixPath(path)
    return bool(_SAFE_REL.fullmatch(path)) and not pp.is_absolute() and ".." not in pp.parts


def rewrite_dataset_paths(text: str, new_path: Callable[[str], str | None]) -> str | None:
    """The rule with every dataset/datarep file path replaced by new_path(path). None (leave the rule out) when a
    path is absolute, has "..", or no new path; when the rule `save`s a file (it would write on the sensor); or when
    a dataset value has quotes or escapes."""
    pieces: list[str] = []
    pos = 0
    for a, b, value in _ds_options(text):
        if any(c in value for c in "\\\"'"):
            return None
        parts = []
        for part in value.split(","):
            word, _, rest = part.strip().partition(" ")
            arg = word.lower()
            if arg == "save":
                return None
            if arg in _DS_FILE_ARGS:
                path = rest.strip()
                new = new_path(path) if _safe_rel(path) else None
                if new is None or not _safe_rel(new):
                    return None
                lead = part[: len(part) - len(part.lstrip())]
                part = f"{lead}{word} {new}"
            parts.append(part)
        pieces += [text[pos:a], ",".join(parts)]
        pos = b
    return "".join(pieces) + text[pos:]


def rule_files(root: Path, rule_path: str, names: list[str]) -> dict[str, Path]:
    """Files a rule loads (relative paths of dataset/datarep `load`, iprep ...), found next to its rule file in the
    source (Suricata's own lookup) or at the source root. Only plain files inside the source folder."""
    out: dict[str, Path] = {}
    try:
        base = root.resolve()
    except OSError:
        return out
    for n in names:
        p = PurePosixPath(n)
        if not _SAFE_REL.fullmatch(n) or p.is_absolute() or ".." in p.parts:
            continue
        for cand in (root / PurePosixPath(rule_path).parent / p, root / p):
            try:
                real = cand.resolve()
                if cand.is_symlink() or not real.is_relative_to(base) or not real.is_file():
                    continue
                if real.stat().st_size > MAX_RULE_FILE_BYTES:
                    continue
            except OSError:
                continue
            out[n] = real
            break
    return out


def _place_files(files: dict[str, Path], workdir: Path) -> None:
    for rel, src in files.items():
        dst = workdir / rel
        if not dst.exists():
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dst)


@dataclass
class Outcome:
    status: str
    error: str | None = None


def check_batch(engine: Engine, rules: list[tuple[str, str]], workdir: Path, files: dict[str, Path] | None = None) -> dict[str, Outcome]:
    """rules: (content_hash, text); files: relative path -> source file to put next to the batch. Returns
    content_hash -> outcome. A rule is `ok` only after a run in which it raised no error and the run passed."""
    if files:
        _place_files(files, workdir)
    f = workdir / f"batch-{sha256_hex(''.join(h for h, _ in rules))[:12]}.rules"
    f.write_text("".join(t + "\n" for _, t in rules), encoding="utf-8", newline="\n")
    rc, out = engine.run(f, workdir)
    f.unlink(missing_ok=True)
    parsed = parse_errors(out)
    errors = {i: e for i, e in parsed.errors.items() if 1 <= i <= len(rules)}
    for start, cause in parsed.unplaced:
        i = _find_rule(rules, start, set(errors))
        if i is not None:
            errors[i] = cause
    if rc != 0 and not errors:
        if len(rules) == 1:
            tail = " | ".join(line for line in out.splitlines()[-5:] if line.strip())
            return {rules[0][0]: Outcome("error", tail[:1000] or f"exit code {rc}")}
        mid = len(rules) // 2
        return check_batch(engine, rules[:mid], workdir) | check_batch(engine, rules[mid:], workdir)
    res = {rules[i - 1][0]: Outcome("error", e) for i, e in errors.items()}
    rest = [r for i, r in enumerate(rules, start=1) if i not in errors]
    if rc != 0 and rest:
        # The run failed: the rules without an error must pass on their own (an error line that could not be
        # matched to its rule, e.g. cut short, would otherwise leave a broken rule marked ok).
        return res | check_batch(engine, rest, workdir)
    return res | {h: Outcome("ok") for h, _ in rest}


def batches(rules: list[tuple[int, int, str, str]], size: int = BATCH) -> list[list[tuple[str, str]]]:
    """Split (gid, sid, hash, text) into batches where every gid:sid is unique."""
    out: list[tuple[set[tuple[int, int]], list[tuple[str, str]]]] = []
    for gid, sid, h, t in rules:
        for keys, items in out:
            if (gid, sid) not in keys and len(items) < size:
                keys.add((gid, sid))
                items.append((h, t))
                break
        else:
            out.append(({(gid, sid)}, [(h, t)]))
    return [items for _, items in out]


@dataclass
class ValidateReport:
    engine: str
    version: str
    checked: int = 0
    cached: int = 0
    ok: int = 0
    errors: int = 0
    categories: dict[str, int] = field(default_factory=dict)


def _files_needed(s: Session, ws: Workspace, versions: list, view: Any = None) -> dict[str, tuple[str, dict[str, Path]]]:  # type: ignore[type-arg]
    """content hash -> (source, files found) for rules that load files: looked up in the best (lowest priority
    number) source that carries the rule, next to the rule file it came from (in the engine's own per-major copy
    when `view` is given, majors.py)."""
    need = {v.content_hash: names for v in versions if (names := rule_dataset_paths(v.raw))}
    if not need:
        return {}
    try:
        configs = {c.name: c for c in load_sources(ws)}
    except ConfigError:
        configs = {}
    q = (
        select(RuleVersion.content_hash, Source.name, Occurrence.path)
        .join(Occurrence, Occurrence.version_id == RuleVersion.id)
        .join(Source, Source.id == Occurrence.source_id)
        .where(in_list(RuleVersion.content_hash, need), Occurrence.present.is_(True), Source.enabled.is_(True))
        .order_by(Source.priority, Source.name, Occurrence.path)
    )
    out: dict[str, tuple[str, dict[str, Path]]] = {}
    for h, name, path in s.execute(q):
        if view is not None and not view.sees_path(path):
            continue
        found = rule_files(source_root(ws, name, configs.get(name)), path, need[h])
        if found and (h not in out or len(found) > len(out[h][1])):
            out[h] = (name, found)
    return out


def files_key(config_hash: str, names: list[str], found: dict[str, Path], cache: dict[Path, str] | None = None) -> str:
    """Cache key of a rule that loads files: the engine config hash plus the digest of every file it names
    ("missing" when the source does not ship it), so a changed or newly shipped file re-validates the rule."""
    cache = {} if cache is None else cache
    parts = [config_hash]
    for n in sorted(set(names)):
        f = found.get(n)
        if f is None:
            parts.append(f"{n}\tmissing")
            continue
        if f not in cache:
            try:
                cache[f] = hashlib.sha256(f.read_bytes()).hexdigest()
            except OSError:
                cache[f] = "unreadable"
        parts.append(f"{n}\t{cache[f]}")
    return sha256_hex("\n".join(parts))


def _file_batches(
    rules: list[tuple[int, int, str, str]], files_of: dict[str, tuple[str, dict[str, Path]]]
) -> list[tuple[list[tuple[str, str]], dict[str, Path]]]:
    """Batches of rules that need files: one source per batch, no two rules wanting different files at the same
    relative path, unique gid:sid."""
    out: list[tuple[str, set[tuple[int, int]], list[tuple[str, str]], dict[str, Path]]] = []
    for gid, sid, h, t in rules:
        src, files = files_of[h]
        for name, keys, items, have in out:
            if name == src and (gid, sid) not in keys and len(items) < BATCH and all(have.get(k, v) == v for k, v in files.items()):
                keys.add((gid, sid))
                items.append((h, t))
                have.update(files)
                break
        else:
            out.append((src, {(gid, sid)}, [(h, t)], dict(files)))
    return [(items, have) for _, _, items, have in out]


def _store(s: Session, rows: list[dict[str, Any]]) -> None:
    """Insert or replace validation results in one statement per chunk (Session.merge did a SELECT and an INSERT per
    rule: the largest cost of a cold update)."""
    from sqlalchemy.dialects.sqlite import insert

    for i in range(0, len(rows), 100):  # 8 columns: 800 variables, under the 999 of some SQLite builds
        stmt = insert(ValidationResult).values(rows[i : i + 100])
        cols = ("engine_version", "status", "category", "error", "checked_at")
        s.execute(
            stmt.on_conflict_do_update(index_elements=["content_hash", "engine", "config_hash"], set_={c: stmt.excluded[c] for c in cols})
        )


def validate(
    s: Session,
    cfg: EngineConfig,
    *,
    ws: Workspace | None = None,
    workers: int | None = None,
    progress: Callable[[int, int], None] | None = None,
) -> ValidateReport:
    """Check every live rule not validated yet in this engine config. With `ws`, rules that load files are checked
    with the source's files next to them."""
    engine = probe(cfg)
    rep = ValidateReport(cfg.name, engine.version)
    from suriharvest.majors import load_views, view_for

    # per-major copies (majors.py): an engine checks only the versions its Suricata major sees
    view = view_for(load_views(s), engine.version)
    by_hash = {v.content_hash: v for v in load_live(s).values() if view is None or v.id in view.versions}
    done = set(
        s.execute(select(ValidationResult.content_hash, ValidationResult.config_hash).where(ValidationResult.engine == cfg.name)).all()
    )
    # a rule naming an absolute or escaping file is never run here (the engine would read/write build host files)
    # from the rule text itself (tokenizer, case-insensitive keywords, load/state/save), never from the stored file list
    ds_paths = {h: paths for h, v in by_hash.items() if (paths := rule_dataset_paths(v.raw))}
    unsafe = {h: p for h in ds_paths if (p := unsafe_dataset_path(by_hash[h].raw))}
    with_files = [by_hash[h] for h in ds_paths if h not in unsafe]
    files_of = _files_needed(s, ws, with_files, view) if ws is not None else {}
    # The result of a rule that loads files depends on those files: their digests are part of its cache key.
    key = dict.fromkeys(by_hash, engine.config_hash)
    digests: dict[Path, str] = {}
    for v in with_files:
        key[v.content_hash] = files_key(engine.config_hash, ds_paths[v.content_hash], files_of.get(v.content_hash, ("", {}))[1], digests)
    pending = {h: v for h, v in by_hash.items() if (h, key[h]) not in done}
    rep.cached = len(by_hash) - len(pending)
    now = utcnow()
    for h in sorted(set(pending) & set(unsafe)):
        err = f"dataset/datarep file {unsafe[h]!r} is absolute or outside the source: not checked, never published"
        _store(
            s,
            [
                {
                    "content_hash": h,
                    "engine": cfg.name,
                    "config_hash": key[h],
                    "engine_version": engine.version,
                    "status": "error",
                    "category": "unsafe_path",
                    "error": err,
                    "checked_at": now,
                }
            ],
        )
        rep.checked += 1
        rep.errors += 1
        rep.categories["unsafe_path"] = rep.categories.get("unsafe_path", 0) + 1
        del pending[h]
    s.commit()
    todo = sorted({(v.gid, v.sid, v.content_hash, v.raw) for v in pending.values()}, key=lambda r: r[2])
    files_of = {h: f for h, f in files_of.items() if h in pending}
    plain = [r for r in todo if r[2] not in files_of]
    groups: list[tuple[list[tuple[str, str]], dict[str, Path]]] = [
        (g, {}) for g in batches(plain, max(200, min(BATCH, len(plain) // (os.cpu_count() or 2) + 1)))
    ]
    groups += _file_batches([r for r in todo if r[2] in files_of], files_of)
    finished = 0
    with tempfile.TemporaryDirectory(prefix="suriharvest-validate-") as tmp, ThreadPoolExecutor(workers or os.cpu_count() or 2) as pool:
        work = Path(tmp)
        futures = []
        for i, (g, files) in enumerate(groups):
            d = work / f"w{i}"
            d.mkdir()
            futures.append(pool.submit(check_batch, engine, g, d, files))
        for fut in futures:
            results = fut.result()
            now = utcnow()
            rows = []
            for h, o in results.items():
                cat = categorise(o.error) if o.error else None
                rows.append(
                    {
                        "content_hash": h,
                        "engine": cfg.name,
                        "config_hash": key[h],
                        "engine_version": engine.version,
                        "status": o.status,
                        "category": cat,
                        "error": o.error,
                        "checked_at": now,
                    }
                )
                rep.checked += 1
                if o.status == "ok":
                    rep.ok += 1
                else:
                    rep.errors += 1
                    rep.categories[cat or "?"] = rep.categories.get(cat or "?", 0) + 1
            _store(s, rows)
            s.commit()  # resume after a crash: finished batches stay stored
            finished += len(results)
            if progress:
                progress(finished, len(todo))
    return rep


def modified_checker(
    ws: Workspace, cfg: EngineConfig, note: Callable[[str], None]
) -> Callable[[dict[str, tuple[int, int, str]]], dict[str, str]]:
    """A check for rules a profile's modify entries rewrote: {key: (gid, sid, text)} -> {key: error} for the texts
    that do not load in this engine (`suricata -T`, like `validate`). Results are cached per engine config in
    data/modified-rules-validation.json (only the texts of the latest build are kept). Rules that load files
    (datasets) are not run here, they need their source's files next to them. Fail-safe: a rewrite that was not
    validated (the engine cannot run, or the rule loads files) is refused, so the rule ships unmodified; `note`
    gets the reason."""
    import json

    state: dict[str, Any] = {}

    def check(todo: dict[str, tuple[int, int, str]]) -> dict[str, str]:
        if not todo:
            return {}
        if "engine" not in state:
            try:
                state["engine"] = probe(cfg)
            except RuntimeError as e:
                state["engine"] = None
                note(f"modified rules not checked: {e}")
        engine: Engine | None = state["engine"]
        if engine is None:
            return {h: "not applied: the engine cannot run, so the modified rule could not be validated" for h in todo}
        cache_file = ws.data / "modified-rules-validation.json"
        try:
            cache = json.loads(cache_file.read_text(encoding="utf-8"))
            known: dict[str, str | None] = dict(cache.get(engine.config_hash) or {}) if isinstance(cache, dict) else {}
        except (OSError, ValueError):
            known = {}
        key = {h: sha256_hex(text) for h, (_, _, text) in todo.items()}
        run = sorted(
            {(gid, sid, key[h], text) for h, (gid, sid, text) in todo.items() if key[h] not in known and not rule_dataset_paths(text)},
            key=lambda r: r[2],
        )
        if run:
            with tempfile.TemporaryDirectory(prefix="suriharvest-modified-") as tmp:
                for i, batch in enumerate(batches(run)):
                    d = Path(tmp) / f"w{i}"
                    d.mkdir()
                    for k, o in check_batch(engine, batch, d).items():
                        known[k] = None if o.status == "ok" else (o.error or "error")
        used = state.setdefault("used", set())
        used.update(key.values())  # every text this build asked about (the closure may ask again with fewer)
        keep = {k: known[k] for k in sorted(used) if k in known}
        try:
            ws.data.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(json.dumps({engine.config_hash: keep}, sort_keys=True), encoding="utf-8", newline="\n")
        except OSError:
            pass
        out = {h: err for h, k in key.items() if (err := known.get(k))}
        for h, (_, _, text) in todo.items():
            if h not in out and rule_dataset_paths(text):
                out[h] = "not applied: a modified rule that loads files is not validated"
        return out

    return check
