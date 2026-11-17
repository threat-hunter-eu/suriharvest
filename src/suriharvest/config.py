"""Workspace layout, sources.yaml and the bundled source catalog."""

from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml

from suriharvest.portable import windows_unsafe_name

SOURCE_TYPES = ("git", "http-tarball", "http-file", "local")
REDISTRIBUTE = ("yes", "no", "unknown")
STATUSES = ("active", "stale", "dead", "deprecated")
# stale = no upstream update for more than a year but still served: synced like active.
SYNCED_STATUSES = ("active", "stale")
# Catalog-only measurement fields (rule counts, validation snapshot): kept in the catalog file, not in sources.yaml.
CATALOG_ONLY_FIELDS = ("rules", "measured")
TIERS = ("core", "community", "experimental", "user-fetch")
DEFAULT_SURICATA_VERSION = "7.0.3"
# Remapped sids start here: above every range seen in public feeds and below 2^31 (tools that read sids as signed
# 32-bit integers). 9,500,000 (the old default) is inside an allocated range (sidallocation.org).
DEFAULT_REMAP_BASE = 1_900_000_000
# Generated IOC dataset rules (export --iocs-as-datasets) start here: away from the remap base, same reasoning.
DEFAULT_DATASET_SID_BASE = 1_990_000_000


# Licence files a publisher ships next to its rules (release LICENSES/<source>/; git sources keep them, sync.py).
LICENCE_FILE = re.compile(r"^(?:LICEN[CS]E|COPYING|COPYRIGHT|NOTICE)(?:\.(?:txt|md|rst))?$", re.IGNORECASE)
MAX_LICENCE_BYTES = 256 * 1024


class ConfigError(ValueError):
    """A problem in sources.yaml / engines that the user can fix."""


@dataclass
class SourceConfig:
    """One entry of sources.yaml."""

    name: str
    type: str
    url: str
    ref: str | None = None
    paths: list[str] = field(default_factory=lambda: ["**/*.rules"])
    licence: str | None = None
    priority: int = 50
    enabled: bool = True
    sid_namespace: str | None = None  # default: the source name
    min_suricata: str | None = None  # oldest Suricata version the rules are written for
    tier: str = "community"  # core | community | experimental | user-fetch (licence/terms unclear: fetch it yourself)
    auth: str | None = None  # optional: name of an env var holding a token (sent as Bearer, or substituted for ${secret})
    redistribute: str = "unknown"  # may the rules be republished? yes | no | unknown (check the licence)
    status: str = "active"  # active | stale (old but served) | dead (upstream gone) | deprecated; active + stale are synced
    homepage: str | None = None
    notes: str | None = None
    oisf_name: str | None = None  # name in the OISF suricata-update index, when it comes from there
    licence_source: str | None = None  # where the licence was read (LICENSE file, README, feed header, ...)
    sid_range: str | None = None  # the publisher's sidallocation.org range(s), free text
    url_versions: dict[str, str] | None = None  # Suricata major -> value for ${suricata_version} (per-engine URLs)
    allow_private: bool = False  # internal mirror: downloads may connect to private addresses
    copyright: str | None = None  # copyright holder line(s) for NOTICE.md (a YAML list is joined with newlines)
    licence_files: list[str] | None = None  # licence texts to publish, relative to the source root (release LICENSES)
    # per-rule licence of a source whose licence splits by sid (ET Open: GPL-2.0 for the old Snort GPL rules, BSD
    # otherwise): [{licence, sids: "1-3464, 100000000-100000908", msg_prefix: "GPL "}, {licence: BSD-3-Clause}];
    # the first entry whose sids or msg_prefix match wins, an entry with neither matches every rule
    rule_licences: list[dict[str, Any]] | None = None

    def __post_init__(self) -> None:
        if self.type not in SOURCE_TYPES:
            raise ConfigError(f"source {self.name}: type must be one of {SOURCE_TYPES}")
        if not self.name or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,120}", self.name):
            raise ConfigError(f"invalid source name: {self.name!r} (letters, digits, . _ -)")
        unsafe = windows_unsafe_name(self.name)
        if unsafe:
            raise ConfigError(f"invalid source name: {self.name!r}: {unsafe}")
        if self.auth and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", self.auth):
            raise ConfigError(f"source {self.name}: auth must be an environment variable name")
        if isinstance(self.redistribute, bool):  # YAML yes/no are booleans
            self.redistribute = "yes" if self.redistribute else "no"
        if self.redistribute not in REDISTRIBUTE:
            raise ConfigError(f"source {self.name}: redistribute must be one of {REDISTRIBUTE}")
        if self.status not in STATUSES:
            raise ConfigError(f"source {self.name}: status must be one of {STATUSES}")
        if self.tier not in TIERS:
            raise ConfigError(f"source {self.name}: tier must be one of {TIERS}")
        if self.min_suricata is not None:
            self.min_suricata = str(self.min_suricata)
        if self.url_versions is not None:
            if not isinstance(self.url_versions, dict):
                raise ConfigError(f"source {self.name}: url_versions must map a Suricata major version to a string")
            self.url_versions = {str(k): str(v) for k, v in self.url_versions.items()}
        if isinstance(self.copyright, list):
            self.copyright = "\n".join(str(x) for x in self.copyright if str(x).strip()) or None
        if self.paths == []:  # http-file sources: the downloaded file itself
            self.paths = ["**/*.rules"]
        self._rule_licences = [self._rule_licence(x) for x in self.rule_licences or []]

    def _rule_licence(self, x: Any) -> tuple[str, list[tuple[int, int]], str | None]:
        if not isinstance(x, dict) or not isinstance(x.get("licence"), str) or not x["licence"].strip():
            raise ConfigError(f"source {self.name}: every rule_licences entry needs a licence")
        if set(x) - {"licence", "sids", "msg_prefix"}:
            raise ConfigError(f"source {self.name}: rule_licences keys are licence, sids and msg_prefix")
        ranges = []
        for part in str(x.get("sids") or "").split(","):
            m = re.fullmatch(r"\s*(\d+)\s*(?:-\s*(\d+))?\s*", part)
            if part.strip() and not m:
                raise ConfigError(f"source {self.name}: rule_licences sids must be like '1-3464, 2100000-2103999'")
            if m:
                ranges.append((int(m[1]), int(m[2] or m[1])))
        return x["licence"].strip(), ranges, str(x["msg_prefix"]) if x.get("msg_prefix") else None

    def licence_of(self, sid: int, msg: str | None) -> str | None:
        """The licence of one rule: the first matching rule_licences entry, else the source's licence."""
        for lic, ranges, prefix in self._rule_licences:
            if (not ranges and not prefix) or any(a <= sid <= b for a, b in ranges) or (prefix and (msg or "").startswith(prefix)):
                return lic
        return self.licence

    @property
    def redistributable(self) -> bool:
        return self.redistribute == "yes"

    def enabled_for(self, suricata_version: str) -> bool:
        """Can this source's rules load in this Suricata version (min_suricata)?"""
        return version_tuple(self.min_suricata) <= version_tuple(suricata_version)

    @property
    def active(self) -> bool:
        """Enabled and not marked dead/deprecated: what `sync` and `update` fetch by default."""
        return self.enabled and self.status in SYNCED_STATUSES

    @property
    def synced_status(self) -> bool:
        """active or stale: the upstream still serves the rules (dead/deprecated are never fetched)."""
        return self.status in SYNCED_STATUSES

    @property
    def namespace(self) -> str:
        return self.sid_namespace or self.name

    def resolved_url(self, suricata_version: str) -> str:
        """URL with ${suricata_version} and ${secret} filled in. The secret comes from the environment only."""
        major = str(version_tuple(suricata_version)[:1][0]) if version_tuple(suricata_version) else ""
        value = (self.url_versions or {}).get(major, suricata_version)
        url = self.url.replace("${suricata_version}", value)
        if "${secret}" in url:
            secret = os.environ.get(self.auth or "", "")
            if not secret:
                raise ConfigError(f"source {self.name}: needs the environment variable {self.auth or '<auth>'}")
            url = url.replace("${secret}", secret)
        return url

    def token(self) -> str | None:
        return os.environ.get(self.auth) if self.auth and "${secret}" not in self.url else None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        keep = ("paths", "enabled", "redistribute", "status", "tier")
        return {k: v for k, v in d.items() if v not in (None, [], False) or k in keep}


@dataclass
class EngineConfig:
    """A Suricata engine used for validation: a local binary or a container image (pinned by digest)."""

    name: str
    binary: str | None = "suricata"
    image: str | None = None  # e.g. jasonish/suricata:8.0.8@sha256:...
    config: str | None = None  # suricata.yaml to start from; default: the engine's own
    version: str | None = None  # Suricata version this engine is (e.g. 8.0.8); default: from the image tag or name

    def command(self, *, mount: bool = True) -> list[str]:
        if self.image:
            vol = ["-v", "{work}:{work}"] if mount else []
            return ["docker", "run", "--rm", "--network=none", *vol, "--entrypoint", "suricata", self.image]
        return [self.binary or "suricata"]

    @property
    def suricata_version(self) -> str | None:
        """The Suricata version this engine validates for: `version`, else the image tag
        (jasonish/suricata:8.0.8@sha256:...), else a name like suricata-8. None when unknown (a plain local binary)."""
        if self.version:
            return str(self.version)
        if self.image:
            tag = self.image.split("@", 1)[0].rsplit("/", 1)[-1]
            m = re.search(r":v?(\d+(?:\.\d+){0,2})(?:$|[-_.])", tag)
            if m:
                return m.group(1)
        m = re.fullmatch(r"suricata-?(\d+(?:\.\d+){0,2})", self.name)
        return m.group(1) if m else None


def highest_engine_version(engines: list[EngineConfig]) -> str | None:
    known = [v for e in engines if (v := e.suricata_version)]
    return max(known, key=version_tuple) if known else None


def default_ruleset_version(engines: list[EngineConfig]) -> str:
    """Ruleset version to request from sources when none is configured: the newest engine's version (a source maps a
    major to its own folder name with url_versions, e.g. ET: 8 -> 8.0), else DEFAULT_SURICATA_VERSION."""
    return highest_engine_version(engines) or DEFAULT_SURICATA_VERSION


@dataclass
class Settings:
    """`ruleset_version` is the ruleset requested from sources (fills ${suricata_version} in source URLs); each
    engine's own Suricata version (EngineConfig.suricata_version) decides validation and min_suricata."""

    ruleset_version: str = DEFAULT_SURICATA_VERSION
    engines: list[EngineConfig] = field(default_factory=lambda: [EngineConfig("local")])
    remap_base: int = DEFAULT_REMAP_BASE

    @property
    def suricata_version(self) -> str:  # old name, kept for callers and old settings files
        return self.ruleset_version

    @property
    def max_engine_version(self) -> str:
        """Newest Suricata among the engines (decides which min_suricata sources can be used at all)."""
        return highest_engine_version(self.engines) or self.ruleset_version


@dataclass
class Workspace:
    """Paths of a suriharvest workspace: sources.yaml, corpus/, data/ (database and caches) and reports/."""

    root: Path

    @property
    def sources_file(self) -> Path:
        return self.root / "sources.yaml"

    @property
    def settings_file(self) -> Path:
        return self.root / "suriharvest.yaml"

    @property
    def corpus(self) -> Path:
        return self.root / "corpus"

    @property
    def data(self) -> Path:
        return self.root / "data"

    @property
    def db_path(self) -> Path:
        return self.data / "suriharvest.db"

    @property
    def reports(self) -> Path:
        return self.root / "reports"

    @property
    def cache(self) -> Path:
        return self.data / "cache"

    def source_dir(self, name: str) -> Path:
        return self.corpus / name

    @property
    def sid_map_file(self) -> Path:
        """Persistent logic hash -> exported sid map (stable sid remapping across builds)."""
        return self.root / "state" / "sid-map.tsv"

    @property
    def initialised(self) -> bool:
        """A suriharvest workspace: sources.yaml, suriharvest.yaml or a database is there (`init` writes the first two)."""
        return self.sources_file.exists() or self.settings_file.exists() or self.db_path.exists()

    def git_repo(self, name: str) -> Path:
        return self.cache / "git" / f"{name}.git"

    def settings(self) -> Settings:
        if not self.settings_file.exists():
            return Settings()
        data = read_yaml_file(self.settings_file) or {}
        if not isinstance(data, dict):
            raise ConfigError(f"{self.settings_file}: expected a mapping of settings (engines:, ruleset_version: ...)")
        try:
            engines = [EngineConfig(**e) for e in data.get("engines", [])] or [EngineConfig("local")]
        except TypeError as e:
            raise ConfigError(f"{self.settings_file}: engines: {e}") from e
        ruleset = data.get("ruleset_version", data.get("suricata_version"))  # suricata_version: the old name
        return Settings(
            ruleset_version=str(ruleset) if ruleset else default_ruleset_version(engines),
            engines=engines,
            remap_base=int(data.get("remap_base", DEFAULT_REMAP_BASE)),
        )


def source_root(ws: Workspace, name: str, cfg: SourceConfig | None = None) -> Path:
    """Folder holding a source's synced files: corpus/<name>, or the folder of a local source."""
    root = ws.source_dir(name)
    if cfg is not None and cfg.type == "local":
        root = Path(cfg.url).expanduser()
        root = root if root.is_absolute() else ws.root / root
    return root


def find_workspace(start: Path | None = None) -> Workspace:
    """SURIHARVEST_HOME if set, else the nearest folder with a sources.yaml, else the current folder."""
    env = os.environ.get("SURIHARVEST_HOME")
    if env:
        return Workspace(Path(env).resolve())
    here = (start or Path.cwd()).resolve()
    for p in [here, *here.parents]:
        if (p / "sources.yaml").exists():
            return Workspace(p)
    return Workspace(here)


def read_yaml_file(path: Path) -> Any:
    """A workspace YAML file (sources.yaml, suriharvest.yaml). ConfigError, not a traceback, when it is not readable
    UTF-8 YAML: a hand edit gone wrong is the user's to fix, so the message names the file and the line."""
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except UnicodeDecodeError as e:
        raise ConfigError(f"{path} is not UTF-8 text ({e.reason} at byte {e.start}): fix it or restore it from a backup") from e
    except yaml.YAMLError as e:
        mark = getattr(e, "problem_mark", None)
        where = f" (line {mark.line + 1}, column {mark.column + 1})" if mark is not None else ""
        problem = getattr(e, "problem", None) or str(e).splitlines()[0]
        raise ConfigError(f"{path} is not valid YAML{where}: {problem}; fix it or restore it from a backup") from e


def _read_sources(path: Path) -> list[SourceConfig]:
    if not path.exists():
        return []
    data = read_yaml_file(path) or {}
    items = data.get("sources", []) if isinstance(data, dict) else []
    try:
        return [SourceConfig(**_strip_catalog_only(item)) for item in items]
    except TypeError as e:
        raise ConfigError(f"{path}: {e}") from e


def _strip_catalog_only(item: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ConfigError(f"a source entry must be a mapping, got {item!r}")
    return {k: v for k, v in item.items() if k not in CATALOG_ONLY_FIELDS}


def load_sources(ws: Workspace) -> list[SourceConfig]:
    sources = _read_sources(ws.sources_file)
    names = [s.name for s in sources]
    dupes = {n for n in names if names.count(n) > 1}
    if dupes:
        raise ConfigError(f"duplicate source names: {sorted(dupes)}")
    return sources


def save_sources(ws: Workspace, sources: list[SourceConfig]) -> None:
    header = (
        "# suriharvest rule sources. Edit by hand or with `suriharvest sources ...`.\n"
        "# type: http-tarball | http-file | git | local. priority: lower wins when the same logic is in several sources.\n"
        "# redistribute: yes | no | unknown (may the rules be republished? `export --redistributable-only` keeps 'yes').\n"
        "# status: active | dead | deprecated (only active sources are synced). url may contain ${suricata_version}.\n"
    )
    body = yaml.safe_dump({"sources": [s.to_dict() for s in sources]}, sort_keys=False, allow_unicode=True, width=120)
    ws.sources_file.write_text(header + body, encoding="utf-8", newline="\n")


CATALOG = Path(__file__).parent / "catalog" / "sources.yaml"
PRESETS = ("core", "community", "all")


def catalog_sources(path: Path | None = None) -> list[SourceConfig]:
    """Every entry of a source catalog (default: the bundled one, free/public sources only).
    A catalog has the same shape as sources.yaml: `sources: [{name, type, url, licence, redistribute, status,
    tier, min_suricata, notes, ...}]`."""
    p = path or CATALOG
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as e:
        raise ConfigError(f"cannot read catalog {p}: {e}") from e
    items = data.get("sources", []) if isinstance(data, dict) else []
    try:
        return [SourceConfig(**_strip_catalog_only(item)) for item in items]
    except TypeError as e:
        raise ConfigError(f"{p}: {e}") from e


def version_tuple(v: str | None) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v or "")[:3])


def preset_sources(name: str, suricata_version: str = DEFAULT_SURICATA_VERSION, catalog: Path | None = None) -> list[SourceConfig]:
    """Sources for a new workspace: core (tier core), community (core + community), all (every entry).
    Every catalog entry outside the preset, dead/deprecated, or needing a newer Suricata than `suricata_version`
    is still written, disabled, so it is visible and easy to turn on (except with preset all)."""
    if name not in PRESETS:
        raise ConfigError(f"preset must be one of {', '.join(PRESETS)}")
    tiers = {"core": {"core"}, "community": {"core", "community"}, "all": set(TIERS)}[name]
    out = []
    for src in catalog_sources(catalog):
        # the preset decides, not the catalog's own `enabled` (a curated default for the core tier)
        src.enabled = src.tier in tiers and src.status in SYNCED_STATUSES and src.enabled_for(suricata_version)
        out.append(src)
    return out


def write_default_settings(
    ws: Workspace, ruleset_version: str, engines: list[EngineConfig] | None = None, *, overwrite: bool = False
) -> None:
    if ws.settings_file.exists() and not overwrite:
        return
    remap = ws.settings().remap_base if ws.settings_file.exists() else DEFAULT_REMAP_BASE
    if engines:
        lines = []
        for e in engines:
            lines.append(f"  - name: {json.dumps(e.name)}\n")
            lines.append(f"    image: {json.dumps(e.image)}\n" if e.image else f"    binary: {json.dumps(e.binary)}\n")
            if e.version:
                lines.append(f"    version: {json.dumps(e.version)}\n")
        engine_text = "".join(lines)
    else:
        engine_text = (
            "  - name: local\n"
            "    binary: suricata\n"
            "  # Suricata 8 through Docker (validation matrix 7 + 8):\n"
            "  # - name: '8.0'\n"
            "  #   image: jasonish/suricata:8.0.8   # pin by digest: ...@sha256:<digest>\n"
        )
    ws.settings_file.write_text(
        "# suriharvest settings\n"
        "# ruleset requested from sources: fills ${suricata_version} in source URLs (each source maps a Suricata major\n"
        "# to its own folder with url_versions). Each engine validates as its own Suricata version (image tag or `version:`).\n"
        f"ruleset_version: '{ruleset_version}'\n"
        "# first sid handed out when rules of different publishers share a gid:sid (see docs/sids.md). Pick a range\n"
        "# nobody owns (https://sidallocation.org/), ideally one allocated to you.\n"
        f"remap_base: {remap}\n"
        "engines:  # Suricata engines used by `suriharvest validate` (a rule must load in every engine a profile names)\n" + engine_text,
        encoding="utf-8",
        newline="\n",
    )
