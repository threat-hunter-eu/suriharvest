"""Per-major rulesets: one download per Suricata major for sources whose URL holds ${suricata_version}.

When the engines of suriharvest.yaml span more than one Suricata major (suricata-7 and suricata-8), an HTTP source
whose URL contains `${suricata_version}` is downloaded once per major into `corpus/<source>/@<major>/` (ET Open:
the 7.0.3 and the 8.0 tarballs). Its occurrences carry the `@<major>/` prefix in their path; every other source is
shared by all engines (no prefix).

A **view** is what one major sees: the shared occurrences plus its own `@<major>/` copies. Identity is not split:
the same text is the same rule version (content hash), the same logic is one logic group (logic hash), so the sid
map, verdicts and exclusions treat both copies as one rule. Only the choice of the text a build writes, the
validation of a version and the membership of a build are per view:

- validate: an engine checks the versions its major sees;
- index: `loads_in` / `fails_in` of an engine come from the canonical version of its major's view;
- profiles and releases for an engine select only logic groups its major sees and write that major's canonical text.

With one major (or a corpus without per-major copies) there are no views and nothing changes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sqlalchemy import select

from suriharvest.config import Settings, SourceConfig, version_tuple

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

PLACEHOLDER = "${suricata_version}"
PER_MAJOR_TYPES = ("http-tarball", "http-file")
_VARIANT = re.compile(r"@(\d+)/")


def major_of(version: str | None) -> str | None:
    v = version_tuple(version)
    return str(v[0]) if v else None


def engine_rulesets(settings: Settings) -> dict[str, str]:
    """Suricata major -> version to request for it, when the engines span more than one major; {} otherwise.
    The major of `ruleset_version` keeps that exact value; another major uses its newest engine's version."""
    best: dict[str, str] = {}
    for e in settings.engines:
        v = e.suricata_version
        m = major_of(v)
        if m is not None and v is not None and (m not in best or version_tuple(v) > version_tuple(best[m])):
            best[m] = v
    if len(best) < 2:
        return {}
    rs = major_of(settings.ruleset_version)
    if rs in best:
        best[rs] = settings.ruleset_version
    return dict(sorted(best.items(), key=lambda kv: int(kv[0])))


def source_rulesets(src: SourceConfig, settings: Settings) -> dict[str, str]:
    """major -> version for a source downloaded once per major; {} for a shared source (one download)."""
    if src.type not in PER_MAJOR_TYPES or PLACEHOLDER not in src.url:
        return {}
    return {m: v for m, v in engine_rulesets(settings).items() if src.enabled_for(v)}


def variant(path: str) -> str | None:
    """The major of a per-major occurrence path (`@8/rules/x.rules` -> "8"), None for a shared path."""
    m = _VARIANT.match(path)
    return m.group(1) if m else None


def strip_variant(path: str) -> str:
    m = _VARIANT.match(path)
    return path[m.end() :] if m else path


def _pick(available: list[str], major: str | None) -> str | None:
    """The copy an engine of `major` uses: its own, else the newest older one, else the oldest newer one."""
    if not available:
        return None
    nums = sorted(int(x) for x in available)
    if major is None:
        return str(nums[-1])
    want = int(major)
    if want in nums:
        return str(want)
    lower = [n for n in nums if n < want]
    return str(lower[-1] if lower else nums[0])


def variant_dir(root: Path, major: str | None) -> Path:
    """The folder of one major's copy inside a source folder (`root/@8`), or `root` for a shared source."""
    if not root.is_dir() or root.is_symlink():
        return root
    found = [d.name[1:] for d in root.iterdir() if d.is_dir() and not d.is_symlink() and re.fullmatch(r"@\d+", d.name)]
    m = _pick(found, major)
    return root / f"@{m}" if m is not None else root


@dataclass
class Pick:
    """The canonical version of a logic group in one view."""

    version_id: int
    source: str
    gid: int
    sid: int
    rev: int | None
    msg: str | None
    enabled: bool


@dataclass
class View:
    major: str
    versions: set[int] = field(default_factory=set)  # live version ids this major sees
    canonical: dict[str, Pick] = field(default_factory=dict)  # logic hash -> canonical version in this view

    def sees(self, logic_hash: str) -> bool:
        return logic_hash in self.canonical

    def sees_path(self, path: str) -> bool:
        v = variant(path)
        return v is None or v == self.major


def load_views(s: Session) -> dict[str, View]:
    """major -> View; {} when the corpus holds no per-major copy (every engine sees everything)."""
    from suriharvest.models import Occurrence, RuleVersion, Source

    live = (Occurrence.present.is_(True), Source.enabled.is_(True), Source.type.in_(PER_MAJOR_TYPES), Occurrence.path.like("@%"))
    q = select(Occurrence.path).join(Source, Source.id == Occurrence.source_id).where(*live).distinct()
    majors = sorted({m for (p,) in s.execute(q) if (m := variant(p)) is not None}, key=int)
    if not majors:
        return {}
    q2 = (
        select(
            Occurrence.version_id,
            Occurrence.path,
            Occurrence.enabled,
            Source.name,
            Source.priority,
            Source.type,
            RuleVersion.logic_hash,
            RuleVersion.gid,
            RuleVersion.sid,
            RuleVersion.rev,
            RuleVersion.msg,
        )
        .join(Source, Source.id == Occurrence.source_id)
        .join(RuleVersion, RuleVersion.id == Occurrence.version_id)
        .where(Occurrence.present.is_(True), Source.enabled.is_(True))
    )
    # per major and version: best (priority, source), enabled anywhere in the view
    seen: dict[str, dict[int, list[Any]]] = {m: {} for m in majors}
    facts: dict[int, tuple[str, int, int, int | None, str | None]] = {}
    for vid, path, enabled, name, prio, typ, lh, gid, sid, rev, msg in s.execute(q2):
        v = variant(path) if typ in PER_MAJOR_TYPES else None
        facts[vid] = (lh, gid, sid, rev, msg)
        for m in majors if v is None else ([v] if v in seen else []):
            cur = seen[m].get(vid)
            if cur is None:
                seen[m][vid] = [prio, name, bool(enabled)]
            else:
                cur[0], cur[1] = min((cur[0], cur[1]), (prio, name))
                cur[2] = cur[2] or bool(enabled)
    out: dict[str, View] = {}
    for m in majors:
        view = View(m, set(seen[m]))
        best: dict[str, tuple[Any, ...]] = {}
        for vid, (prio, name, enabled) in seen[m].items():
            lh, gid, sid, rev, msg = facts[vid]
            key = (prio, not enabled, -(rev or 0), vid)  # index._canonical: priority, enabled, newest rev, oldest id
            if lh not in best or key < best[lh][0]:
                best[lh] = (key, Pick(vid, name, gid, sid, rev, msg, enabled))
        view.canonical = {lh: p for lh, (_, p) in best.items()}
        out[m] = view
    return out


def view_for(views: dict[str, View], version: str | None) -> View | None:
    """The view an engine of this Suricata version uses (None without views; the newest for an unknown version)."""
    m = _pick(list(views), major_of(version))
    return views[m] if m is not None else None


def engine_version(s: Session, engine: str | None) -> str | None:
    """The Suricata version an engine reported in its newest validation, else the number in its name."""
    if not engine:
        return None
    from suriharvest.models import ValidationResult

    v = s.scalar(
        select(ValidationResult.engine_version)
        .where(ValidationResult.engine == engine)
        .order_by(ValidationResult.checked_at.desc())
        .limit(1)
    )
    if v:
        return v
    m = re.fullmatch(r"suricata-?(\d+(?:\.\d+)*)", engine)
    return m.group(1) if m else None


def view_of_engine(s: Session, engine: str | None, views: dict[str, View] | None = None) -> View | None:
    """The view of an engine (the newest major's view when no engine is named); None without per-major copies."""
    views = load_views(s) if views is None else views
    if not views:
        return None
    return view_for(views, engine_version(s, engine))


class Scoped:
    """A logic group as one view sees it: its canonical version, source, sid and revision come from the view."""

    __slots__ = ("_g", "_p")

    def __init__(self, g: Any, p: Pick) -> None:
        object.__setattr__(self, "_g", g)
        object.__setattr__(self, "_p", p)

    @property
    def canonical_version_id(self) -> int:
        return self._p.version_id

    @property
    def canonical_source(self) -> str:
        return self._p.source

    @property
    def gid(self) -> int:
        return self._p.gid

    @property
    def sid(self) -> int:
        return self._p.sid

    @property
    def rev(self) -> int | None:
        return self._p.rev

    @property
    def msg(self) -> str | None:
        return self._p.msg

    def __getattr__(self, name: str) -> Any:
        return getattr(self._g, name)


def scoped(g: Any, view: View | None) -> Any:
    """`g` as `view` sees it (unchanged without a view); None when the view does not see it."""
    if view is None or g is None:
        return g
    p = view.canonical.get(g.logic_hash)
    return Scoped(g, p) if p is not None else None
