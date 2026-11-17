"""Release extras: merged classification/reference config and `duplicate_of` manifest rows.

classification.config / reference.config (in suriharvest-N.tar.gz under rules/): Suricata's default entries, then
the entries of every `classification.config` / `reference.config` the sources in the build ship (sources in the order
given, i.e. by source priority; the first definition of a name wins, so a source can add names but not redefine the
defaults nor another, higher-priority source's classtype: such conflicts are reported), then a
plain entry for any classtype a published rule uses that no file defines. Lines are validated and normalised, so a
source cannot inject anything but well-formed config lines. Output is sorted by origin and stable.

Duplicates: a published logic (one rule in the build) can be carried by other rules with a different gid:sid
(publishers sometimes duplicate their own rules; forks renumber). Those rules are left out of the build and listed
in the manifest with `excluded_reason: duplicate` and `duplicate_of: "<gid>:<exported sid>"`.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from suriharvest.models import LogicGroup, Occurrence, RuleVersion, Source

MAX_CONFIG_FILES = 20  # per source
MAX_CONFIG_BYTES = 256 * 1024

# Suricata's reference.config defaults (the entries every Suricata install knows).
DEFAULT_REFERENCES: tuple[tuple[str, str], ...] = (
    ("bugtraq", "http://www.securityfocus.com/bid/"),
    ("bid", "http://www.securityfocus.com/bid/"),
    ("cve", "http://cve.mitre.org/cgi-bin/cvename.cgi?name="),
    ("secunia", "http://www.secunia.com/advisories/"),
    ("arachNIDS", "http://www.whitehats.com/info/IDS"),
    ("McAfee", "http://vil.nai.com/vil/content/v_"),
    ("nessus", "http://cgi.nessus.org/plugins/dump.php3?id="),
    ("url", "http://"),
    ("et", "http://doc.emergingthreats.net/"),
    ("telus", "http://"),
    ("osvdb", "http://osvdb.org/show/osvdb/"),
    ("threatexpert", "http://www.threatexpert.com/report.aspx?md5="),
    ("md5", "http://www.threatexpert.com/report.aspx?md5="),
    ("exploitdb", "http://www.exploit-db.com/exploits/"),
    ("openpacket", "https://www.openpacket.org/capture/grab/"),
    ("securitytracker", "http://securitytracker.com/id?"),
    ("xforce", "http://xforce.iss.net/xforce/xfdb/"),
    ("msft", "http://technet.microsoft.com/security/bulletin/"),
)

_CLASS_RX = re.compile(r"^\s*config\s+classification\s*:\s*([A-Za-z0-9_.-]{1,64})\s*,\s*([^,\r\n]{0,200}?)\s*,\s*(\d{1,3})\s*$")
_REF_RX = re.compile(r"^\s*config\s+reference\s*:\s*([A-Za-z0-9_.-]{1,64})\s+(\S{1,300})\s*$")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_NO_MARKUP = str.maketrans("", "", "<>\"'`\\")


def _config_files(root: Path, name: str) -> list[Path]:
    if not root.is_dir() or root.is_symlink():
        return []
    found = sorted(p for p in root.rglob(name) if p.is_file() and not p.is_symlink() and p.stat().st_size <= MAX_CONFIG_BYTES)
    return found[:MAX_CONFIG_FILES]


def _lines(roots: Iterable[tuple[str, Path]], name: str) -> Iterable[tuple[str, str]]:
    for src, root in roots:
        for f in _config_files(root, name):
            for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
                yield src, line


def _safe_ref_url(url: str) -> bool:
    if any(c in url for c in "\"'<>\\`"):
        return False
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    return parts.scheme in ("http", "https") and bool(parts.hostname)


def merged_configs(
    roots: list[tuple[str, Path]],
    classtypes_used: Iterable[str | None],
    refs_used: dict[str, set[str]] | None = None,
    conflicts: list[dict[str, Any]] | None = None,
) -> dict[str, bytes]:
    """{"classification.config": ..., "reference.config": ...} for the given (source name, source root) pairs.

    reference.config: Suricata's defaults are the base and cannot be redefined. A source's own definition is taken
    only for a system its own published rules reference (`refs_used`: source -> lower-case system names), only with
    an http(s) URL, and a system that two sources define differently is dropped.

    classification.config: `roots` in priority order (best first); a classtype keeps the first source definition, a
    different definition by a later source is ignored and appended to `conflicts`.
    """
    from suriharvest.web.ui import CLASSTYPES

    classes: dict[str, tuple[str, int, str]] = {k.lower(): (k, *v, "suricata") for k, v in CLASSTYPES.items()}
    for src, line in _lines(roots, "classification.config"):
        m = _CLASS_RX.match(line)
        if not m or not 0 < int(m.group(3)) < 256:
            continue
        entry = (m.group(1), _CTRL.sub("", m.group(2)).translate(_NO_MARKUP), int(m.group(3)), src)
        cur = classes.get(entry[0].lower())
        if cur is None:
            classes[entry[0].lower()] = entry
        elif conflicts is not None and cur[3] not in ("suricata", src) and cur[1:3] != entry[1:3]:
            conflicts.append(
                {
                    "classtype": entry[0],
                    "kept": cur[3],
                    "kept_definition": f"{cur[1]},{cur[2]}",
                    "ignored": src,
                    "ignored_definition": f"{entry[1]},{entry[2]}",
                }
            )
    for c in sorted({c for c in classtypes_used if c}):
        if re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", c) and c.lower() not in classes:
            classes[c.lower()] = (c, c, 3, "used by a rule, defined nowhere")
    refs: dict[str, tuple[str, str, str]] = {k.lower(): (k, v, "suricata") for k, v in DEFAULT_REFERENCES}
    refs_used = refs_used or {}
    claims: dict[str, dict[str, tuple[str, str]]] = {}  # system -> source -> (name, url)
    for src, line in _lines(roots, "reference.config"):
        m = _REF_RX.match(line)
        if not m or not _safe_ref_url(m.group(2)):
            continue
        key = m.group(1).lower()
        if key in refs or key not in refs_used.get(src, set()):
            continue
        claims.setdefault(key, {}).setdefault(src, (m.group(1), m.group(2)))
    for key in sorted(claims):
        by_src = claims[key]
        if len({url for _, url in by_src.values()}) == 1:  # one definition (several sources may agree)
            src = min(by_src)
            refs[key] = (by_src[src][0], by_src[src][1], src)

    head = "# Merged by suriharvest: Suricata's defaults, then the files shipped by: " + (", ".join(s for s, _ in roots) or "-")
    cls = [head + "\n# config classification: shortname,description,priority\n"]
    origin = ""
    for name, desc, prio, src in classes.values():
        if src != origin:
            cls.append(f"\n# {src}\n")
            origin = src
        cls.append(f"config classification: {name},{desc},{prio}\n")
    ref = [head + "\n# config reference: system url\n"]
    origin = ""
    for name, url, src in refs.values():
        if src != origin:
            ref.append(f"\n# {src}\n")
            origin = src
        ref.append(f"config reference: {name} {url}\n")
    return {"classification.config": "".join(cls).encode(), "reference.config": "".join(ref).encode()}


def classtypes_of(s: Session, logic_hashes: set[str]) -> set[str]:
    return {c for h, c in s.execute(select(LogicGroup.logic_hash, LogicGroup.classtype)) if h in logic_hashes and c}


def references_by_source(s: Session, rows: list[dict[str, Any]]) -> dict[str, set[str]]:
    """source -> reference systems (lower case) used by that source's published rules."""
    src_of = {r["logic_hash"]: r["source"] for r in rows}
    out: dict[str, set[str]] = {}
    q = select(LogicGroup.logic_hash, RuleVersion.references).join(RuleVersion, RuleVersion.id == LogicGroup.canonical_version_id)
    for h, refs in s.execute(q):
        src = src_of.get(h)
        if src is None:
            continue
        for ref in refs or []:
            system = str(ref).split(",", 1)[0].strip().lower()
            if system:
                out.setdefault(src, set()).add(system)
    return out


def duplicate_rows(
    s: Session, engine: str, rows: list[dict[str, Any]], sources: set[str], major: str | None = None
) -> list[dict[str, Any]]:
    """Manifest rows for live rules with the logic of a published rule but another gid:sid.

    Only copies in `sources` (the sources in this engine's build, already limited to redistributable ones when the
    build is) are listed, so the manifest never names a rule of a source that is not published; with per-major
    copies (majors.py) only those of the engine's `major`."""
    published = {r["logic_hash"]: r for r in rows}
    found: dict[tuple[str, int, int], dict[str, Any]] = {}
    q = (
        select(RuleVersion.logic_hash, RuleVersion.gid, RuleVersion.sid, RuleVersion.rev, Source.name, Source.type, Occurrence.path)
        .join(Occurrence, Occurrence.version_id == RuleVersion.id)
        .join(Source, Source.id == Occurrence.source_id)
        .where(Occurrence.present.is_(True), Source.enabled.is_(True))
    )
    from suriharvest.majors import PER_MAJOR_TYPES, variant

    for h, gid, sid, rev, src, typ, path in s.execute(q):
        if major is not None and typ in PER_MAJOR_TYPES and variant(path) not in (None, major):
            continue  # another major's copy (majors.py)
        pub = published.get(h)
        if src not in sources or pub is None or (gid, sid) == (pub["gid"], pub["sid"]):
            continue
        key = (h, gid, sid)
        cur = found.get(key)
        if cur is None:
            found[key] = cur = {
                "engine": engine,
                "gid": gid,
                "sid": sid,
                "exported_sid": None,
                "rev": rev,
                "source": src,
                "logic_hash": h,
                "duplicate_of": f"{pub['gid']}:{pub['exported_sid']}",
                "excluded_reason": "duplicate",
            }
        else:
            revs = [x for x in (cur["rev"], rev) if x is not None]
            cur["rev"] = max(revs) if revs else None
            cur["source"] = min(cur["source"], src)
    return sorted(found.values(), key=lambda r: (r["gid"], r["sid"], r["logic_hash"]))
