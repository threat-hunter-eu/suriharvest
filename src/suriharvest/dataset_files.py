"""Dataset files that travel with the rules that load them (release, profile builds, export, web feed).

A rule with `dataset:`/`datarep:` options needs its `load`/`state` file next to the rule file on the sensor. Every
written ruleset uses one layout: the file of source S at path P is published as `datasets/S/P`, the rule's path is
rewritten to match, and the file is written next to the rules file (and next to `by-source/`). A rule is left out,
with its reason, when a path is absolute or escapes the source, when it `save`s a file on the sensor, when a value
cannot be read safely, or when the source does not ship the file.

Dataset names are global in Suricata: two rules that use one name with a different type or file make the whole rule
file fail to load ("load mismatch"). So one name keeps one definition per written ruleset: the first by source
priority (then source name, gid, sid) keeps the name, every other definition gets its own name
`<name>-<8 hex digits>` (stable: derived from the name, type and published file). Renames are reported.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from suriharvest.config import ConfigError, Workspace, load_sources, source_root
from suriharvest.validate import (
    _ds_args,
    _ds_options,
    _safe_rel,
    dataset_defs,
    dataset_paths,
    rename_datasets,
    rewrite_dataset_paths,
    rule_files,
)


class DatasetPacker:
    """Finds the files dataset rules load in their source and names them datasets/<source>/<path>."""

    def __init__(self, s: Session, ws: Workspace, configs: dict[str, Any] | None = None, major: str | None = None) -> None:
        if configs is None:
            try:
                configs = {c.name: c for c in load_sources(ws)}
            except ConfigError:
                configs = {}
        self.s, self.ws, self.configs = s, ws, configs
        self.major = major  # per-major copies (majors.py): look next to this major's rule files only
        self.content: dict[str, bytes] = {}  # published path -> content
        self._dirs: dict[str, list[str]] = {}
        self._found: dict[tuple[str, str], str | None] = {}

    def _rule_paths(self, src: str) -> list[str]:
        if src not in self._dirs:
            from suriharvest.models import Occurrence, Source

            paths = self.s.scalars(
                select(Occurrence.path)
                .join(Source, Source.id == Occurrence.source_id)
                .where(Source.name == src, Occurrence.present.is_(True))
                .distinct()
            )
            from suriharvest.majors import variant

            dirs = sorted({str(Path(p).parent) for p in paths if self.major is None or variant(p) in (None, self.major)})
            self._dirs[src] = [f"{d}/x.rules" for d in dirs] or ["x.rules"]
        return self._dirs[src]

    def publish(self, src: str, rel: str) -> str | None:
        """The published path of file `rel` of source `src`, or None when the source does not ship it."""
        key = (src, rel)
        if key not in self._found:
            self._found[key] = None
            root = source_root(self.ws, src, self.configs.get(src))
            for rule_path in self._rule_paths(src):
                found = rule_files(root, rule_path, [rel]).get(rel)
                if found is not None:
                    name = f"datasets/{src}/{rel.removeprefix('./')}"
                    self.content[name] = found.read_bytes()
                    self._found[key] = name
                    break
        return self._found[key]


@dataclass
class Shipped:
    texts: dict[str, str] = field(default_factory=dict)  # key -> rule text to write (left-out rules are absent)
    files: dict[str, bytes] = field(default_factory=dict)  # published path -> content (only files a kept rule loads)
    left_out: list[dict[str, Any]] = field(default_factory=list)  # {key, source, reason}
    renamed: list[dict[str, Any]] = field(default_factory=list)  # {key, source, dataset, renamed_to, reason}


def _why(text: str, src: str, packer: DatasetPacker | None) -> str:
    for _, _, value in _ds_options(text):
        if any(c in value for c in "\\\"'"):
            return "dataset option with quotes or escapes (cannot be read safely)"
        for arg, path in _ds_args(value):
            if arg == "save":
                return "rule writes a dataset file on the sensor (save)"
            if not _safe_rel(path):
                return f"dataset file path {path!r} is absolute or outside the source"
            if packer is None:
                return f"needs dataset file {path} (not shipped by this export)"
            if packer.publish(src, path) is None:
                return f"dataset file {path} is not shipped by source {src}"
    return "dataset file not available"


def ship(rules: Iterable[tuple[str, str, str]], packer: DatasetPacker | None) -> Shipped:
    """rules: (key, source, text) in priority order (best first). Rules without dataset options pass unchanged."""
    out = Shipped()
    holders: dict[str, tuple[str | None, str | None]] = {}  # dataset name in the output -> (type, file)
    for key, src, text in rules:
        if not dataset_paths(text) and not dataset_defs(text):
            out.texts[key] = text
            continue
        new = rewrite_dataset_paths(text, lambda rel, src=src: packer.publish(src, rel)) if packer is not None else None
        if new is None and dataset_paths(text):
            out.left_out.append({"key": key, "source": src, "reason": _why(text, src, packer)})
            continue
        new = new if new is not None else text

        def name_for(name: str, typ: str | None, path: str | None, key: str = key, src: str = src) -> str:
            sig = (typ, path)
            cur = name
            n = 8
            while cur in holders and holders[cur] != sig:
                digest = hashlib.sha256(f"{name}\t{typ}\t{path}".encode()).hexdigest()
                cur = f"{name}-{digest[:n]}"
                n += 4
            holders.setdefault(cur, sig)
            if cur != name:
                out.renamed.append(
                    {
                        "key": key,
                        "source": src,
                        "dataset": name,
                        "renamed_to": cur,
                        "reason": f"dataset name {name!r} already defined with another type or file by a rule of higher priority",
                    }
                )
            return cur

        out.texts[key] = rename_datasets(new, name_for)
        for p in dataset_paths(out.texts[key]):
            if packer is not None and p in packer.content:
                out.files[p] = packer.content[p]
    return out


def strip_dataset_rules(text: str) -> tuple[str, int]:
    """A single rules file cannot carry dataset files: drop the rules that load one (with a note). Returns the text
    and how many rules were dropped. Use the zip / feed download to get them with their files."""
    keep, n = [], 0
    for line in text.splitlines(keepends=True):
        if not line.lstrip().startswith("#") and dataset_paths(line):
            n += 1
            continue
        keep.append(line)
    if n:
        keep.insert(0, f"# {n} rules that load dataset files are left out of this single file: download the zip or use the feed\n")
    return "".join(keep), n


def dataset_tree(folder: Path) -> list[tuple[str, Path]]:
    """(published path, file) of every dataset file an export or build wrote (datasets/<source>/...)."""
    base = folder / "datasets"
    if not base.is_dir():
        return []
    return [(f.relative_to(folder).as_posix(), f) for f in sorted(base.rglob("*")) if f.is_file() and not f.is_symlink()]
