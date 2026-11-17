"""Ruleset downloads of the web UI, built in a short-lived child process.

An export of tens of thousands of rules takes seconds of CPU and a few hundred MB. Run inside the server it held the
GIL (light pages slowed down) and the memory stayed with the server process after the download. Here every build
runs in a fresh process (spawn, one task per process) that writes the file into a temporary folder and exits, so
the memory goes back to the operating system; the server only streams the finished file.

The functions below are top level (picklable) and take plain values: paths as strings, lists of hashes.
"""

from __future__ import annotations

import multiprocessing
import os
import shutil
import tarfile
import zipfile
from collections.abc import Callable
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any, TypeVar

T = TypeVar("T")

# SURIHARVEST_WEB_INPROCESS=1 builds downloads in the server process (debugging; no isolation).
INPROCESS_ENV = "SURIHARVEST_WEB_INPROCESS"


def run_isolated(fn: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    """fn(*args, **kwargs) in a fresh child process that exits afterwards. Exceptions come back as raised by fn."""
    if os.environ.get(INPROCESS_ENV) == "1":
        return fn(*args, **kwargs)
    ctx = multiprocessing.get_context("spawn")
    with ProcessPoolExecutor(max_workers=1, mp_context=ctx, max_tasks_per_child=1) as pool:
        return pool.submit(fn, *args, **kwargs).result()


def _export(ws_root: str, tmp: Path, hashes: list[str], *, fmt: str, share: bool, remap: bool) -> Path:
    """Export into tmp/out (dataset files under tmp/out/datasets/); the workspace sid map is never written."""
    from suriharvest.config import Workspace
    from suriharvest.db import session_factory
    from suriharvest.export import export

    ws = Workspace(Path(ws_root))
    smap = tmp / "sid-map.tsv"
    if ws.sid_map_file.exists():
        shutil.copy(ws.sid_map_file, smap)  # a download never writes the workspace sid map
    with session_factory(ws.db_path)() as s:
        export(
            s,
            tmp / "out",
            logic_hashes=hashes,
            remap_sids=remap,
            remap_base=ws.settings().remap_base,
            sid_map=smap,
            redistributable_only=share,
            iocs_as_datasets=(fmt == "datasets"),
            split_by_source=(fmt == "zip"),
            ws=ws,
        )
    return tmp / "out"


def _strip_to(src: Path, dest: Path) -> None:
    """The rules of src without those that load dataset files (a single file cannot carry them)."""
    from suriharvest.dataset_files import strip_dataset_rules

    body, _ = strip_dataset_rules(src.read_text(encoding="utf-8"))
    dest.write_bytes(body.encode("utf-8"))


def build_export(ws_root: str, hashes: list[str], fmt: str, share: bool, remap: bool, label: str, *, tmp: str) -> tuple[str, str]:
    """A search / selection download: (file path, media type) inside tmp."""
    from suriharvest.dataset_files import dataset_tree

    t = Path(tmp)
    out = _export(ws_root, t, hashes, fmt=fmt, share=share, remap=remap)
    if fmt in ("zip", "datasets"):
        dest, media = t / f"{label}.zip", "application/zip"
        with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
            if fmt == "zip":
                for f in sorted((out / "by-source").glob("*.rules")):
                    zf.write(f, f"{label}/{f.name}")
                for rel, f in dataset_tree(out):  # relative loads resolve next to the rule files
                    zf.write(f, f"{label}/{rel}")
                zf.write(out / "manifest.jsonl", f"{label}/manifest.jsonl")
            else:
                for f in sorted(out.rglob("*")):
                    if f.is_file():
                        zf.write(f, f"{label}/{f.relative_to(out)}")
    else:
        dest, media = t / f"{label}.rules", "text/plain; charset=utf-8"
        _strip_to(out / "suricata.rules", dest)
    shutil.rmtree(out, ignore_errors=True)
    return str(dest), media


def build_stripped(src: str, label: str, *, tmp: str) -> str:
    """A profile build's suricata.rules without the dataset-loading rules."""
    dest = Path(tmp) / f"{label}.rules"
    _strip_to(Path(src), dest)
    return str(dest)


def build_feed(ws_root: str, build_path: str, keep: list[str] | None, notice: str, epoch: int, name: str, *, tmp: str) -> str:
    """The suricata-update tarball of a build: the build's own files when `keep` is None (every rule loads),
    else a fresh export of `keep`. Members are written from files, never held in memory as a whole."""
    from suriharvest.dataset_files import dataset_tree

    t = Path(tmp)
    folder = Path(build_path) if keep is None else _export(ws_root, t, keep, fmt="rules", share=False, remap=True)
    notice_file = t / "NOTICE.md"
    notice_file.write_bytes(notice.encode("utf-8"))
    dest = t / name
    members = [("rules/suricata.rules", folder / "suricata.rules"), *((f"rules/{rel}", f) for rel, f in dataset_tree(folder))]
    members.append(("NOTICE.md", notice_file))
    with tarfile.open(dest, mode="w:gz") as tf:
        for arc, f in members:
            info = tarfile.TarInfo(arc)
            info.size, info.mtime, info.mode = f.stat().st_size, epoch, 0o644
            with f.open("rb") as fh:
                tf.addfile(info, fh)
    return str(dest)
