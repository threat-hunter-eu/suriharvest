"""Extra export formats.

suricata-update - rules from sources suricata-update already fetches (those that came from the OISF index) are not
                  copied; triage verdicts on them become enable.conf / disable.conf. Every other selected rule goes
                  to suriharvest-local.rules for `suricata-update --local`.
IOC datasets    - single-indicator rules (domains on dns.query / tls.sni / http.host / quic.sni, ja3 / ja3s hashes)
                  are replaced by one dataset file per buffer plus one rule each, and iocs.jsonl maps every
                  indicator back to the rules it came from (for alert enrichment). Datasets match exact values:
                  rules that matched subdomains (endswith/dotprefix) are counted as narrowed in the report.
"""

from __future__ import annotations

import base64
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from suriharvest.db import in_list
from suriharvest.models import LogicGroup, RuleVersion, Source

_LINE_BREAKS = re.compile(r"[\x00-\x1f\x7f\x85\u2028\u2029]")

DATASET_BUFFERS = {
    # buffer -> (dataset type, transform, file encoding)
    "dns.query": ("string", "to_lowercase; ", "base64"),
    "tls.sni": ("string", "to_lowercase; ", "base64"),
    "http.host": ("string", "to_lowercase; ", "base64"),
    "quic.sni": ("string", "to_lowercase; ", "base64"),
    "ja3.hash": ("md5", "", "hex"),
    "ja3s.hash": ("md5", "", "hex"),
}
RULE_PROTO = {"dns.query": "dns", "tls.sni": "tls", "http.host": "http", "quic.sni": "quic", "ja3.hash": "tls", "ja3s.hash": "tls"}


@dataclass
class DatasetReport:
    replaced_rules: int = 0
    indicators: dict[str, int] = field(default_factory=dict)  # buffer -> unique values
    narrowed: int = 0  # rules that matched subdomains; the dataset matches the exact name only
    rules_written: int = 0


def ioc_datasets(s: Session, groups: list[LogicGroup], out_dir: Path, sid_base: int) -> tuple[list[LogicGroup], DatasetReport]:
    """Write datasets/ + datasets.rules for the IOC rules among `groups`. Returns the groups that stay rules."""
    rep = DatasetReport()
    keep: list[LogicGroup] = []
    values: dict[str, dict[str, list[dict]]] = defaultdict(dict)
    vids = {g.canonical_version_id for g in groups if g.is_ioc}
    raws = dict(s.execute(select(RuleVersion.id, RuleVersion.raw).where(in_list(RuleVersion.id, vids))).all()) if vids else {}
    for g in groups:
        buf = g.buffers[0] if g.is_ioc and len(g.buffers) == 1 else None
        if buf not in DATASET_BUFFERS or g.ioc_type not in ("domain", "ja3", "ja3s") or not g.ioc_value:
            keep.append(g)
            continue
        raw = raws.get(g.canonical_version_id, "")
        if "endswith" in raw or "dotprefix" in raw or "pcre" in raw:
            rep.narrowed += 1
        values[buf].setdefault(g.ioc_value, []).append(
            {"sid": g.sid, "gid": g.gid, "msg": g.msg, "source": g.canonical_source, "logic_hash": g.logic_hash}
        )
        rep.replaced_rules += 1
    if not values:
        return keep, rep
    ds_dir = out_dir / "datasets"
    ds_dir.mkdir(parents=True, exist_ok=True)
    rules = []
    with (ds_dir / "iocs.jsonl").open("w", encoding="utf-8", newline="\n") as fm:
        for i, (buf, vals) in enumerate(sorted(values.items())):
            dtype, transform, enc = DATASET_BUFFERS[buf]
            name = "suriharvest-" + buf.replace(".", "-")
            lines = []
            for v in sorted(vals):
                lines.append(base64.b64encode(v.encode()).decode() if enc == "base64" else v.lower())
                fm.write(json.dumps({"dataset": name, "buffer": buf, "value": v, "rules": vals[v]}) + "\n")
            (ds_dir / f"{name}.lst").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
            rep.indicators[buf] = len(vals)
            rules.append(
                f'alert {RULE_PROTO[buf]} any any -> any any (msg:"suriharvest IOC list {buf} ({len(vals)} indicators, see iocs.jsonl)"; '
                f"{buf}; {transform}dataset:isset,{name},type {dtype},load datasets/{name}.lst; "
                f"classtype:trojan-activity; sid:{sid_base + i}; rev:1; metadata:suriharvest ioc_dataset;)"
            )
    (out_dir / "datasets.rules").write_text("\n".join(rules) + "\n", encoding="utf-8", newline="\n")
    rep.rules_written = len(rules)
    return keep, rep


@dataclass
class SuricataUpdateReport:
    managed_sources: list[str] = field(default_factory=list)
    local_rules: int = 0
    enabled: int = 0
    disabled: int = 0
    unmapped: list[str] = field(default_factory=list)  # sources in suriharvest-local.rules with no OISF mapping
    et_unmanaged: bool = False  # ET Open is in suriharvest-local.rules: suricata-update's default et/open duplicates it
    disable_skipped: list[str] = field(default_factory=list)  # gid:sid kept by another selected rule: not disabled


def suricata_update_files(
    s: Session,
    out_dir: Path,
    picked: list[LogicGroup],
    managed: set[str] | dict[str, str],
    raws: dict[int, str],
    excluded: list | None = None,
) -> SuricataUpdateReport:
    """enable.conf / disable.conf from verdicts on managed sources and, with a profile, from the rules its
    exclusions leave out (`excluded`: rows with gid, sid, msg, canonical_source); the rest of `picked` into
    suriharvest-local.rules. `managed` may map each source to its OISF index name (shown in README.txt)."""
    oisf = managed if isinstance(managed, dict) else {}
    rep = SuricataUpdateReport(managed_sources=sorted(managed))
    local = [g for g in picked if g.canonical_source not in managed]
    out_dir.mkdir(parents=True, exist_ok=True)
    with (out_dir / "suriharvest-local.rules").open("w", encoding="utf-8", newline="\n") as f:
        f.write("# suriharvest: selected rules from sources suricata-update does not fetch\n")
        for g in sorted(local, key=lambda g: (g.gid, g.sid)):
            f.write(raws[g.canonical_version_id] + "\n")
    rep.local_rules = len(local)
    on_managed = (
        list(s.scalars(select(LogicGroup).where(in_list(LogicGroup.canonical_source, managed), LogicGroup.verdict.is_not(None))))
        if managed
        else []
    )
    enable = sorted({(g.gid, g.sid, g.msg or "") for g in on_managed if g.verdict == "keep" and not g.enabled_anywhere})
    # Every rule the profile leaves out goes to disable.conf, whatever its source: suricata-update may fetch the same
    # rule from a source of its own (et/open is enabled by default) and would otherwise turn it back on. A gid:sid
    # that another selected rule uses is not disabled (it would switch that rule off too) and is reported.
    kept = {(g.gid, g.sid) for g in picked}
    wanted = {(g.gid, g.sid, g.msg or "") for g in on_managed if g.verdict == "drop"} | {
        (g.gid, g.sid, g.msg or "") for g in (excluded or [])
    }
    disable = sorted(x for x in wanted if (x[0], x[1]) not in kept)
    rep.disable_skipped = sorted({f"{gid}:{sid}" for gid, sid, _ in wanted if (gid, sid) in kept})
    rep.unmapped = sorted({g.canonical_source for g in local})
    if rep.unmapped:
        ns = dict(s.execute(select(Source.name, Source.sid_namespace).where(in_list(Source.name, rep.unmapped))).all())
        rep.et_unmanaged = any(ns.get(n) == "et" for n in rep.unmapped)
    head = "# Generated by suriharvest from triage verdicts and profile exclusions. One gid:sid per line; the comment is the rule's msg.\n"

    def _one_line(msg: str) -> str:
        # suricata-update reads these files with universal newlines: a CR (or any other line break) in a third-party
        # msg would start a new matcher line, e.g. "*" disables every rule.
        return _LINE_BREAKS.sub(" ", msg)

    (out_dir / "enable.conf").write_text(
        head + "".join(f"{gid}:{sid}  # {_one_line(msg)}\n" for gid, sid, msg in enable), encoding="utf-8", newline="\n"
    )
    (out_dir / "disable.conf").write_text(
        head + "".join(f"{gid}:{sid}  # {_one_line(msg)}\n" for gid, sid, msg in disable), encoding="utf-8", newline="\n"
    )
    rep.enabled, rep.disabled = len(enable), len(disable)
    warn = ""
    if rep.et_unmanaged:
        warn = (
            "\nET Open is in suriharvest-local.rules. suricata-update enables et/open by default: run\n"
            "  suricata-update disable-source et/open\n"
            "or it is loaded twice (disable.conf still switches your excluded rules off in both copies).\n"
        )
    fetched = [f"{n} (suricata-update name {oisf[n]})" if oisf.get(n) else n for n in rep.managed_sources]
    (out_dir / "README.txt").write_text(
        "Use with suricata-update (it keeps fetching " + (", ".join(fetched) or "its own sources") + "):\n\n"
        "  suricata-update --local suriharvest-local.rules --enable-conf enable.conf --disable-conf disable.conf\n\n"
        "enable.conf turns on rules you kept that their publisher ships disabled; disable.conf turns off every rule\n"
        "your profile leaves out (and rules you triaged as drop), whichever source suricata-update gets them from.\n" + warn,
        encoding="utf-8",
        newline="\n",
    )
    return rep


def managed_sources(s: Session, oisf_names: dict[str, str | None]) -> dict[str, str]:
    """Enabled sources that came from the OISF index (suricata-update fetches them itself): suriharvest name -> OISF
    index name."""
    names = set(s.scalars(select(Source.name).where(Source.enabled.is_(True))))
    return {n: oisf for n in sorted(names) if (oisf := oisf_names.get(n))}
