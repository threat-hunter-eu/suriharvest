"""Who owns a sid: the public allocation table of https://sidallocation.org/ (snapshot 2026-11).

A rule whose sid falls in a publisher's allocated range gets that publisher's namespace, so the same rule carried by
a mirror, a fork or a bundle is recognised as the same rule (rule key `namespace:gid:sid`; rev orders the revisions
of one lineage, across sources ownership then priority decide: profiles.pick_revisions). Some publishers also
require a name prefix, because their ranges are shared with unrelated rules in the wild (ET: "ET " / "GPL ").
Rules outside every range, or in the local range 1,000,000-1,999,999, keep the namespace of their source. Ranges
from unrelated publishers that squat an allocation do not merge with the owner: the rule-key clustering marks such
keys ambiguous (different logic and names).

Keep this table in sync with sidallocation.org; remapped sids (sidmap.py) must stay outside every range here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import cache
from pathlib import Path


@dataclass(frozen=True)
class Allocation:
    first: int
    last: int
    namespace: str
    owner: str
    msg: re.Pattern[str] | None = None  # the rule name must match too (shared/busy ranges)


_ET = re.compile(r"^(ET|GPL) ")

ALLOCATIONS: tuple[Allocation, ...] = (
    Allocation(2_000_000, 2_103_999, "et", "Emerging Threats Open", _ET),
    Allocation(2_200_000, 2_299_999, "oisf", "OISF (Suricata engine events)", re.compile(r"^SURICATA ")),
    Allocation(2_400_000, 2_609_999, "et", "Emerging Threats Open", _ET),
    Allocation(2_610_000, 2_619_999, "tgreen", "Travis Green (hunting rules)"),
    Allocation(2_700_000, 2_799_999, "et", "Emerging Threats Open", _ET),
    Allocation(2_800_000, 2_899_999, "et-commercial", "Emerging Threats commercial ruleset", _ET),
    Allocation(3_000_000, 3_099_999, "vendor-3.0m", "network sensor vendor (3.0M)"),
    Allocation(3_100_000, 3_199_999, "stamus", "Stamus Networks"),
    Allocation(3_200_000, 3_299_999, "dcso", "DCSO"),
    Allocation(3_300_000, 3_399_999, "pawpatrules", "PAW Patrules"),
    Allocation(3_400_000, 3_499_999, "aleksibovellan", "Aleksi Bovellan"),
    Allocation(3_500_000, 3_509_999, "hunters-ledger", "The Hunters Ledger"),
    Allocation(3_600_000, 3_609_999, "echap", "Echap"),
    Allocation(3_700_000, 3_799_999, "dersec", "DERSec"),
    Allocation(4_000_000, 4_099_999, "extrahop", "ExtraHop"),
    Allocation(4_100_000, 4_199_999, "bizone", "BI.ZONE"),
    Allocation(4_200_000, 4_299_999, "vectra", "Vectra"),
    Allocation(5_000_000, 5_000_213, "etnetera", "Etnetera"),
    Allocation(6_000_000, 6_099_999, "julioliraup", "julioliraup (Antiphishing)"),
    Allocation(8_000_000, 8_003_000, "vendor-8.0m", "endpoint vendor (8.0M)"),
    Allocation(9_555_000, 9_954_999, "wybot", "Wybot"),
    Allocation(10_000_000, 11_999_999, "ptsecurity", "Positive Technologies"),
    Allocation(12_000_000, 12_999_999, "ipfire", "IPFire"),
    Allocation(80_000_000, 89_999_999, "abuse.ch-urlhaus", "abuse.ch URLhaus"),
    Allocation(90_000_000, 99_999_999, "abuse.ch-threatfox", "abuse.ch ThreatFox"),
    Allocation(100_000_000, 199_999_999, "et", "Emerging Threats Open", _ET),
    Allocation(900_500_000, 900_700_000, "abuse.ch-feodo", "abuse.ch Feodo Tracker"),
    Allocation(902_200_000, 906_200_000, "abuse.ch-sslbl", "abuse.ch SSLBL"),
)

LOCAL_RANGE = range(1_000_000, 2_000_000)  # for local rules: never a publisher, never a remap target


def owner(gid: int, sid: int, msg: str | None) -> Allocation | None:
    """The allocation a gid 1 rule belongs to, when its sid (and name, where required) matches one."""
    if gid != 1:
        return None
    for a in ALLOCATIONS:
        if a.first <= sid <= a.last:
            if a.msg is not None and not a.msg.match(msg or ""):
                return None
            return a
    return None


REGISTRY = Path(__file__).parent / "catalog" / "sid-allocation.tsv"


@cache
def registry_ranges() -> tuple[tuple[int, int, str], ...]:
    """Every allocated range of the shipped sidallocation.org copy (plus the table above), sorted."""
    out = {(a.first, a.last, a.owner) for a in ALLOCATIONS}
    if REGISTRY.exists():
        for line in REGISTRY.read_text(encoding="utf-8").splitlines():
            parts = line.split("\t")
            if len(parts) >= 3 and parts[0].isdigit() and parts[1].isdigit():
                out.add((int(parts[0]), int(parts[1]), parts[2]))
    out.add((LOCAL_RANGE.start, LOCAL_RANGE.stop - 1, "local"))
    return tuple(sorted(out))


def allocated(sid: int) -> bool:
    """Is sid inside an allocated range or the local range (a remapped sid must never be)?"""
    return any(a <= sid <= b for a, b, _ in registry_ranges())


def overlapping(first: int, last: int) -> list[str]:
    """Owners of allocated ranges that overlap [first, last]."""
    return [f"{o} ({a:,}-{b:,})" for a, b, o in registry_ranges() if a <= last and first <= b]


def next_unallocated(sid: int) -> int:
    """The first sid >= `sid` outside every allocated range and the local range."""
    moved = True
    while moved:
        moved = False
        for a, b, _ in registry_ranges():
            if a <= sid <= b:
                sid, moved = b + 1, True
    return sid
