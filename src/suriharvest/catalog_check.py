"""Catalog health: compare a source catalog with the OISF suricata-update index and check that sources answer.

Used by `suriharvest sources check` (and scripts/refresh_catalog.py). Never edits the catalog: a human reviews
licences before a source is added or its redistribute/status/tier changes. The health file it writes is
deterministic (sorted, no timestamps), so a quiet week gives an empty diff.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from suriharvest.config import CATALOG, SYNCED_STATUSES

INDEX_URL = "https://www.openinfosecfoundation.org/rules/index.yaml"
USER_AGENT = "suriharvest-catalog-check"
# Listed in the OISF index but not usable without a personal key (or gone): never proposed.
SKIP = {
    "abuse.ch/urlhaus": "download answers HTTP 410; the feed now needs an abuse.ch Auth-Key",
    "abuse.ch/threatfox": "needs an abuse.ch Auth-Key",
}


def free_oisf_sources(index: dict) -> dict[str, dict]:
    out = {}
    for key, src in (index.get("sources") or {}).items():
        if key in SKIP or src.get("parameters") or str(src.get("license", "")).lower() == "commercial":
            continue
        out[key] = src
    return out


def _norm_url(url: str) -> str:
    """Comparable form of a source URL: version placeholders unified, scheme/host lower case, no trailing slash."""
    u = url.strip().replace("%(__version__)s", "{v}").replace("${suricata_version}", "{v}").rstrip("/")
    m = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*://[^/]+)(.*)$", u)
    return (m.group(1).lower() + m.group(2)) if m else u


def _oisf_key_for(entry: dict, oisf: dict[str, dict], index: dict[str, dict]) -> str | None:
    """The OISF index key of a catalog entry: its `oisf_name`, else the index entry with the same URL (a live one
    first: the index keeps deprecated aliases of some URLs)."""
    if entry.get("oisf_name"):
        return entry["oisf_name"]
    url = _norm_url(str(entry.get("url", "")))
    same = [k for k, v in sorted(index.items()) if _norm_url(str(v.get("url", ""))) == url]
    live = [k for k in same if k in oisf and not (index[k].get("obsolete") or index[k].get("deprecated"))]
    return (live or same or [None])[0]


def catalog_entry(key: str, src: dict) -> dict:
    url = src["url"].replace("%(__version__)s", "${suricata_version}")
    kind = "http-tarball" if url.lower().split("?")[0].endswith((".tar.gz", ".tgz", ".tar")) else "http-file"
    entry = {
        "name": key.replace("/", "-"),
        "type": kind,
        "url": url,
        "licence": src.get("license"),
        "redistribute": "unknown",
        "status": "active",
        "oisf_name": key,
        "notes": " - ".join(str(n).strip() for n in (src.get("vendor"), src.get("summary")) if n),
        "tier": "community",
    }
    if src.get("min-version"):
        entry["min_suricata"] = str(src["min-version"])
    return entry


def _url_for(entry: dict, version: str) -> str:
    major = (re.findall(r"\d+", version) or [""])[0]
    per_major = entry.get("url_versions") if isinstance(entry.get("url_versions"), dict) else {}
    value = str({str(k): v for k, v in per_major.items()}.get(major, version))
    return entry["url"].replace("${suricata_version}", value)


def health(entry: dict, version: str) -> str:
    url = _url_for(entry, version)
    from suriharvest.sync import GIT_BASE_CONFIG, SyncError, download

    if entry["type"] == "git":
        if url.startswith("-"):
            return "git error: refused URL"
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
        proc = subprocess.run(
            ["git", *GIT_BASE_CONFIG, "ls-remote", "--", url, "HEAD"], capture_output=True, text=True, timeout=60, check=False, env=env
        )
        return "ok" if proc.returncode == 0 else f"git error: {proc.stderr.strip()[:120]}"
    if entry["type"] == "local":
        return "local"
    # the same guarded client as sync (global addresses only, no https->http, redirects checked per hop, deadline)
    try:
        download(url, max_bytes=1, truncate=True, user_agent=USER_AGENT)
        return "ok"
    except SyncError as e:
        m = re.search(r"HTTPStatusError: (\d+)", str(e))
        return f"HTTP {m.group(1)}" if m else str(e)[:120]


LICENCE_NAMES = ("LICENSE", "LICENSE.txt", "LICENSE.md", "LICENCE", "COPYING", "LICENSE.rst")


def licence_urls(entry: dict) -> list[str]:
    """Where the licence text of a source can be fetched without downloading the rules: the catalog's `licence_url`,
    else the usual LICENSE files at the root of a GitHub repository (git URL or raw.githubusercontent.com file)."""
    if entry.get("licence_url"):
        return [str(entry["licence_url"])]
    url = str(entry.get("url", ""))
    m = re.match(r"^https://github\.com/([^/]+)/([^/]+?)(?:\.git)?(?:/.*)?$", url) or re.match(
        r"^https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/", url
    )
    if not m:
        return []
    org, repo = m.group(1), m.group(2)
    return [f"https://raw.githubusercontent.com/{org}/{repo}/HEAD/{n}" for n in LICENCE_NAMES]


MAX_LICENCE_BYTES = 256 * 1024


def licence_fingerprint(entry: dict, budget: list[int]) -> dict:
    """{licence_url, licence_sha256} of the first candidate that answers 200, {} when none does (or no budget).
    Fetched with sync's guarded client; a text above MAX_LICENCE_BYTES is not a licence file."""
    from suriharvest.sync import SyncError, download

    for url in licence_urls(entry):
        if budget[0] <= 0:
            return {}
        budget[0] -= 1
        try:
            data, _ = download(url, max_bytes=MAX_LICENCE_BYTES, user_agent=USER_AGENT)
        except SyncError:
            continue
        if data:
            return {"licence_url": url, "licence_sha256": hashlib.sha256(data).hexdigest()}
    return {}


@dataclass
class CheckResult:
    candidates: list[dict] = field(default_factory=list)  # free OISF sources not in the catalog
    excluded: list[str] = field(default_factory=list)  # free OISF sources the catalog excludes on purpose
    attention: list[str] = field(default_factory=list)
    health: dict[str, dict] = field(default_factory=dict)  # source name -> {status, oisf...}

    @property
    def exit_code(self) -> int:
        return 1 if self.attention or self.candidates else 0


def check(
    catalog: Path | None = None,
    *,
    index_text: str | None = None,
    oisf_index: str = INDEX_URL,
    do_health: bool = True,
    max_http_requests: int = 200,
    suricata_version: str = "7.0.3",
    licences: bool = False,
    previous_health: dict | None = None,
) -> CheckResult:
    """`licences`: also fetch each source's licence text and record its sha256; with `previous_health` (the last
    health file) a changed hash is flagged `licence_changed: true` and needs attention."""
    res = CheckResult()
    if index_text is None:
        from suriharvest.sync import download

        data, _ = download(oisf_index, max_bytes=8 * 1024 * 1024, user_agent=USER_AGENT)
        index_text = (data or b"").decode("utf-8", "replace")
    full_index = (yaml.safe_load(index_text) or {}).get("sources") or {}
    oisf = free_oisf_sources({"sources": full_index})
    data = yaml.safe_load((catalog or CATALOG).read_text(encoding="utf-8"))
    entries = data["sources"]
    keys = {e["name"]: _oisf_key_for(e, oisf, full_index) for e in entries}
    # `excluded:` lists sources left out on purpose (licence, needs a key, empty, ...): never proposed again
    skip_keys, skip_urls = set(), set()
    for x in data.get("excluded") or []:
        if isinstance(x, dict):
            skip_keys.update([x["oisf_name"]] if x.get("oisf_name") else [])
            skip_urls.update([_norm_url(str(x["url"]))] if x.get("url") else [])
    known = set(keys.values()) | skip_keys
    for k, v in sorted(oisf.items()):
        if k in known or _norm_url(str(v.get("url", ""))) in skip_urls:
            if k not in keys.values():
                res.excluded.append(k)
            continue
        if not (v.get("obsolete") or v.get("deprecated")):
            res.candidates.append(catalog_entry(k, v))
    requests = 0
    budget = [max_http_requests]
    prev_sources = (previous_health or {}).get("sources") or {}
    for e in sorted(entries, key=lambda x: x["name"]):
        status = e.get("status", "active")
        h: dict = {"status": status}
        key = keys[e["name"]]
        if key:
            src = full_index.get(key)
            if src is None:
                h["oisf"] = "gone"
                res.attention.append(f"{e['name']}: gone from the OISF index ({key})")
            else:
                h["oisf"] = {k: src.get(k) for k in ("license", "min-version", "obsolete", "deprecated") if src.get(k) is not None}
                h["oisf"] = {"name": key, **h["oisf"]}
                if (src.get("obsolete") or src.get("deprecated")) and status in SYNCED_STATUSES:
                    res.attention.append(f"{e['name']}: obsolete/deprecated upstream but {status} here")
        if do_health and status in SYNCED_STATUSES and requests < max_http_requests:
            requests += 1
            st = health(e, suricata_version)
            h["check"] = st
            if st not in ("ok", "local"):
                res.attention.append(f"{e['name']}: {st}")
        if licences and status in SYNCED_STATUSES:
            fp = licence_fingerprint(e, budget)
            h.update(fp)
            old = (prev_sources.get(e["name"]) or {}).get("licence_sha256")
            if fp and old and old != fp["licence_sha256"]:
                h["licence_changed"] = True
                res.attention.append(f"{e['name']}: licence text changed ({fp['licence_url']})")
        res.health[e["name"]] = h
    return res


def render_health(res: CheckResult) -> str:
    return yaml.safe_dump({"sources": res.health, "candidates": res.candidates, "excluded": res.excluded}, sort_keys=True, width=120)


def render_report(res: CheckResult) -> str:
    lines = ["# Source catalog check\n\n"]
    lines.append(f"{len(res.attention)} item(s) need attention, {len(res.candidates)} candidate source(s).\n\n")
    lines += [f"- {a}\n" for a in res.attention]
    if res.candidates:
        lines.append("\n## Free OISF sources not in the catalog\n\n")
        lines += [f"- `{c['oisf_name']}` {c['url']} ({c['licence']})\n" for c in res.candidates]
    return "".join(lines)
