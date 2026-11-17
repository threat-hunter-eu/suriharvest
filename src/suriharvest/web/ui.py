"""Presentation helpers for the web UI: licences, engines, times, rule text highlighting, search extras.

Pure functions (no request state), so they can be tested on their own.
"""

from __future__ import annotations

import difflib
import re
import shlex
from datetime import UTC, datetime
from typing import Any

from markupsafe import Markup, escape
from sqlalchemy import Select, or_, text

from suriharvest.db import in_list
from suriharvest.models import LogicGroup
from suriharvest.search import FILTERS

# ---------------------------------------------------------------------------------------------------------------
# licences

LIC_TITLES = {
    "permissive": "Free to reuse and share with the notice (BSD, MIT, Apache, CC0, CC-BY)",
    "copyleft": "Share-alike: redistribute under the same licence (GPL family, CC-BY-SA)",
    "restricted": "Your own sensors only: no redistribution (NC, custom terms)",
    "none": "No licence stated: link only, do not redistribute",
}
LIC_WORDS = {"permissive": "permissive", "copyleft": "copyleft", "restricted": "own use only", "none": "unknown"}


def licence_short(licence: str | None) -> str:
    """A short SPDX-like label for a source licence string ('BSD (sids ...) and GPL-2.0-only ...' -> 'BSD-3 + GPL-2')."""
    lic = (licence or "").strip()
    if not lic:
        return "no licence"
    low = lic.lower()
    if "bsd" in low and "gpl" in low:
        return "BSD-3 + GPL-2"
    m = re.match(r"[A-Za-z0-9.+-]+", lic)
    return (m.group(0) if m else lic[:20]).removesuffix("-only")


def licence_class(licence: str | None, redistribute: str | None = "yes") -> str:
    if redistribute == "no":
        return "restricted"
    low = (licence or "").lower()
    if not low:
        return "none"
    if "-nc" in low or "noncommercial" in low or "non-commercial" in low:
        return "restricted"
    if any(x in low for x in ("bsd", "mit", "apache", "cc0", "isc", "unlicense")) or re.search(r"cc-by(?!-sa)", low):
        return "permissive"
    if any(x in low for x in ("gpl", "cc-by-sa", "mpl")):
        return "copyleft"
    return "restricted"


def rule_licence(src: Any, msg: str | None) -> tuple[str, str]:
    """(label, class) of one rule: ET Open ships BSD rules and GPL-2.0 rules ('GPL ...' names) in one source."""
    if src is None:
        return "unknown", "none"
    low = (src.licence or "").lower()
    if "bsd" in low and "gpl" in low:
        if (msg or "").startswith("GPL "):
            return "GPL-2.0", "copyleft"
        return "BSD-3-Clause", "permissive"
    return licence_short(src.licence), licence_class(src.licence, src.redistribute)


# ---------------------------------------------------------------------------------------------------------------
# engines


def short_engine(name: str) -> str:
    m = re.fullmatch(r"suricata-?(\d+)(?:\.\d+)*", name)
    if m:
        return m.group(1)
    m = re.fullmatch(r"(\d+)(?:\.\d+)*", name)
    return m.group(1) if m else name


def engine_label(name: str) -> str:
    """'suricata-8' -> 'Suricata 8'; the default engine 'local' (the suricata on PATH) -> 'local Suricata'."""
    s = short_engine(name)
    if s.isdigit():
        return f"Suricata {s}"
    return "local Suricata" if name == "local" else name


# ---------------------------------------------------------------------------------------------------------------
# time


def reltime(dt: Any) -> str:
    if dt is None:
        return "never"
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt)
        except ValueError:
            return dt
    now = datetime.now(UTC).replace(tzinfo=None)
    if dt.tzinfo is not None:
        dt = dt.astimezone(UTC).replace(tzinfo=None)
    sec = (now - dt).total_seconds()
    if sec < 60:
        return "just now"
    if sec < 3600:
        return f"{int(sec // 60)} min ago"
    if sec < 86400:
        return f"{int(sec // 3600)} h ago"
    if sec < 86400 * 60:
        return f"{int(sec // 86400)} d ago"
    if sec < 86400 * 730:
        return f"{int(sec // (86400 * 30))} months ago"
    return f"{int(sec // (86400 * 365))} years ago"


def fulltime(dt: Any) -> str:
    if dt is None:
        return ""
    if isinstance(dt, str):
        return dt
    return dt.strftime("%Y-%m-%d %H:%M UTC")


def num(n: Any) -> str:
    try:
        return f"{int(n):,}"
    except (TypeError, ValueError):
        return str(n)


def width_class(n: float, top: float) -> str:
    """Bar width as a .wN utility class (no inline style under the CSP)."""
    if not top or n <= 0:
        return "w2"
    return f"w{max(2, min(100, round(100 * n / top)))}"


def heat_class(n: float, top: float) -> str:
    if not top or n <= 0:
        return "h0"
    r = n / top
    return "h5" if r > 0.5 else "h4" if r > 0.25 else "h3" if r > 0.08 else "h2" if r > 0.02 else "h1" if r > 0.004 else "h0"


# ---------------------------------------------------------------------------------------------------------------
# rule text highlighting (server side; classes k-*)

_OPT_SPLIT = re.compile(r"(?<!\\);")


def _split_opts(body: str) -> list[str]:
    out, cur, i = [], [], 0
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body):
            cur.append(body[i : i + 2])
            i += 2
            continue
        if ch == ";":
            tok = "".join(cur).strip()
            if tok:
                out.append(tok)
            cur = []
        else:
            cur.append(ch)
        i += 1
    tok = "".join(cur).strip()
    if tok:
        out.append(tok)
    return out


def _span(cls: str, s: str) -> Markup:
    return Markup('<span class="{}">{}</span>').format(cls, s)


def _hl_header(head: str) -> Markup:
    parts = head.split()
    out: list[Markup] = []
    for i, p in enumerate(parts):
        if i == 0:
            out.append(_span("k-act", p))
        elif i == 1:
            out.append(_span("k-proto", p))
        elif p in ("->", "<>", "=>", "<-"):
            out.append(_span("k-dir", p))
        elif "$" in p:
            out.append(_span("k-var", p))
        else:
            out.append(Markup("{}").format(p))
    return Markup(" ").join(out)


def _hl_value(name: str, value: str) -> Markup:
    v = value.strip()
    if name == "msg":
        return _span("k-msg", v)
    if v.startswith(('"', '!"')):
        return _span("k-str", v)
    if re.fullmatch(r"-?\d+", v):
        return _span("k-num", v)
    return Markup("{}").format(v)


def rule_html(raw: str, one_per_line: bool = True) -> Markup:
    """The rule as <span class="l"> lines with k-* classes. One option per line, metadata one pair per line."""
    s = (raw or "").strip()
    disabled = s.startswith("#")
    if disabled:
        s = s.lstrip("#").strip()
    open_, close = s.find("("), s.rfind(")")
    if open_ < 0 or close < open_:
        return Markup('<span class="l">{}</span>').format(raw)
    head = _hl_header(s[:open_].strip())
    opts = _split_opts(s[open_ + 1 : close])
    prefix = Markup('<span class="k-com"># </span>') if disabled else Markup("")
    if not one_per_line:
        body = Markup(" ").join(_opt_html(o) + Markup(";") for o in opts)
        return Markup('<span class="l">{}{} ({})</span>').format(prefix, head, body)
    lines = [Markup('<span class="l">{}{} (</span>').format(prefix, head)]
    for o in opts:
        name, sep, val = o.partition(":")
        if name.strip().lower() == "metadata" and sep:
            pairs = [p.strip() for p in val.split(",") if p.strip()]
            lines.append(Markup('<span class="l">    {}:</span>').format(_span("k-opt", name.strip())))
            for j, p in enumerate(pairs):
                end = ";" if j == len(pairs) - 1 else ","
                lines.append(Markup('<span class="l">        {}{}</span>').format(_span("k-com", p), end))
            continue
        lines.append(Markup('<span class="l">    {};</span>').format(_opt_html(o)))
    lines.append(Markup('<span class="l">)</span>'))
    return Markup("").join(lines)


def _opt_html(o: str) -> Markup:
    name, sep, val = o.partition(":")
    n = name.strip()
    if not sep:
        cls = (
            "k-buf"
            if ("." in n or n in ("file_data", "pkt_data", "dns_query", "tls_sni", "ja3_hash") or n.startswith("http_"))
            else "k-opt"
        )
        return _span(cls, n)
    return _span("k-opt", n) + Markup(":") + _hl_value(n.lower(), val)


# ---------------------------------------------------------------------------------------------------------------
# search: filters the core search does not have (cve:, flowbits:, metadata:, severity lists, short engine names)

EXTRA_KEYS = ("cve", "flowbits", "flowbit", "metadata", "meta", "severity", "remapped", "licence", "license", "loads", "fails")
_n = 0


def _bind(sql: str, **kw: Any):  # type: ignore[no-untyped-def]
    global _n
    _n += 1
    names = {}
    for k, v in kw.items():
        nk = f"{k}_{_n}"
        sql = re.sub(rf":{k}\b", f":{nk}", sql)
        names[nk] = v
    return text(sql).bindparams(**names)


def _phrase(words: list[str]) -> str:
    from suriharvest.search import _FTS_JUNK

    return '"' + " ".join(_FTS_JUNK.sub(" ", w.replace('"', "")) for w in words) + '"'


def _fts(match: str):  # type: ignore[no-untyped-def]
    """Rows whose full-text entry matches (fast pre-filter; the exact check follows)."""
    return LogicGroup.id.in_(_bind("SELECT rowid FROM rules_fts WHERE rules_fts MATCH :m", m=match))


# filter keys every search understands (search.FILTERS plus the extras above), and common wrong spellings
KNOWN_KEYS = tuple(dict.fromkeys([*FILTERS, *EXTRA_KEYS]))
KEY_ALIASES = {"protocol": "proto", "application": "app", "app_proto": "app", "class": "classtype", "engine": "loads", "src": "source"}


def _unknown_key(k: str, val: str, tok: str) -> bool:
    """A `key:value` token whose key is no filter: refused instead of being searched as a word (0 results, no
    message). URLs (`http://...`), rule keys (`et:1:2000001`) and words in quotes are not filters."""
    if k in KNOWN_KEYS or not re.fullmatch(r"[a-z_]+", k) or val.startswith("/"):
        return False
    return not re.fullmatch(r"[\w.-]+:\d+:\d+", tok)


VALUE_COLUMNS = {
    "app": LogicGroup.app_layer,
    "proto": LogicGroup.protocol,
    "severity": LogicGroup.severity,
    "classtype": LogicGroup.classtype,
}


def value_hints(s: Any, q: str) -> list[str]:
    """For a search that found nothing: filter values no rule in the index has (`app:htp`), with the closest one."""
    from sqlalchemy import func, select

    out = []
    try:
        toks = shlex.split(q)
    except ValueError:
        return out
    for tok in toks:
        key, sep, val = tok.partition(":")
        col = VALUE_COLUMNS.get(key.lower())
        if not sep or not val or col is None:
            continue
        known = {str(v).lower() for v in s.scalars(select(func.distinct(col)).where(col.is_not(None))) if v}
        for v in val.lower().split(","):
            if v and v not in known:
                near = difflib.get_close_matches(v, sorted(known), n=3, cutoff=0.5)
                out.append(f"no rule has {key.lower()}:{v}" + (f" (closest: {', '.join(near)})" if near else ""))
    return out


def split_query(q: str, engines: list[str]) -> tuple[str, list[tuple[str, str]]]:
    """The query for the core search, and the extra filters the web layer applies. Raises ValueError on quotes."""
    tokens = shlex.split(q)
    keep, extra = [], []
    shorts = {short_engine(e): e for e in engines}
    for tok in tokens:
        key, sep, val = tok.partition(":")
        k = key.lower()
        if sep and val and _unknown_key(k, val, tok):
            near = difflib.get_close_matches(k, [*KNOWN_KEYS, *KEY_ALIASES], n=1, cutoff=0.6)
            hint = f" (did you mean {KEY_ALIASES.get(near[0], near[0])}:?)" if near else ""
            raise ValueError(f"unknown filter {k}:{hint}; filters: {', '.join(sorted(KNOWN_KEYS))}")
        if sep and val and k in EXTRA_KEYS:
            if k in ("loads", "fails"):
                eng = shorts.get(val, val)
                if engines and eng not in engines:
                    raise ValueError(f"{k}:{val}: no such engine (engines: {', '.join(engines)})")
                keep.append(f"{k}:{eng}")
                continue
            extra.append((k, val))
        elif re.fullmatch(r"cve[-_]\d{4}[-_]\d{4,}", tok, re.IGNORECASE):
            extra.append(("cve", tok))  # a bare CVE id is the cve: filter: one answer however it is asked
        else:
            keep.append(tok)
    return " ".join(shlex.quote(t) if (" " in t or '"' in t or "'" in t) else t for t in keep), extra


def apply_extra(stmt: Select, extra: list[tuple[str, str]], *, remapped: set[str], lic_sources: dict[str, set[str]]) -> Select:
    for k, val in extra:
        lv = val.lower()
        if k == "cve":
            v = re.sub(r"^cve[-_]?", "", lv).replace("_", "-")
            if v in ("*", "any", "yes"):
                stmt = stmt.where(_fts("{refs metadata} : cve"))
            else:
                parts = [x for x in re.split(r"[^0-9a-z]+", v) if x]
                stmt = stmt.where(_fts("{msg refs metadata} : " + _phrase(["cve", *parts])))
                pat = "%" + "-".join(parts) + "%"
                stmt = stmt.where(
                    or_(
                        LogicGroup.msg.ilike("%cve-" + "-".join(parts) + "%"),  # named in the rule's message
                        _bind(
                            'EXISTS (SELECT 1 FROM rule_versions rv, json_each(rv."references") j WHERE rv.id = logic_groups.canonical_version_id '
                            "AND lower(j.value) LIKE 'cve,%' AND lower(j.value) LIKE :p)",
                            p=pat,
                        ),
                        _bind(
                            "EXISTS (SELECT 1 FROM rule_versions rv, json_each(rv.metadata, '$.cve') j WHERE rv.id = logic_groups.canonical_version_id "
                            "AND replace(lower(j.value), '_', '-') LIKE :p)",
                            p=pat,
                        ),
                    )
                )
        elif k in ("flowbits", "flowbit"):
            names = [f"flowbits:{lv}", f"xbits:{lv}"]
            words = [x for x in re.split(r"[^0-9a-z]+", lv) if x]
            if words:
                stmt = stmt.where(_fts("raw : " + _phrase(words)))
            stmt = stmt.where(
                _bind(
                    "(EXISTS (SELECT 1 FROM rule_versions rv, json_each(rv.flowbits_set) j WHERE rv.id = logic_groups.canonical_version_id "
                    "AND lower(j.value) IN (:a, :b)) OR EXISTS (SELECT 1 FROM rule_versions rv, json_each(rv.flowbits_check) j "
                    "WHERE rv.id = logic_groups.canonical_version_id AND lower(j.value) IN (:a, :b)))",
                    a=names[0],
                    b=names[1],
                )
            )
        elif k in ("metadata", "meta"):
            mk, _, mv = val.partition("=")
            mk = re.sub(r"[^a-z0-9_]", "", mk.lower())
            if not mk:
                raise ValueError("metadata: needs key=value, e.g. metadata:malware_family=Lumma_Stealer")
            words = [x for x in re.split(r"[^0-9a-z]+", f"{mk} {mv.lower()}") if x]
            stmt = stmt.where(_fts("metadata : " + _phrase(words)))
            if mv:
                stmt = stmt.where(
                    _bind(
                        "EXISTS (SELECT 1 FROM rule_versions rv, json_each(rv.metadata, :path) j WHERE rv.id = logic_groups.canonical_version_id "
                        "AND lower(j.value) = :v)",
                        path=f"$.{mk}",
                        v=mv.lower(),
                    )
                )
        elif k == "severity":
            vals = [x for x in lv.split(",") if x]
            conds = []
            named = [x for x in vals if x not in ("none", "unrated")]
            if named:
                conds.append(
                    text("logic_groups.severity COLLATE NOCASE IN (" + ",".join(f"'{re.sub(r'[^a-z]', '', x)}'" for x in named) + ")")
                )
            if len(named) != len(vals):
                conds.append(LogicGroup.severity.is_(None))
            stmt = stmt.where(or_(*conds))
        elif k == "remapped":
            want = lv in ("yes", "1", "true")
            stmt = stmt.where(in_list(LogicGroup.logic_hash, remapped) if want else ~in_list(LogicGroup.logic_hash, remapped))
        elif k in ("licence", "license"):
            cls = {"own": "restricted", "own-use": "restricted", "nc": "restricted", "unknown": "none"}.get(lv, lv)
            plain = lic_sources.get(cls, set())
            mixed = lic_sources.get("mixed", set())
            cond = [LogicGroup.canonical_source.in_(plain)]
            if cls == "permissive":
                cond.append(LogicGroup.canonical_source.in_(mixed) & ~LogicGroup.msg.like("GPL %"))
            elif cls == "copyleft":
                cond.append(LogicGroup.canonical_source.in_(mixed) & LogicGroup.msg.like("GPL %"))
            stmt = stmt.where(or_(*cond))
    return stmt


def toggle(q: str, token: str) -> str:
    """q with `token` added, or removed when present (facet links)."""
    try:
        tokens = shlex.split(q)
    except ValueError:
        tokens = q.split()
    if token in tokens:
        tokens = [t for t in tokens if t != token]
    else:
        tokens.append(token)
    return " ".join(shlex.quote(t) if (" " in t or '"' in t) else t for t in tokens)


def tokens_of(q: str) -> list[str]:
    try:
        return shlex.split(q)
    except ValueError:
        return q.split()


def esc(x: Any) -> Markup:
    return escape(x)


# classification.config shipped with Suricata: classtype -> (description, priority)
CLASSTYPES = {
    "not-suspicious": ("Not Suspicious Traffic", 3),
    "unknown": ("Unknown Traffic", 3),
    "bad-unknown": ("Potentially Bad Traffic", 2),
    "attempted-recon": ("Attempted Information Leak", 2),
    "successful-recon-limited": ("Information Leak", 2),
    "successful-recon-largescale": ("Large Scale Information Leak", 2),
    "attempted-dos": ("Attempted Denial of Service", 2),
    "successful-dos": ("Denial of Service", 2),
    "attempted-user": ("Attempted User Privilege Gain", 1),
    "unsuccessful-user": ("Unsuccessful User Privilege Gain", 1),
    "successful-user": ("Successful User Privilege Gain", 1),
    "attempted-admin": ("Attempted Administrator Privilege Gain", 1),
    "successful-admin": ("Successful Administrator Privilege Gain", 1),
    "rpc-portmap-decode": ("Decode of an RPC Query", 2),
    "shellcode-detect": ("Executable code was detected", 1),
    "string-detect": ("A suspicious string was detected", 3),
    "suspicious-filename-detect": ("A suspicious filename was detected", 2),
    "suspicious-login": ("An attempted login using a suspicious username was detected", 2),
    "system-call-detect": ("A system call was detected", 2),
    "tcp-connection": ("A TCP connection was detected", 4),
    "trojan-activity": ("A Network Trojan was detected", 1),
    "unusual-client-port-connection": ("A client was using an unusual port", 2),
    "network-scan": ("Detection of a Network Scan", 3),
    "denial-of-service": ("Detection of a Denial of Service Attack", 2),
    "non-standard-protocol": ("Detection of a non-standard protocol or event", 2),
    "protocol-command-decode": ("Generic Protocol Command Decode", 3),
    "web-application-activity": ("access to a potentially vulnerable web application", 2),
    "web-application-attack": ("Web Application Attack", 1),
    "misc-activity": ("Misc activity", 3),
    "misc-attack": ("Misc Attack", 2),
    "icmp-event": ("Generic ICMP event", 3),
    "inappropriate-content": ("Inappropriate Content was Detected", 1),
    "policy-violation": ("Potential Corporate Privacy Violation", 1),
    "default-login-attempt": ("Attempt to login by a default username and password", 2),
    "targeted-activity": ("Targeted Malicious Activity was Detected", 1),
    "exploit-kit": ("Exploit Kit Activity Detected", 1),
    "external-ip-check": ("Device Retrieving External IP Address Detected", 2),
    "domain-c2": ("Domain Observed Used for C2 Detected", 1),
    "pup-activity": ("Possibly Unwanted Program Detected", 2),
    "credential-theft": ("Successful Credential Theft Detected", 1),
    "social-engineering": ("Possible Social Engineering Attempted", 2),
    "coin-mining": ("Crypto Currency Mining Activity Detected", 2),
    "command-and-control": ("Malware Command and Control Activity Detected", 1),
}


IOC_WORDS = {
    "domain": "domain",
    "ip": "IP",
    "url": "URL",
    "ja3": "JA3",
    "ja3s": "JA3S",
    "ja4": "JA4",
    "cert_fingerprint": "TLS cert",
    "cert_serial": "cert serial",
    "dataset": "dataset",
}


def mark(textval: str | None, words: list[str]) -> Markup:
    """Escape `textval` and wrap the search words in <mark>."""
    s = textval or ""
    terms = sorted({w.strip('"').lower() for w in words if len(w.strip('"')) >= 2}, key=len, reverse=True)
    if not terms:
        return escape(s)
    pat = re.compile("|".join(re.escape(t) for t in terms), re.IGNORECASE)
    out, last = [], 0
    for m in pat.finditer(s):
        out.append(escape(s[last : m.start()]))
        out.append(Markup("<mark>{}</mark>").format(m.group(0)))
        last = m.end()
    out.append(escape(s[last:]))
    return Markup("").join(out)


def licence_groups(s: Any, sources: list[Any] | None = None) -> dict[str, set[str]]:
    """Licence class -> source names (the `licence:` filter). `sources`: the Source rows when already read."""
    from sqlalchemy import select

    from suriharvest.models import Source

    out: dict[str, set[str]] = {}
    for src in sources if sources is not None else s.scalars(select(Source)):
        low = (src.licence or "").lower()
        cls = "mixed" if ("bsd" in low and "gpl" in low and src.redistribute != "no") else licence_class(src.licence, src.redistribute)
        out.setdefault(cls, set()).add(src.name)
    return out


def friendly_error(error: str | None) -> str:
    """A download error as a reader sees it: without the Python exception class in front ("SyncError: ...")."""
    return re.sub(r"^[A-Z][A-Za-z]*(?:Error|Exception): ", "", (error or "").strip())


def display_path(path: object) -> str:
    """A local path as the UI shows it: `~/...` under the home directory, else only its last part (the workspace
    name), so absolute machine paths never reach a page or a screenshot."""
    from pathlib import Path

    p = Path(str(path)).expanduser()
    try:
        return "~/" + p.resolve().relative_to(Path.home().resolve()).as_posix()
    except (ValueError, OSError, RuntimeError):
        return p.name or str(p)


# ----------------------------------------------------------------------------- overview charts (same code as sigharvest/web/present.py)


def age_chart(by_year: dict[int, int], unknown: int, recent: int, total: int, this_year: int, span: int = 10) -> dict[str, Any]:
    """Columns for "when the rules were last changed": one per year for the last `span` years, older years in one
    first column. Geometry in a 0..100 x 0..100 box (the template draws it as SVG, no inline style under the CSP)."""
    first = this_year - span + 1
    cols: list[dict[str, Any]] = []
    older = sum(n for y, n in by_year.items() if y < first)
    if older:
        cols.append({"label": f"before {first}", "short": "older", "n": older, "now": False})
    for y in range(first, this_year + 1):
        cols.append(
            {"label": str(y), "short": f"'{y % 100:02d}" if y != this_year else str(y), "n": by_year.get(y, 0), "now": y == this_year}
        )
    peak = max((c["n"] for c in cols), default=0)
    n = len(cols)
    slot = 100 / n if n else 100
    for i, c in enumerate(cols):
        h = 0.0 if not peak or not c["n"] else max(2.0, 96 * c["n"] / peak)
        c.update(x=round(i * slot + slot * 0.14, 3), w=round(slot * 0.72, 3), y=round(100 - h, 3), h=round(h, 3))
    dated = sum(by_year.values())
    return {
        "cols": cols,
        "dated": dated,
        "unknown": unknown,
        "recent": recent,
        "share": round(100 * recent / total) if total else 0,
        "peak": peak,
    }


def spark(values: list[int]) -> dict[str, Any] | None:
    """A sparkline (polyline points in a 0..100 x 0..30 box) of a count over the last updates, oldest first; None for
    fewer than two points."""
    if len(values) < 2:
        return None
    lo, hi = min(values), max(values)
    rng = (hi - lo) or 1
    step = 100 / (len(values) - 1)
    pts = [(round(i * step, 2), round(27 - 24 * (v - lo) / rng, 2) if hi > lo else 15.0) for i, v in enumerate(values)]
    return {
        "points": " ".join(f"{x},{y}" for x, y in pts),
        "area": "0,30 " + " ".join(f"{x},{y}" for x, y in pts) + " 100,30",
        "last": pts[-1],
        "n": len(values),
        "delta": values[-1] - values[0],
    }


def composition(counts: list[tuple[str, int]], order: tuple[str, ...], href: Any, cls_prefix: str) -> list[dict[str, Any]]:
    """Parts of a 100% bar in a fixed order (never by rank): label, count, percent, .wNN width class, colour class."""
    by = dict(counts)
    total = sum(by.get(k, 0) for k in order)
    parts: list[dict[str, Any]] = []
    for k in order:
        n = by.get(k, 0)
        if n and total:
            pct = 100 * n / total
            parts.append(
                {
                    "label": k,
                    "n": n,
                    "pct": round(pct) if pct >= 1 else "<1",
                    "w": f"w{max(2, min(100, round(pct)))}",
                    "cls": f"{cls_prefix}{k}",
                    "href": href(k),
                }
            )
    return parts
