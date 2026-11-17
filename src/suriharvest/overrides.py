"""Declarative overrides kept in a profile: enable, modify and thresholds.

They live in the profile (and in `exclusions/<profile>.yaml`, next to its exclusions), never in the rule files,
so every build applies them again: an upstream update cannot wipe them. Each entry picks rules with a selector,
the same `kind` / `value` pairs as exclusions (sid, rule_key, msg_regex, rule_regex, category, file, metadata,
query, ...).

  enable      rules their publisher ships disabled (commented out) become candidates of the profile
  modify      `action: drop` turns alert rules into drop rules (IPS), or `from` / `to` rewrites the rule text
              with a Python regular expression (`\\1` back-references); a modified rule gets
              `metadata:suriharvest_modified true;`; a rewrite that breaks the rule (parser, line break, gid:sid
              change, or the profile engine's `suricata -T`) or removes a flowbit setter other rules of the build
              need is refused and reported (the rule is written unmodified). Rules with `noalert` (flowbit
              setters) never change action, as in suricata-update's drop.conf
  thresholds  lines of `threshold.config` (suppress, threshold, event_filter, rate_filter) written next to
              `suricata.rules` with the gid:sid each rule has in that build (remapped sids included)

Exclusions win: a rule that is excluded is not enabled, modified or thresholded, except that an enable entry with
`beats_exclusions: true` (what `profile import-conf` writes for enable.conf) keeps the rule, like suricata-update
where enable.conf re-enables what disable.conf disabled.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

SECTIONS = ("enable", "modify", "thresholds")
ACTIONS = ("alert", "drop", "reject", "rejectsrc", "rejectdst", "rejectboth", "pass")
FILTERS = ("suppress", "threshold", "event_filter", "rate_filter")
TRACK = {
    "suppress": ("by_src", "by_dst", "by_either"),
    "threshold": ("by_src", "by_dst", "by_rule", "by_both"),
    "event_filter": ("by_src", "by_dst", "by_rule", "by_both"),
    "rate_filter": ("by_src", "by_dst", "by_rule", "by_both"),
}
THRESHOLD_TYPES = ("threshold", "limit", "both")
RATE_ACTIONS = ("alert", "drop", "pass", "reject")
MARK = "metadata:suriharvest_modified true;"
_ACTION = re.compile(r"^(\s*)(\w+)(?=\s)")
_VAR = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*")


class OverrideError(ValueError):
    pass


# Address groups of Suricata's default suricata.yaml: a threshold.config line naming another variable stops the
# whole file from loading (`Variable "X" is not defined`), so only these are accepted.
ADDRESS_VARS = frozenset(
    {
        "HOME_NET",
        "EXTERNAL_NET",
        "HTTP_SERVERS",
        "SMTP_SERVERS",
        "SQL_SERVERS",
        "DNS_SERVERS",
        "TELNET_SERVERS",
        "AIM_SERVERS",
        "DC_SERVERS",
        "DNP3_SERVER",
        "DNP3_CLIENT",
        "MODBUS_CLIENT",
        "MODBUS_SERVER",
        "ENIP_CLIENT",
        "ENIP_SERVER",
    }
)
_ADDR_CHARS = re.compile(r"[0-9A-Fa-f:./]+")
UINT32_MAX = 4_294_967_295


def _ip(value: str) -> str:
    """An address, network, default $VARIABLE or a flat [list] of those, as Suricata's threshold.config takes it:
    no negation (`!` is a parse error there), no spaces inside the list. Returns the canonical text."""
    v = value.strip()
    items = [x.strip() for x in v[1:-1].split(",")] if v.startswith("[") and v.endswith("]") else [v]
    if len(items) > 1 and "$EXTERNAL_NET" in items:
        # EXTERNAL_NET is !$HOME_NET (default suricata.yaml): merged with $HOME_NET, a *_SERVERS variable (= $HOME_NET)
        # or an address, Suricata refuses the file ("no addresses left after merging addresses and negated addresses")
        raise OverrideError(f"ip: {v!r}: $EXTERNAL_NET (= !$HOME_NET) cannot share a list; use one entry per address")
    for x in items:
        if not x:
            raise OverrideError(f"ip: empty item in {v!r}")
        if x.startswith("!"):
            raise OverrideError(f"ip: {x!r}: negation is not allowed in threshold.config (Suricata refuses the file)")
        if x.startswith("$"):
            if x[1:] not in ADDRESS_VARS:
                raise OverrideError(f"ip: {x!r} is not one of Suricata's default address variables ({', '.join(sorted(ADDRESS_VARS))})")
            continue
        try:
            if not _ADDR_CHARS.fullmatch(x):
                raise ValueError(x)
            ipaddress.ip_network(x, strict=False)
        except ValueError as e:
            raise OverrideError(f"ip: {x!r} is not an address, network or $VARIABLE") from e
    return f"[{','.join(items)}]" if len(items) > 1 or v.startswith("[") else items[0]


def _int(entry: dict[str, Any], key: str, low: int = 1) -> int:
    """A whole number Suricata takes: ASCII digits, low..2^32-1 (count/seconds/timeout 0 make the file fail or mean nothing)."""
    v = entry.get(key)
    text = str(v).strip() if isinstance(v, int | str) and not isinstance(v, bool) else ""
    if not re.fullmatch(r"[0-9]{1,10}", text, re.ASCII) or not low <= int(text) <= UINT32_MAX:
        raise OverrideError(f"{key} must be a whole number from {low} to {UINT32_MAX} (got {v!r})")
    return int(text)


# Line separators (str.splitlines) and other control characters: a rewrite must keep the rule on one line.
_CONTROL = re.compile(r"[\x00-\x08\x0a-\x1f\x7f\x85\u2028\u2029]")


def normalise(section: str, entry: Any) -> dict[str, Any]:
    """Check one entry and return it in canonical form (string values, known keys only)."""
    from suriharvest.profiles import ProfileError, _check

    if section not in SECTIONS:
        raise OverrideError(f"section must be one of {', '.join(SECTIONS)}")
    if not isinstance(entry, dict) or "kind" not in entry or entry.get("value") in (None, ""):
        raise OverrideError("an entry needs kind and value (the same selectors as exclusions)")
    out: dict[str, Any] = {"kind": str(entry["kind"]), "value": str(entry["value"])}
    try:
        _check(out["kind"], out["value"])
    except ProfileError as e:
        raise OverrideError(str(e)) from e
    if section == "modify":
        if "action" in entry:
            if "from" in entry or "to" in entry:
                raise OverrideError("modify: use either action or from/to, not both")
            if entry["action"] not in ACTIONS:
                raise OverrideError(f"action must be one of {', '.join(ACTIONS)}")
            out["action"] = entry["action"]
        else:
            if "from" not in entry or "to" not in entry:
                raise OverrideError("modify needs action, or from and to")
            try:
                re.compile(str(entry["from"]))
            except re.error as e:
                raise OverrideError(f"from: bad regular expression: {e}") from e
            for k in ("from", "to"):
                if _CONTROL.search(str(entry[k])):
                    raise OverrideError(f"{k}: line breaks and control characters are not allowed (a rule is one line)")
            out["from"], out["to"] = str(entry["from"]), str(entry["to"])
    elif section == "enable":
        if entry.get("beats_exclusions") not in (None, False, True):
            raise OverrideError("beats_exclusions must be true or false")
        if entry.get("beats_exclusions"):
            out["beats_exclusions"] = True
    elif section == "thresholds":
        kind = entry.get("filter")
        if kind not in FILTERS:
            raise OverrideError(f"filter must be one of {', '.join(FILTERS)}")
        out["filter"] = kind
        if kind == "suppress":
            if ("track" in entry) != ("ip" in entry):
                raise OverrideError("suppress: track and ip go together (or leave both out to suppress the rule)")
            if "track" in entry:
                out["track"], out["ip"] = str(entry["track"]), _ip(str(entry["ip"]))
        else:
            out["track"] = str(entry.get("track"))
            out["count"], out["seconds"] = _int(entry, "count"), _int(entry, "seconds")
            if kind == "rate_filter":
                if entry.get("new_action") not in RATE_ACTIONS:
                    raise OverrideError(f"new_action must be one of {', '.join(RATE_ACTIONS)}")
                out["new_action"], out["timeout"] = entry["new_action"], _int(entry, "timeout")
            else:
                if entry.get("type") not in THRESHOLD_TYPES:
                    raise OverrideError(f"type must be one of {', '.join(THRESHOLD_TYPES)}")
                out["type"] = entry["type"]
        if "track" in out and out["track"] not in TRACK[kind]:
            raise OverrideError(f"{kind}: track must be one of {', '.join(TRACK[kind])}")
    if entry.get("reason"):
        out["reason"] = str(entry["reason"])
    return out


def entries(t: Any) -> dict[str, list[dict[str, Any]]]:
    opts = t.options or {}
    return {k: list(opts.get(k) or []) for k in SECTIONS}


def set_entries(t: Any, section: str, items: list[dict[str, Any]]) -> None:
    """Replace one section of a profile (validated). The options dict is reassigned so the JSON column is saved."""
    clean = [normalise(section, x) for x in items]
    opts = dict(t.options or {})
    if clean:
        opts[section] = clean
    else:
        opts.pop(section, None)
    t.options = opts


def add_entries(t: Any, section: str, items: list[dict[str, Any]]) -> int:
    """Append entries that are not there yet; returns how many were new."""
    have = entries(t)[section]
    new = [normalise(section, x) for x in items]
    added = [x for x in new if x not in have]
    set_entries(t, section, have + added)
    return len(added)


def describe(sec: str, e: dict[str, Any]) -> str:
    """One line on what an override entry does."""
    if sec == "enable":
        return "enable" + (" (beats exclusions)" if e.get("beats_exclusions") else "")
    if sec == "modify":
        return f"action {e['action']}" if "action" in e else f"{e['from']!r} -> {e['to']!r}"[:50]
    return " ".join(f"{k} {e[k]}" for k in ("filter", "type", "track", "count", "seconds", "ip", "new_action", "timeout") if k in e)


def _threshold_line(e: dict[str, Any], gid: int, sid: int) -> str:
    head = f"{e['filter']} gen_id {gid}, sig_id {sid}"
    if e["filter"] == "suppress":
        return head + (f", track {e['track']}, ip {e['ip']}" if "track" in e else "")
    if e["filter"] == "rate_filter":
        return (
            head + f", track {e['track']}, count {e['count']}, seconds {e['seconds']}, new_action {e['new_action']}, timeout {e['timeout']}"
        )
    return head + f", type {e['type']}, track {e['track']}, count {e['count']}, seconds {e['seconds']}"


def noalert(rule: Any) -> bool:
    """suricata-update's test (rule.py): a `noalert` option, or a flowbits option whose value mentions noalert."""
    return rule.has("noalert") or any("noalert" in v for v in rule.get_all("flowbits"))


@dataclass
class Applied:
    """What a build did with the overrides (goes into the build summary)."""

    modified: dict[str, list[int]] = field(default_factory=dict)  # logic hash -> modify entry numbers
    refused: list[str] = field(default_factory=list)  # rewrites that broke a rule (or were refused by the engine)
    threshold_lines: int = 0
    unmatched: list[str] = field(default_factory=list)  # entries that matched no rule in the build
    noalert: list[str] = field(default_factory=list)  # action changes skipped: noalert (flowbit setter) rules
    enable_overridden: list[str] = field(default_factory=list)  # enable entries an exclusion wins over
    unchecked: str | None = None  # why modified rules were not checked with an engine
    threshold_skipped: list[str] = field(default_factory=list)  # rules with their own threshold (entries ignored)
    hits: dict[str, int] = field(default_factory=dict)  # "thresholds #2" -> rules the entry matched

    def summary(self) -> dict[str, Any]:
        return {
            "modified": len(self.modified),
            "modify_refused": self.refused[:50],
            "modify_noalert": len(self.noalert),
            "modify_noalert_sample": self.noalert[:20],
            "enable_overridden": self.enable_overridden[:50],
            "modify_unchecked": self.unchecked,
            "threshold_lines": self.threshold_lines,
            "overrides_unmatched": self.unmatched[:50],
            "threshold_skipped": len(self.threshold_skipped),
            "threshold_skipped_sample": self.threshold_skipped[:20],
            "overrides_hits": self.hits,
        }


class Overrides:
    """The overrides of one profile, with matchers built once per build."""

    def __init__(self, s: Session, t: Any) -> None:
        from suriharvest.profiles import Matcher, _Item

        self.items = entries(t)
        self.applied = Applied()
        self._m = {}
        for sec, lst in self.items.items():
            self._m[sec] = Matcher.build(s, [_Item(i, e["kind"], e["value"]) for i, e in enumerate(lst)]) if lst else None
        self._used: dict[str, set[int]] = {k: set() for k in SECTIONS}
        self._cache: dict[str, str] = {}  # logic hash -> rewritten text (export may ask twice)
        self._refused: dict[tuple[str, int], str] = {}
        self._hits: dict[tuple[str, int], set[str]] = {}  # (section, entry index) -> logic hashes it matched

    def __bool__(self) -> bool:
        return any(self.items.values())

    def _match(self, sec: str, g: Any) -> list[int]:
        m = self._m.get(sec)
        if m is None:
            return []
        ids = [x.id for x in m.matches(g)]
        self._used[sec].update(ids)
        for i in ids:
            self._hits.setdefault((sec, i), set()).add(g.logic_hash)
        return ids

    def enables(self, g: Any) -> bool:
        return bool(self._match("enable", g))

    def enable_beats(self, g: Any, why: str) -> bool:
        """For a candidate an exclusion matched: True when an enable entry with `beats_exclusions` picks it (an
        imported enable.conf re-enables what disable.conf disabled, as in suricata-update). Enable entries without
        the flag that pick it are reported as overridden by the exclusion."""
        ids = self._match("enable", g)
        if any(self.items["enable"][i].get("beats_exclusions") for i in ids):
            return True
        for i in ids:
            e = self.items["enable"][i]
            self.applied.enable_overridden.append(f"enable #{i + 1} ({e['kind']}: {e['value']}): {g.rule_key} excluded by {why}")
        return False

    def _refuse(self, g: Any, i: int, why: str) -> None:
        self._refused[(g.logic_hash, i)] = f"{g.rule_key}: modify #{i + 1}: {why}"

    def rewrite(self, g: Any, text: str) -> str:
        """The rule text after every matching modify entry (in file order); unchanged when nothing matches."""
        if g.logic_hash in self._cache:
            return self._cache[g.logic_hash]
        new = self._rewrite(g, text)
        self._cache[g.logic_hash] = new
        return new

    def _rewrite(self, g: Any, text: str) -> str:
        from suriharvest.parser import ParseError, parse_rule
        from suriharvest.userregex import MAX_SCAN

        ids = self._match("modify", g)
        if not ids:
            return text
        try:
            before = parse_rule(text)
        except ParseError:
            return text
        new, applied = text, []
        for i in ids:  # one entry at a time: a bad rewrite is refused alone, the others still apply
            e = self.items["modify"][i]
            if "action" in e:
                m = _ACTION.match(new)
                if not (m and m.group(2) == "alert"):  # like suricata-update's drop.conf: only alert rules change
                    continue
                if noalert(parse_rule(new)):
                    # suricata-update's DropRuleFilter skips noalert rules: a dropping flowbit setter blocks
                    # traffic without ever logging an alert
                    self.applied.noalert.append(
                        f"{g.rule_key}: modify #{i + 1}: not changed to {e['action']}: noalert rule (flowbit setter)"
                    )
                    continue
                cand = new[: m.start(2)] + e["action"] + new[m.end(2) :]
            else:
                if len(new) > MAX_SCAN:
                    self._refuse(g, i, f"rule longer than {MAX_SCAN} bytes (Suricata does not load it)")
                    continue
                try:
                    cand = re.sub(e["from"], e["to"], new)
                except (re.error, IndexError) as err:
                    self._refuse(g, i, str(err))
                    continue
            if cand == new:
                continue
            try:
                if len(_CONTROL.findall(cand)) > len(_CONTROL.findall(new)):
                    raise ParseError("the rewrite adds a line break or control character")
                after = parse_rule(cand)
                if (before.gid, before.sid) != (after.gid, after.sid):
                    raise ParseError("the rewrite changes gid:sid")
            except ParseError as err:
                self._refuse(g, i, str(err))
                continue
            new = cand
            applied.append(i + 1)
        if not applied:
            return text
        body = new.rstrip()
        if body.endswith(")") and MARK not in body:
            body = body[:-1].rstrip() + " " + MARK + ")"
        self.applied.modified[g.logic_hash] = applied
        return body

    def settle(self, modified: set[str], refused: dict[str, str]) -> None:
        """After an export: keep the rules it wrote modified; `refused` (logic hash -> reason) are rewrites it took
        back (the engine refused the rule, or it removed a flowbit setter other rules need)."""
        self.applied.modified = {h: v for h, v in self.applied.modified.items() if h in modified}
        for h, why in refused.items():
            self._refused[(h, -1)] = why

    def thresholds(self, rows: list[tuple[Any, int]], own: set[str] | None = None) -> list[str]:
        """threshold.config lines for the rules of a build: (light row, exported sid) pairs, enabled rules only.
        `own`: logic hashes of rules with their own `threshold:` / `detection_filter:`. Suricata ignores every entry
        but `suppress` for those (warning "signature ... has a threshold set ... Bug #425"): they are left out and
        counted (Applied.threshold_skipped)."""
        lst = self.items["thresholds"]
        m = self._m.get("thresholds")
        if not lst or m is None:
            return []
        out: list[str] = []
        skipped: set[str] = set()
        for g, sid in rows:
            for x in m.matches(g):
                self._used["thresholds"].add(x.id)
                self._hits.setdefault(("thresholds", x.id), set()).add(g.logic_hash)
                if own and g.logic_hash in own and lst[x.id]["filter"] != "suppress":
                    skipped.add(g.rule_key)
                    continue
                out.append(_threshold_line(lst[x.id], g.gid, sid))
        self.applied.threshold_skipped = sorted(skipped)
        self.applied.threshold_lines = len(out)
        return sorted(set(out), key=out.index)

    def finish(self) -> Applied:
        self.applied.refused = list(self._refused.values())
        for sec, lst in self.items.items():
            for i, e in enumerate(lst):
                if i not in self._used[sec]:
                    self.applied.unmatched.append(f"{sec} #{i + 1} ({e['kind']}: {e['value']})")
                self.applied.hits[f"{sec} #{i + 1}"] = len(self._hits.get((sec, i), ()))
        return self.applied
