"""Import a suricata-update configuration (enable.conf, disable.conf, drop.conf, modify.conf) into a profile.

The migration path for existing suricata-update users: their local decisions become profile entries that
survive every update (docs/profiles.md):

  disable.conf  -> exclusions
  enable.conf   -> `enable` entries (rules shipped commented out become candidates)
  drop.conf     -> `modify` entries with `action: drop` (alert rules only, like suricata-update)
  modify.conf   -> `modify` entries with `from` / `to` (Python regex; `${1}` becomes `\\1`)

Lines are read as suricata-update 1.3 reads them (main.py load_matchers/load_filters, matchers.py
parse_rule_match): a ` #` and everything after it is a comment, matchers are tried in its order (`*`, sid lists,
`re:`, `filename:`, `group:` or a bare `*.rules` name, `metadata:`), prefixes are case-sensitive, and `group:X`
matches the file name with or without `.rules`.

Matchers: `sid`, `gid:sid` (gid 1), comma lists of those, `*` (every rule), `re:` (whole rule text,
case-insensitive), `group:` / `name.rules` (rule file name, shell patterns), `metadata: key value`. Anything else is
reported with its file and line, never dropped silently.

Precedence is suricata-update's too: enable.conf re-enables what disable.conf disables, so enable entries are
imported with `beats_exclusions: true` (overrides.py).
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path

from suriharvest.portable import decode_text

FILES = ("enable.conf", "disable.conf", "drop.conf", "modify.conf")
_ID = re.compile(r"(?:([0-9]{1,10}):)?([0-9]{1,10})", re.ASCII)


class Unsupported(ValueError):
    pass


@dataclass
class Converted:
    exclusions: list[tuple[str, str, str]] = field(default_factory=list)  # kind, value, reason
    enable: list[dict[str, str]] = field(default_factory=list)
    modify: list[dict[str, str]] = field(default_factory=list)
    unsupported: list[str] = field(default_factory=list)  # "file:line: text -> why"
    counts: dict[str, int] = field(default_factory=dict)  # file -> lines converted


def selectors(matcher: str) -> list[tuple[str, str]]:
    """(kind, value) selectors for one suricata-update matcher (its parse_rule_match order). Raises Unsupported."""
    m = matcher.strip()
    if not m:
        raise Unsupported("empty matcher")
    if m == "*":
        return [("file", "*")]
    ids = _ids(m)
    if ids is not None:
        return ids
    if m.startswith("re:"):
        rx = m.split(":", 1)[1].strip()
        try:
            re.compile(rx, re.IGNORECASE)
        except re.error as e:
            raise Unsupported(f"bad regular expression: {e}") from None
        return [("rule_regex", rx)]
    if m.startswith("filename:"):
        raise Unsupported("filename: (a path inside the source archive) is not supported; use group:")
    if m.startswith("group:") or m.endswith(".rules"):
        pat = m.split(":", 1)[1].strip() if m.startswith("group:") else m
        if not pat:
            raise Unsupported("group: without a file name")
        return [("file", pat)]  # the file kind matches the name with or without .rules, like GroupMatcher
    if m.startswith("metadata:"):
        kv = m.split(":", 1)[1].strip()
        if len(kv.split(None, 1)) != 2:
            raise Unsupported("metadata: needs 'key value'")
        return [("metadata", " ".join(kv.split(None, 1)))]
    raise Unsupported("not a supported matcher (sid, gid:sid, *, re:, group:, name.rules, metadata:)")


def _ids(m: str) -> list[tuple[str, str]] | None:
    """A sid list as IdRuleMatcher reads it; None when the line is not one (the other matchers are tried next)."""
    pairs = []
    for part in m.split(","):
        im = _ID.fullmatch(part.strip())
        if not im:
            return None
        pairs.append((im.group(1), im.group(2)))
    for gid, _ in pairs:
        if gid not in (None, "1"):
            raise Unsupported(f"gid {gid}: only gid 1 rules are matched by sid")
    return [("sid", str(int(sid))) for _, sid in pairs]


def strip_comment(line: str) -> str:
    """suricata-update drops everything from the first ` #` (`line.rsplit(" #")[0]`)."""
    return line.split(" #", 1)[0].strip()


def _lines(path: Path) -> list[tuple[int, str]]:
    out = []
    for n, raw in enumerate(decode_text(path.read_bytes()).replace("\r\n", "\n").split("\n"), 1):
        s = raw.strip()
        if s and not s.startswith("#"):
            s = strip_comment(s)
            if s:
                out.append((n, s))
    return out


def _modify_tokens(line: str) -> tuple[str, str, str]:
    try:
        tok = shlex.split(line)
    except ValueError as e:
        raise Unsupported(f"cannot split the line: {e}") from None
    if len(tok) == 3:
        return tok[0], tok[1], tok[2]
    if len(tok) == 5 and tok[0] == "modifysid" and tok[3] == "|":  # oinkmaster style
        return tok[1], tok[2], tok[4]
    raise Unsupported('expected: <matcher> "<from>" "<to>"')


def convert(files: dict[str, Path]) -> Converted:
    """files: name (one of FILES) -> path. Every line is converted or listed in `unsupported`. Line references
    (`where`, in reasons and in `unsupported`) use the real file name, so a renamed file (`disable-sensor1.conf`) is
    the one named."""
    res = Converted()
    for name in FILES:
        path = files.get(name)
        if path is None:
            continue
        ok = 0
        for n, line in _lines(path):
            where = f"{path.name}:{n}"
            try:
                if name == "modify.conf":
                    matcher, frm, to = _modify_tokens(re.sub(r"\\\$", "$", line))  # suricata-update unescapes \$
                    to = re.sub(r"\$\{(\d+)\}", r"\\\1", to)
                    try:
                        groups = re.compile(frm).groups
                    except re.error as e:
                        raise Unsupported(f"bad regular expression: {e}") from None
                    if any(int(g) > groups for g in re.findall(r"\\(\d+)", to)):
                        raise Unsupported(f"back-reference to a group the pattern does not have ({groups} groups)")
                    sels = selectors(matcher)
                    res.modify += [{"kind": k, "value": v, "from": frm, "to": to, "reason": where} for k, v in sels]
                else:
                    sels = selectors(line)
                    if name == "disable.conf":
                        res.exclusions += [(k, v, where) for k, v in sels]
                    elif name == "enable.conf":
                        res.enable += [{"kind": k, "value": v, "beats_exclusions": True, "reason": where} for k, v in sels]
                    else:
                        res.modify += [{"kind": k, "value": v, "action": "drop", "reason": where} for k, v in sels]
                ok += 1
            except Unsupported as e:
                res.unsupported.append(f"{where}: {line} -> {e}")
        res.counts[name] = ok
    return res
