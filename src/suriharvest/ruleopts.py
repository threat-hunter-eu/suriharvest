r"""Rule option splitting, standard library only: shared by parser.py and by sidmap_check.py (which the nightly
`state` job runs with `python3 -I`, without the package installed).

An option ends at the first ";" whose preceding character is not a backslash (so `\\;` does not end it either,
as in Suricata); quotes do not protect a ";" (Suricata requires `\;` or `|3b|` inside values). Option names are
case-insensitive.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

ACTIONS = frozenset({"alert", "drop", "reject", "rejectsrc", "rejectdst", "rejectboth", "pass", "accept", "config"})
OPTION_NAME = re.compile(r"[a-z0-9_.\-]+")


class OptionError(ValueError):
    pass


def option_spans(body: str) -> Iterator[tuple[str, int, int]]:
    """(lower-case name, start, end) of every option in `body` (the text between the outer parentheses)."""
    i, n = 0, len(body)
    while i < n:
        while i < n and body[i] in " \t;":
            i += 1
        if i >= n:
            break
        j = i
        # Suricata (detect-parse.c, checked with suricata -T on 7.0.3, 7.0.17 and 8.0.8): a ";" right after a
        # backslash never ends an option, also after "\\" (the backslash pair is not collapsed first)
        while j < n and not (body[j] == ";" and body[j - 1] != "\\"):
            j += 1
        yield body[i:j].partition(":")[0].strip().lower(), i, min(j, n)
        i = j + 1


def option_tokens(body: str) -> list[tuple[str, str | None]]:
    """(lower-case name, value or None) of every option; OptionError on a bad option name."""
    out: list[tuple[str, str | None]] = []
    for _, a, b in option_spans(body):
        token = body[a:b].strip()
        if not token:
            continue
        name, sep, value = token.partition(":")
        name = name.strip().lower()
        if not name or not OPTION_NAME.fullmatch(name):
            raise OptionError(f"bad option name {name!r}")
        out.append((name, value.strip() if sep else None))
    return out


U32_MAX = 2**32 - 1
# Leading zeros are skipped (strtoul does); at most 10 significant digits (2^32-1), so int() never meets
# Python's 4,300-digit conversion limit.
_UINT = re.compile(r"\+?0*([0-9]{1,10})", re.ASCII)


def option_int(v: str | None) -> int | None:
    """An option's integer value as Suricata reads it (strtoul over ASCII digits, surrounding blanks ignored):
    None for quotes, `_`, non-ASCII digits, signs other than "+" and values above 2^32-1 (Suricata refuses them)."""
    m = _UINT.fullmatch(v.strip()) if v is not None else None
    if m is None:
        return None
    n = int(m.group(1))
    return n if n <= U32_MAX else None


def is_rule_line(line: str) -> bool:
    """A rule, enabled or commented out: (after "#" and blanks) a rule action word, then an option list."""
    t = line.strip().lstrip("#").strip()
    word = t.split(None, 1)[0].lower() if t else ""
    return word in ACTIONS and "(" in t


def gid_sid(line: str) -> tuple[int, int]:
    """(gid, sid) of a rule line (a leading "#" is allowed). OptionError unless there is exactly one numeric sid
    and at most one numeric gid."""
    t = line.strip().lstrip("#").strip()
    open_, close = t.find("("), t.rfind(")")
    if open_ < 0 or close < open_:
        raise OptionError("no option list")
    opts = option_tokens(t[open_ + 1 : close])
    sids = [option_int(v) for n, v in opts if n == "sid"]
    gids = [option_int(v) for n, v in opts if n == "gid"]
    if len(sids) != 1 or sids[0] is None or len(gids) > 1 or (gids and not gids[0]):
        raise OptionError(f"{len(sids)} sid and {len(gids)} gid options (exactly one numeric sid, at most one gid above 0)")
    return (gids[0] if gids else 1), sids[0]
