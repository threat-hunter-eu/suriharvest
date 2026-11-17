"""Parse Suricata rule text into a structured Rule.

A rules file is line based: one rule per logical line, a trailing backslash joins the next line, "#" in front of a
rule disables it (it is still a rule: ET ships many rules disabled). Other "#" lines are comments.

The option list is tokenised the way Suricata does it: an option ends at the first ";" that is not escaped with a
backslash. Quotes do not protect a ";" (Suricata requires `\\;` or `|3b|` inside values).

This parser is written from the Suricata documentation; it does not reuse suricata-update's GPL code.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field

from suriharvest.ruleopts import ACTIONS, OptionError, option_int, option_spans, option_tokens

DIRECTIONS = frozenset({"->", "<>", "=>"})

# Cheap pre-filters. Both are linear in the input: upstream files are untrusted, and a backtracking pattern such as
# `^\s*#*\s*` is quadratic on a long run of blanks (one 4 MiB line of spaces would stall a sync for hours).
_ACTION_WORD = re.compile(r"(" + "|".join(sorted(ACTIONS, key=len, reverse=True)) + r")[ \t\r\n\f\v]+\S", re.ASCII)
_ACTIONS_B = tuple(a.encode() for a in sorted(ACTIONS, key=len, reverse=True))
# A rule line longer than this is not a rule (the longest public rules are a few KiB); it is reported, not parsed.
MAX_RULE_LINE = 256 * 1024
# Suricata's rule buffer (8 KiB with the terminating NUL): a rule of 8192 bytes or more never loads ("no
# terminating ';' found"). Such rules are refused at ingest, so nothing downstream (user regexes)
# scans more than this per rule.
MAX_SURICATA_RULE = 8191


def _rule_start(line: str) -> bool:
    """Does the line start (after blanks and "#") with a rule action followed by blanks and more text?"""
    return bool(_ACTION_WORD.match(line.lstrip(" \t\r\n\f\v#")))


def looks_like_rules_bytes(data: bytes) -> bool:
    """True when some line starts (after blanks and "#") with a rule action, blanks, and has a "(" later on.
    A plain line scan: linear in len(data), no regex backtracking."""
    for line in data.split(b"\n"):
        rest = line.lstrip(b" \t#")
        for a in _ACTIONS_B:
            if rest.startswith(a):
                tail = rest[len(a) :]
                if tail[:1] in (b" ", b"\t") and b"(" in tail and tail.strip(b" \t\r(").strip():
                    return True
                break
    return False


HAS_SID = re.compile(rb"\bsid[ \t]*:[ \t]*\d")


class ParseError(ValueError):
    """The line looks like a rule but cannot be parsed."""


@dataclass(frozen=True)
class Option:
    name: str  # lower case
    value: str | None  # stripped; None for "name;"


@dataclass
class Rule:
    """One parsed rule. `text` is the logical line without a leading "#" (what content_hash covers)."""

    text: str
    enabled: bool
    action: str
    protocol: str
    src_addr: str
    src_port: str
    direction: str
    dst_addr: str
    dst_port: str
    options: list[Option]
    line_no: int = 0  # first physical line (1-based) in the file
    repaired: bool = False  # was split over several lines without a trailing backslash

    def get(self, name: str) -> str | None:
        """Value of the first option called `name` (None when missing or valueless)."""
        for o in self.options:
            if o.name == name:
                return o.value
        return None

    def get_all(self, name: str) -> list[str]:
        return [o.value for o in self.options if o.name == name and o.value is not None]

    def has(self, name: str) -> bool:
        return any(o.name == name for o in self.options)

    @property
    def sid(self) -> int | None:
        return _int(self.get("sid"))

    @property
    def gid(self) -> int:
        return _int(self.get("gid")) or 1

    @property
    def rev(self) -> int | None:
        return _int(self.get("rev"))

    @property
    def msg(self) -> str | None:
        v = self.get("msg")
        return unquote(v) if v is not None else None


def _int(v: str | None) -> int | None:
    return option_int(v)  # ASCII digits only, at most 2^32-1, like Suricata (ruleopts.py)


def unquote(v: str) -> str:
    """Strip surrounding double quotes and undo backslash escapes (\\" \\; \\\\)."""
    v = v.strip()
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        v = v[1:-1]
    return re.sub(r"\\(.)", r"\1", v)


@dataclass
class LogicalLine:
    text: str
    line_no: int


def logical_lines(text: str) -> Iterator[LogicalLine]:
    """Join backslash-continued lines. Yields every non-empty logical line with its first physical line number."""
    buf: list[str] = []
    start = 0
    # Lines end at "\n" only, as Suricata reads a rules file (fgets): \x0c, \x85 or U+2028 inside a rule do not
    # split it (str.splitlines would)
    for i, raw in enumerate(text.split("\n"), start=1):
        line = raw.rstrip("\r")
        if not buf:
            start = i
        # A continuation backslash followed only by spaces still continues the line (seen in vendor feeds).
        bare = line.rstrip(" \t")
        if bare.endswith("\\") and not bare.endswith("\\\\"):
            buf.append(bare[:-1])
            continue
        buf.append(line)
        joined = "".join(buf).strip()
        buf = []
        if joined:
            yield LogicalLine(joined, start)
    if buf:
        joined = "".join(buf).strip()
        if joined:
            yield LogicalLine(joined, start)


def looks_like_rule(line: str) -> bool:
    """True for lines that start (after optional "#") with a rule action and contain an option list."""
    return len(line) <= MAX_RULE_LINE and _rule_start(line) and "(" in line and ")" in line


def split_header(header: str) -> list[str]:
    """Split a rule header on whitespace, keeping [..] lists (which may contain spaces) together."""
    out: list[str] = []
    cur: list[str] = []
    depth = 0
    for ch in header:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth = max(0, depth - 1)
        if ch.isspace() and depth == 0:
            if cur:
                out.append("".join(cur))
                cur = []
            continue
        cur.append(ch)
    if cur:
        out.append("".join(cur))
    return out


def split_options(body: str) -> list[Option]:
    """Tokenise the text between the outer parentheses. A ";" preceded by a backslash does not end an option
    (ruleopts.py, shared with the stdlib-only sid map check)."""
    try:
        return [Option(n, v) for n, v in option_tokens(body)]
    except OptionError as e:
        raise ParseError(str(e)) from None


def _option_spans(body: str) -> Iterator[tuple[str, int, int]]:
    """(lower-case name, start, end) of every option in `body`, split exactly like split_options."""
    return option_spans(body)


def replace_sid(text: str, sid: int) -> str:
    """Return the rule text with the value of its `sid` option set to `sid`.

    The option list is tokenised like split_options (the way Suricata does it), so a "sid:N;" inside another
    option's value (`reference:url,example.com/a-sid:2000001;`) is never touched. Raises ParseError when the rule has
    no sid option or more than one."""
    open_ = text.find("(")
    close = text.rfind(")")
    if open_ < 0 or close < open_:
        raise ParseError("no option list")
    body = text[open_ + 1 : close]
    spans = [(a, b) for name, a, b in _option_spans(body) if name == "sid"]
    if len(spans) != 1:
        raise ParseError(f"expected exactly one sid option, found {len(spans)}")
    a, b = spans[0]
    return text[: open_ + 1] + body[:a] + f"sid:{sid}" + body[b:] + text[close:]


def add_noalert(text: str) -> str:
    """Return the rule text with a `noalert;` option before its `sid` option, as suricata-update's rule.format()
    does for flowbit setters it enables; unchanged when the rule already has a `noalert` option or a flowbits
    option whose value mentions noalert. The option list is split like replace_sid, so a "sid:N;" or "noalert;"
    inside another option's value (`content:"sid:1;"`) is never taken for the option. Raises ParseError when the
    rule has no sid option or more than one."""
    open_ = text.find("(")
    close = text.rfind(")")
    if open_ < 0 or close < open_:
        raise ParseError("no option list")
    body = text[open_ + 1 : close]
    spans = list(_option_spans(body))
    for name, a, b in spans:
        if name == "noalert" or (name == "flowbits" and "noalert" in body[a:b].partition(":")[2]):
            return text
    sids = [a for name, a, _ in spans if name == "sid"]
    if len(sids) != 1:
        raise ParseError(f"expected exactly one sid option, found {len(sids)}")
    a = sids[0]
    sep = "" if a == 0 or body[a - 1] in " \t" else " "
    return text[: open_ + 1] + body[:a] + f"{sep}noalert; " + body[a:] + text[close:]


def parse_rule(line: str, line_no: int = 0) -> Rule:
    """Parse one logical line (with or without a leading "#"). Raises ParseError."""
    s = line.strip()
    enabled = True
    if s.startswith("#"):
        enabled = False
        s = s.lstrip("#").strip()
    if len(s) > MAX_SURICATA_RULE or len(s.encode("utf-8", "surrogateescape")) > MAX_SURICATA_RULE:
        raise ParseError(f"rule longer than {MAX_SURICATA_RULE} bytes: Suricata never loads it")
    open_ = s.find("(")
    close = s.rfind(")")
    if open_ < 0 or close < open_:
        raise ParseError("no option list")
    if s[close + 1 :].strip():
        raise ParseError("text after the option list")
    head = split_header(s[:open_])
    if not head or head[0].lower() not in ACTIONS:
        raise ParseError("unknown action")
    if len(head) != 7:
        raise ParseError(f"header has {len(head)} fields, expected 7")
    action, proto, sa, sp, direction, da, dp = head
    if direction not in DIRECTIONS:
        raise ParseError(f"bad direction {direction!r}")
    options = split_options(s[open_ + 1 : close])
    if not options:
        raise ParseError("empty option list")
    rule = Rule(
        text=s,
        enabled=enabled,
        action=action.lower(),
        protocol=proto.lower(),
        src_addr=sa,
        src_port=sp,
        direction=direction,
        dst_addr=da,
        dst_port=dp,
        options=options,
        line_no=line_no,
    )
    if rule.sid is None:
        raise ParseError("missing or non-numeric sid (ASCII digits, at most 4294967295)")
    gids = [o.value for o in options if o.name == "gid"]
    if len(gids) > 1 or (gids and not option_int(gids[0])):
        raise ParseError("bad gid (one gid option, ASCII digits, 1 to 4294967295)")
    n_sid = sum(1 for o in options if o.name == "sid")
    if n_sid != 1:
        raise ParseError(f"{n_sid} sid options (exactly one allowed)")
    return rule


@dataclass
class ParsedFile:
    rules: list[Rule] = field(default_factory=list)
    errors: list[tuple[int, str, str]] = field(default_factory=list)  # (line_no, text, error)


MAX_REPAIR_LINES = 50


def parse_text(text: str) -> ParsedFile:
    """Parse a rules file. Lines that look like rules but fail to parse are returned as errors (quarantine).

    Some feeds and exports split rules over several lines without the trailing backslash Suricata
    needs. A line that starts like an enabled rule but does not end with ")" is joined with the following lines
    (not comments, not another rule start) up to the one that ends with ")"; if that parses, the rule is kept and
    marked `repaired`."""
    out = ParsedFile()
    lines = list(logical_lines(text))
    i = 0
    while i < len(lines):
        ll = lines[i]
        t = ll.text
        if _unterminated_start(t):
            repaired = _repair(lines, i)
            if repaired is not None:
                rule, i = repaired
                out.rules.append(rule)
                continue
            out.errors.append((ll.line_no, t, "rule without a closing parenthesis"))
            i += 1
            continue
        i += 1
        if len(t) > MAX_RULE_LINE:
            if _rule_start(t[:4096]):
                out.errors.append((ll.line_no, t[:200] + "...", f"line longer than {MAX_RULE_LINE} characters"))
            continue
        if not looks_like_rule(t):
            continue
        try:
            out.rules.append(parse_rule(t, ll.line_no))
        except ParseError as e:
            fixed = strip_stray_continuations(t)
            if fixed != t:
                try:
                    rule = parse_rule(fixed, ll.line_no)
                    rule.repaired = True
                    out.rules.append(rule)
                    continue
                except ParseError:
                    pass
            # A commented line that only looks like a rule (prose starting with "alert ...") is a comment.
            if not (t.lstrip().startswith("#") and "sid" not in t):
                out.errors.append((ll.line_no, t, str(e)))
    return out


def strip_stray_continuations(t: str) -> str:
    """Remove continuation backslashes left inside a joined line ("any [80] \\ (msg:..."), outside quotes.
    Tools that join multi-line rules but miss CRLF line ends leave them (seen in some threat-intel exports)."""
    out: list[str] = []
    quoted = False
    i = 0
    while i < len(t):
        ch = t[i]
        if ch == "\\" and i + 1 < len(t):
            if not quoted and t[i + 1] in " \t":
                out.append(" ")
                i += 1
                continue
            out.append(t[i : i + 2])
            i += 2
            continue
        if ch == '"':
            quoted = not quoted
        out.append(ch)
        i += 1
    return "".join(out).rstrip("\\").rstrip()


def _unterminated_start(t: str) -> bool:
    return len(t) <= MAX_RULE_LINE and _rule_start(t) and "(" in t and not t.rstrip().endswith(")") and not t.lstrip().startswith("#")


def _repair(lines: list[LogicalLine], i: int) -> tuple[Rule, int] | None:
    """Join lines[i] with the following lines up to one ending in ")". Returns (rule, index after it) or None."""
    parts = [lines[i].text]
    for j in range(i + 1, min(len(lines), i + 1 + MAX_REPAIR_LINES)):
        nxt = lines[j].text
        if len(nxt) > MAX_RULE_LINE or _rule_start(nxt) or nxt.lstrip().startswith("#"):
            return None
        parts.append(nxt)
        if nxt.rstrip().endswith(")"):
            try:
                rule = parse_rule(" ".join(parts), lines[i].line_no)
            except ParseError:
                return None
            rule.repaired = True
            return rule, j + 1
    return None


# ---------------------------------------------------------------------------------------------------------------
# content values


def decode_content(value: str) -> tuple[bytes, bool]:
    """Decode a content/byte pattern value: optional "!" negation, quotes, |hex| blocks, backslash escapes.

    Returns (bytes, negated). Raises ParseError on malformed hex.
    """
    v = value.strip()
    negated = False
    if v.startswith("!"):
        negated = True
        v = v[1:].strip()
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        v = v[1:-1]
    out = bytearray()
    i = 0
    in_hex = False
    hexbuf: list[str] = []
    while i < len(v):
        c = v[i]
        if in_hex:
            if c == "|":
                digits = "".join(hexbuf).replace(" ", "").replace("\t", "")
                if len(digits) % 2 or not re.fullmatch(r"[0-9A-Fa-f]*", digits):
                    raise ParseError(f"bad hex block |{''.join(hexbuf)}|")
                out.extend(bytes.fromhex(digits))
                hexbuf = []
                in_hex = False
            else:
                hexbuf.append(c)
            i += 1
            continue
        if c == "|":
            in_hex = True
            i += 1
            continue
        if c == "\\" and i + 1 < len(v):
            out.extend(v[i + 1].encode("utf-8"))
            i += 2
            continue
        out.extend(c.encode("utf-8"))
        i += 1
    if in_hex:
        raise ParseError("unterminated hex block")
    return bytes(out), negated


_PLAIN = set(range(0x20, 0x7F)) - {ord('"'), ord(";"), ord("\\"), ord("|")}


def encode_content(data: bytes) -> str:
    """One canonical text form: printable ASCII literal, everything else (and " ; \\ |) as |hex| blocks."""
    parts: list[str] = []
    hexrun: list[str] = []
    for b in data:
        if b in _PLAIN:
            if hexrun:
                parts.append("|" + " ".join(hexrun) + "|")
                hexrun = []
            parts.append(chr(b))
        else:
            hexrun.append(f"{b:02X}")
    if hexrun:
        parts.append("|" + " ".join(hexrun) + "|")
    return "".join(parts)
