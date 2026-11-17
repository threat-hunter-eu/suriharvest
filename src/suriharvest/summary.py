"""A rule in plain words, built from the parsed rule text (deterministic, no AI).

    s = summarize(raw, app_layer="http", setters={"ET.foo": 2050296})
    s.plain    one or two sentences: who talks to whom, over what, what must be in it, what it depends on
    s.short    one line for search results
    s.traffic  the two ends and the wire between them (traffic strip)
    s.steps    the match steps in order: gates (flowbits, datasets) first, then each check in words
    s.needs    what a sensor needs for the rule to fire (parser, engine setting, companion rules, files)

Rules that are too involved to say in words honestly (many contents, pcre only, lua, byte_math chains) get
`complex=True` and a plain line that says so; nothing is guessed. Everything returned is escaped HTML (Markup).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from markupsafe import Markup, escape

from suriharvest.identity import LEGACY_MODIFIER_BUFFERS, NON_BUFFER_DOTTED, STICKY_ALIASES
from suriharvest.parser import ParseError, decode_content, parse_rule, unquote

MAX_CONTENTS = 6
MAX_IN_SENTENCE = 4

BUFFER_WORDS = {
    "http.uri": "URI",
    "http.uri.raw": "raw URI",
    "http.method": "request method",
    "http.header": "headers",
    "http.header.raw": "raw headers",
    "http.header_names": "header names",
    "http.host": "Host header",
    "http.host.raw": "raw Host header",
    "http.user_agent": "User-Agent",
    "http.cookie": "Cookie header",
    "http.request_body": "request body",
    "http.client_body": "request body",
    "http.response_body": "response body",
    "http.stat_code": "status code",
    "http.stat_msg": "status message",
    "http.content_type": "Content-Type",
    "http.content_len": "Content-Length",
    "http.referer": "Referer",
    "http.request_line": "request line",
    "http.response_line": "response line",
    "http.server": "Server header",
    "http.location": "Location header",
    "http.accept": "Accept header",
    "http.accept_enc": "Accept-Encoding",
    "http.accept_lang": "Accept-Language",
    "http.connection": "Connection header",
    "http.protocol": "HTTP version",
    "http.start": "request start",
    "http.request_header": "an HTTP/2 request header",
    "http.response_header": "an HTTP/2 response header",
    "file.data": "body",
    "file.name": "file name",
    "file.magic": "file type",
    "dns.query": "DNS query name",
    "dns.answer.name": "DNS answer name",
    "dns.queries.rrname": "DNS query name",
    "tls.sni": "server name (SNI)",
    "quic.sni": "QUIC server name",
    "tls.cert_subject": "certificate subject",
    "tls.cert_issuer": "certificate issuer",
    "tls.cert_serial": "certificate serial",
    "tls.cert_fingerprint": "certificate SHA-1",
    "tls.certs": "certificate chain",
    "tls.version": "TLS version",
    "tls.subjectaltname": "certificate SAN",
    "ja3.hash": "JA3 hash",
    "ja3.string": "JA3 string",
    "ja3s.hash": "JA3S hash",
    "ja3s.string": "JA3S string",
    "ja4.hash": "JA4 hash",
    "ssh.proto": "SSH protocol version",
    "ssh.software": "SSH software version",
    "ssh.hassh": "HASSH",
    "ssh.hassh.server": "server HASSH",
    "smb.named_pipe": "named pipe",
    "smb.share": "share name",
    "smtp.helo": "SMTP HELO",
    "smtp.mail_from": "MAIL FROM",
    "smtp.rcpt_to": "RCPT TO",
    "krb5.cname": "Kerberos client name",
    "krb5.sname": "Kerberos service name",
    "sip.method": "SIP method",
    "sip.uri": "SIP URI",
    "pkt": "packet",
    "pkt_data": "packet",
    "base64_data": "base64-decoded data",
    "dce_stub_data": "DCE/RPC stub data",
    "": "payload",
}

APP_WORDS = {
    "http": ("an HTTP request", "an HTTP response", "HTTP traffic", "HTTP request", "HTTP response"),
    "tls": ("a TLS handshake", "a TLS handshake", "a TLS connection", "TLS client hello", "TLS server hello"),
    "dns": ("a DNS query", "a DNS response", "DNS traffic", "DNS query", "DNS response"),
    "smb": ("SMB traffic", "SMB traffic", "SMB traffic", "SMB", "SMB"),
    "ssh": ("an SSH session", "an SSH session", "an SSH session", "SSH", "SSH"),
    "smtp": ("an email (SMTP)", "an SMTP reply", "SMTP traffic", "SMTP", "SMTP"),
    "ftp": ("an FTP command", "an FTP reply", "FTP traffic", "FTP", "FTP"),
    "krb5": ("a Kerberos request", "a Kerberos reply", "Kerberos traffic", "Kerberos", "Kerberos"),
    "quic": ("a QUIC connection", "a QUIC connection", "a QUIC connection", "QUIC", "QUIC"),
    "file": ("a file transfer", "a file download", "a file transfer", "file", "file"),
    "icmp": ("an ICMP packet", "an ICMP packet", "an ICMP packet", "ICMP", "ICMP"),
    "tcp": ("TCP traffic", "TCP traffic", "TCP traffic", "TCP", "TCP"),
    "udp": ("UDP traffic", "UDP traffic", "UDP traffic", "UDP", "UDP"),
    "ip": ("IP traffic", "IP traffic", "IP traffic", "IP", "IP"),
}

PARSERS = {
    "http": "the HTTP parser (on by default)",
    "tls": "the TLS parser (on by default)",
    "dns": "the DNS parser (on by default)",
    "smb": "the SMB parser (on by default)",
    "ssh": "the SSH parser (on by default)",
    "smtp": "the SMTP parser (on by default)",
    "ftp": "the FTP parser (on by default)",
    "krb5": "the Kerberos parser",
    "quic": "the QUIC parser",
    "dcerpc": "the DCE/RPC parser (on by default)",
    "modbus": "the Modbus parser (off by default: enable it in suricata.yaml)",
    "dnp3": "the DNP3 parser (off by default: enable it in suricata.yaml)",
    "enip": "the ENIP parser (off by default: enable it in suricata.yaml)",
}

ADDR_WORDS = {
    "$home_net": ("your network", "a host in your network"),
    "$external_net": ("outside", "an outside host"),
    "$http_servers": ("your web servers", "one of your web servers"),
    "$smtp_servers": ("your mail servers", "one of your mail servers"),
    "$dns_servers": ("your DNS servers", "one of your DNS servers"),
    "$sql_servers": ("your SQL servers", "one of your SQL servers"),
    "$telnet_servers": ("your telnet servers", "one of your telnet servers"),
    "$aim_servers": ("AIM servers", "an AIM server"),
    "$dc_servers": ("your domain controllers", "one of your domain controllers"),
    "$modbus_server": ("your Modbus devices", "one of your Modbus devices"),
    "$modbus_client": ("your Modbus clients", "one of your Modbus clients"),
    "any": ("any host", "any host"),
}

COMPLEX_OPTIONS = frozenset({"lua", "luajit", "byte_math"})


@dataclass
class End:
    label: str
    addr: str
    role: str


@dataclass
class Traffic:
    left: End
    right: End
    wire: str
    note: str
    both: bool = False


@dataclass
class Step:
    html: Markup
    gate: bool = False


@dataclass
class Summary:
    plain: Markup
    short: Markup
    traffic: Traffic | None = None
    steps: list[Step] = field(default_factory=list)
    needs: list[Markup] = field(default_factory=list)
    complex: bool = False
    sets: list[str] = field(default_factory=list)  # flowbits this rule sets
    noalert: bool = False


@dataclass
class _Check:
    buffer: str
    kind: str  # content | pcre | other
    value: str  # display value (content text or pattern)
    negated: bool = False
    mods: dict[str, str | None] = field(default_factory=dict)


def _c(x: str, limit: int = 64) -> Markup:
    x = x if len(x) <= limit else x[: limit - 1] + "…"
    return Markup("<code>{}</code>").format(x)


def _content_text(value: str) -> tuple[str, bool]:
    """Readable form of a content value: the text when it is printable, else the |hex| as written."""
    try:
        data, neg = decode_content(value)
    except ParseError:
        return value.strip().strip('"'), value.strip().startswith("!")
    try:
        txt = data.decode("utf-8")
    except UnicodeDecodeError:
        txt = ""
    if txt and all(ch.isprintable() or ch == " " for ch in txt):
        return txt, neg
    if txt and sum(ch.isprintable() for ch in txt) >= 0.6 * len(txt):
        esc_ = {"\r": "\\r", "\n": "\\n", "\t": "\\t"}
        return "".join(ch if ch.isprintable() else esc_.get(ch, f"\\x{ord(ch):02x}") for ch in txt), neg
    raw = value.strip().lstrip("!").strip().strip('"')
    return raw, neg


def _buf_word(buf: str, to_client: bool) -> str:
    if buf in ("file.data", "http.response_body") and to_client:
        return "response body"
    if buf == "file.data":
        return "body"
    return BUFFER_WORDS.get(buf, buf)


def _v(word: str, verb: str) -> str:
    """Agree the verb with a plural buffer word ('headers contain', 'URI contains')."""
    if not word.endswith(("headers", "names")):
        return verb
    first, _, rest = verb.partition(" ")
    first = {"is": "are", "does": "do", "matches": "match"}.get(first, first.removesuffix("s"))
    return f"{first} {rest}".strip()


def _who(addr: str) -> tuple[str, str]:
    a = addr.strip().lower()
    if a in ADDR_WORDS:
        return ADDR_WORDS[a]
    if a.startswith("!$home_net") or a == "!$home_net":
        return ADDR_WORDS["$external_net"]
    if a.startswith("$"):
        return (addr, f"a host in {addr}")
    return (addr, addr)


def _end_label(addr: str, server: bool | None) -> str:
    a = addr.strip().lower()
    inside = a in ("$home_net",) or (a.startswith("$") and a.endswith("_servers") and a != "$external_net")
    outside = a in ("$external_net", "!$home_net")
    if a.endswith("_servers") or a == "$dc_servers":
        return "Your server"
    if inside:
        return "Your server" if server else "Your client" if server is False else "Your network"
    if outside:
        return "Outside server" if server else "Outside client" if server is False else "Outside host"
    if a == "any":
        return "Any host"
    return addr


def _rule_checks(rule) -> tuple[list[_Check], list[tuple[str, str]], list[str], dict[str, str | None]]:  # type: ignore[no-untyped-def]
    """Walk the options: checks in buffer order, gates (flowbits/xbits/dataset), options outside buffers."""
    checks: list[_Check] = []
    gates: list[tuple[str, str]] = []  # (kind, value)
    other: list[str] = []
    flow: dict[str, str | None] = {}
    buf = ""
    last: _Check | None = None
    for o in rule.options:
        n = STICKY_ALIASES.get(o.name, o.name)
        if (
            o.value is None
            and n not in NON_BUFFER_DOTTED
            and (n in STICKY_ALIASES.values() or "." in n or n in ("pkt_data", "base64_data"))
        ):
            buf = "pkt" if n == "pkt_data" else n
            last = None
            continue
        if n in LEGACY_MODIFIER_BUFFERS and last is not None:
            last.buffer = LEGACY_MODIFIER_BUFFERS[n]
            continue
        if n in ("content", "uricontent") and o.value is not None:
            txt, neg = _content_text(o.value)
            last = _Check("http.uri" if n == "uricontent" else buf, "content", txt, neg)
            checks.append(last)
            continue
        if (
            n in ("nocase", "depth", "offset", "distance", "within", "startswith", "endswith", "fast_pattern", "rawbytes", "dotprefix")
            and last
        ):
            last.mods[n] = o.value
            continue
        if n == "isdataat" and last is not None:
            last.mods["isdataat"] = o.value
            continue
        if n == "pcre" and o.value is not None:
            last = _Check(buf, "pcre", unquote(o.value))
            checks.append(last)
            continue
        if n == "bsize" and o.value is not None:
            checks.append(_Check(buf, "bsize", o.value))
            continue
        if n in ("flowbits", "xbits") and o.value:
            parts = [p.strip() for p in o.value.split(",")]
            gates.append((n, ",".join(parts)))
            continue
        if n in ("dataset", "datarep") and o.value:
            gates.append((n + ":" + buf, o.value))
            continue
        if n == "flow" and o.value:
            for p in o.value.split(","):
                flow[p.strip().lower()] = None
            continue
        if n in ("msg", "sid", "rev", "gid", "classtype", "reference", "metadata", "priority", "target", "tag", "fast_pattern"):
            continue
        other.append(n + (f":{o.value}" if o.value else ""))
    return checks, gates, other, flow


def _check_phrase(ch: _Check, to_client: bool, prev: _Check | None) -> str:
    """'whose URI contains <code>x</code>' style (escaped HTML)."""
    word = _buf_word(ch.buffer, to_client)
    if ch.kind == "pcre":
        return f"whose {escape(word)} {_v(word, 'matches')} the pattern {_c(ch.value, 48)}"
    if ch.kind == "bsize":
        return f"whose {escape(word)} {_v(word, 'is')} {escape(ch.value)} bytes long"
    if ch.kind != "content":
        return ""
    v = _c(ch.value)
    if prev is not None and prev.buffer == ch.buffer and ("distance" in ch.mods or "within" in ch.mods):
        return f"followed by {v}" if not ch.negated else f"not followed by {v}"
    if ch.negated:
        return f"whose {escape(word)} {_v(word, 'does not contain')} {v}"
    s, e = "startswith" in ch.mods, "endswith" in ch.mods
    if s and e:
        return f"whose {escape(word)} {_v(word, 'is exactly')} {v}"
    if s or (ch.mods.get("depth") is not None and ch.mods.get("depth") == str(len(ch.value)) and "offset" not in ch.mods):
        return f"whose {escape(word)} {_v(word, 'starts with')} {v}"
    if e:
        return f"whose {escape(word)} {_v(word, 'ends with')} {v}"
    return f"whose {escape(word)} {_v(word, 'contains')} {v}"


def _step(ch: _Check, to_client: bool, prev: _Check | None) -> Markup:
    word = _buf_word(ch.buffer, to_client)
    cap = word[:1].upper() + word[1:]
    raw_mods = []
    if ch.buffer:
        raw_mods.append(ch.buffer)
    for k, val in ch.mods.items():
        if k in ("fast_pattern",):
            continue
        raw_mods.append(k if val is None else f"{k}:{val}")
    hint = Markup(' <span class="muted xs">{}</span>').format(" ".join(raw_mods)) if raw_mods else Markup("")
    if ch.kind == "pcre":
        return Markup("{} {} the pattern {}").format(cap, _v(word, "matches"), _c(ch.value, 80)) + hint
    if ch.kind == "bsize":
        return Markup("{} {} {} bytes long").format(cap, _v(word, "is"), ch.value) + hint
    v = _c(ch.value)
    extra = []
    if "nocase" in ch.mods:
        extra.append("any case")
    if ch.mods.get("depth") and "startswith" not in ch.mods:
        extra.append(f"in the first {ch.mods['depth']} bytes")
    if ch.mods.get("offset"):
        extra.append(f"from byte {ch.mods['offset']}")
    if ch.mods.get("within"):
        extra.append(f"within {ch.mods['within']} bytes")
    if (iv := ch.mods.get("isdataat")) is not None and iv.startswith("!") and "relative" in iv:
        extra.append("and nothing after it")
    tail = Markup(" ({})").format(", ".join(extra)) if extra else Markup("")
    neg = _v(word, "does not contain" if ch.negated else "contains")
    if prev is not None and prev.buffer == ch.buffer and "distance" in ch.mods:
        d = ch.mods["distance"] or "0"
        where = "somewhere after it" if d.strip() == "0" else f"{d} bytes after it"
        if ch.negated:
            return Markup("…and not {}, {}").format(where, v) + tail + hint
        return Markup("…and {}, {}").format(where, v) + tail + hint
    s, e = "startswith" in ch.mods, "endswith" in ch.mods
    if s and e:
        return Markup("{} {} {}").format(cap, _v(word, "is exactly"), v) + tail + hint
    if s:
        return Markup("{} {} {}").format(cap, _v(word, "starts with"), v) + tail + hint
    if e:
        return Markup("{} {} {}").format(cap, _v(word, "ends with"), v) + tail + hint
    return Markup("{} {} {}").format(cap, neg, v) + tail + hint


def _bit_name(v: str) -> tuple[str, str]:
    parts = [p.strip() for p in v.split(",")]
    return parts[0].lower(), (parts[1] if len(parts) > 1 else "")


def summarize(
    raw: str,
    *,
    app_layer: str | None = None,
    ioc_type: str | None = None,
    ioc_value: str | None = None,
    setters: dict[str, int] | None = None,
    msg: str | None = None,
) -> Summary:
    """setters: flowbit name (without the flowbits: prefix) -> sid of a rule that sets it."""
    try:
        rule = parse_rule(raw)
    except ParseError:
        return Summary(plain=Markup("{} The rule's own text is below.").format(msg or ""), short=Markup(""), complex=True)
    setters = setters or {}
    app = (app_layer or rule.protocol or "").lower()
    checks, gates, other, flow = _rule_checks(rule)
    to_client = "to_client" in flow or "from_server" in flow
    to_server = "to_server" in flow or "from_client" in flow
    idx = 3 if to_server else 4 if to_client else 2
    words = APP_WORDS.get(app, (f"{app.upper()} traffic",) * 3 + (app.upper(),) * 2)
    proto_long = words[0] if to_server else words[1] if to_client else words[2]
    wire = words[idx] if idx > 2 else words[3] if app not in ("http", "dns") else words[2].replace(" traffic", "")

    src_short, src_long = _who(rule.src_addr)
    dst_short, dst_long = _who(rule.dst_addr)
    both = rule.direction in ("<>", "=>")
    # traffic strip
    src_server = True if to_client else False if to_server else None
    dst_server = None if src_server is None else not src_server
    left = End(
        _end_label(rule.src_addr, src_server),
        f"{rule.src_addr} {rule.src_port}",
        "sends the response" if to_client else "sends the request" if to_server else "sends",
    )
    right = End(_end_label(rule.dst_addr, dst_server), f"{rule.dst_addr} {rule.dst_port}", "receives it")
    if right.label.startswith("Outside"):
        right.role = "the attacker" if to_client else "receives it"
    flow_note = []
    if "established" in flow:
        flow_note.append("established flow")
    if to_server:
        flow_note.append("to the server")
    elif to_client:
        flow_note.append("to the client")
    if both:
        flow_note.append("both directions")
    traffic = Traffic(left, right, wire, ", ".join(flow_note) or "any packet", both)

    sets, noalert = [], False
    steps: list[Step] = []
    needs: list[Markup] = []
    dep_clause = Markup("")
    for kind, v in gates:
        if kind in ("flowbits", "xbits"):
            op, name = _bit_name(v)
            label = "flowbit" if kind == "flowbits" else "xbit"
            if op == "noalert":
                noalert = True
                continue
            if op in ("set", "toggle"):
                sets.append(name)
                continue
            if op == "unset":
                continue
            names = [x for x in re.split(r"[|&]", name) if x]
            for nm in names:
                by = setters.get(nm)
                who = Markup(" (set by sid {})").format(by) if by else Markup(" (no rule in the index sets it)")
                if op == "isset":
                    steps.append(Step(Markup("Only if {} {} is set on this connection").format(label, _c(nm)) + who, gate=True))
                    if by:
                        needs.append(
                            Markup("<b>sid {} enabled in the same ruleset</b>, because it sets the {} {}").format(by, label, _c(nm))
                        )
                        if not dep_clause:
                            dep_clause = Markup(" &mdash; <b>but only on connections where rule {} already set {} {}</b>").format(
                                by, label, _c(nm)
                            )
                    elif not dep_clause:
                        dep_clause = Markup(" &mdash; <b>but only when {} {} is set, and no rule in the index sets it</b>").format(
                            label, _c(nm)
                        )
                elif op == "isnotset":
                    steps.append(Step(Markup("Only if {} {} is <b>not</b> set on this connection").format(label, _c(nm)), gate=True))
        elif kind.startswith(("dataset", "datarep")):
            dkind, _, b = kind.partition(":")
            parts = [p.strip() for p in v.split(",")]
            word = _buf_word(b, to_client)
            name = parts[1] if len(parts) > 1 else v
            steps.append(Step(Markup("Only if the {} is in {} {}").format(word, dkind, _c(name)), gate=True))
            if m := re.search(r"\b(?:load|state)\s+([^,\s]+)", v):
                needs.append(Markup("the {} file {} next to the rules").format(dkind, _c(m.group(1))))
    prev = None
    for ch in checks:
        steps.append(Step(_step(ch, to_client, prev)))
        prev = ch
    for o in other:
        name, _, val = o.partition(":")
        if name in ("threshold", "detection_filter"):
            steps.append(Step(Markup("Rate limit: {}").format(_c(o, 80))))
        elif name in ("dsize",):
            steps.append(Step(Markup("Payload size is {}").format(_c(val))))
        elif name in ("urilen",):
            steps.append(Step(Markup("URI length is {}").format(_c(val))))
        elif name in (
            "byte_test",
            "byte_jump",
            "byte_extract",
            "isdataat",
            "ssl_state",
            "ssl_version",
            "app-layer-event",
            "stream_size",
            "itype",
            "icode",
            "ip_proto",
            "flags",
            "ttl",
            "dce_iface",
            "dce_opnum",
        ):
            steps.append(Step(Markup("Also checks {}").format(_c(o, 80))))
        elif name in ("lua", "luajit"):
            needs.append(
                Markup("the lua script {} next to the rules (and <code>security.lua.allow-rules</code> in Suricata 8)").format(_c(val))
            )
            steps.append(Step(Markup("Runs the lua script {}").format(_c(val))))
    for b in sets:
        steps.append(Step(Markup("Then marks the connection with flowbit {} for other rules").format(_c(b))))
    if noalert:
        steps.append(Step(Markup("Never alerts on its own: it only sets the flowbit")))

    if app in PARSERS:
        needs.insert(0, Markup(PARSERS[app]))  # noqa: S704 (constant table of our own HTML)
    bufs = {c.buffer for c in checks}
    if bufs & {"ja3.hash", "ja3.string", "ja3s.hash", "ja3s.string"}:
        needs.append(
            Markup(
                "JA3 turned on: Suricata 8 needs <code>tls.ja3-fingerprints: yes</code> (Suricata 7: <code>app-layer.protocols.tls.ja3-fingerprints</code>)"
            )
        )
    if bufs & {"ja4.hash"}:
        needs.append(Markup("Suricata 7.0.3 or newer with JA4 turned on (<code>ja4-fingerprints: yes</code>)"))

    contents = [c for c in checks if c.kind == "content"]
    too_complex = (
        len(contents) > MAX_CONTENTS
        or (not contents and any(c.kind == "pcre" for c in checks))
        or any(o.split(":")[0] in COMPLEX_OPTIONS for o in other)
    )
    subject = src_long
    target = dst_long
    if to_client:
        lead = Markup("Alerts when <b>{}</b> answers {} with {}").format(subject, target, proto_long)
    elif to_server or app not in ("tcp", "udp", "ip", "icmp"):
        lead = Markup("Alerts when <b>{}</b> sends {} to {}").format(subject, proto_long, target)
    else:
        lead = Markup("Alerts on {} from <b>{}</b> to {}").format(proto_long, subject, target)

    # IOC rules: one indicator, say it directly
    if ioc_type and ioc_value and not too_complex:
        ioc_line = _ioc_line(ioc_type, ioc_value, src_short, dst_short)
        if ioc_line is not None:
            plain = Markup("{}{}.").format(ioc_line, dep_clause)
            return Summary(plain, ioc_line + Markup("."), traffic, steps, needs, False, sets, noalert)

    if too_complex:
        many = len(contents) > MAX_CONTENTS and not any(o.split(":")[0] in COMPLEX_OPTIONS for o in other)
        if many:
            plain = lead + dep_clause + Markup(". It checks {} things, listed below in order.").format(len(checks))
            short = Markup("{} from {} to {}, {} checks.").format(
                _cap(words[3] if to_server else words[4] if to_client else words[2]), src_short, dst_short, len(checks)
            )
        else:
            plain = Markup("{}: too involved to say in a sentence without guessing; the rule's own text is below.").format(
                msg or "This rule"
            )
            short = Markup("")
        return Summary(plain, short, traffic, steps, needs, not many, sets, noalert)

    phrases = []
    prev = None
    for ch in checks[:MAX_IN_SENTENCE]:
        ph = _check_phrase(ch, to_client, prev)
        if ph:
            phrases.append(Markup(ph))  # noqa: S704 (_check_phrase escapes every rule value)
        prev = ch
    more = len(checks) - MAX_IN_SENTENCE
    if phrases:
        body = _join(phrases)
        if more > 0:
            body += Markup(", plus {} more check{}").format(more, "s" if more > 1 else "")
        plain = lead + Markup(" ") + body + dep_clause + Markup(".")
    else:
        plain = lead + dep_clause + Markup(".")
    if noalert:
        plain += Markup(" It never alerts by itself: it marks the connection for other rules.")

    # short line for search results
    short_lead = Markup("{} from {} to {}").format(
        _cap(words[3] if to_server else words[4] if to_client else words[2]), src_short, dst_short
    )
    sp = [Markup(_check_phrase(ch, to_client, None)) for ch in checks[:2] if ch.kind in ("content", "pcre")]  # noqa: S704 (escaped)
    short = short_lead + (Markup(" ") + _join(sp) if sp else Markup("")) + Markup(".")
    gate_bits = [_bit_name(v)[1] for k, v in gates if k == "flowbits" and _bit_name(v)[0] == "isset"]
    if gate_bits:
        short += Markup(" <b>Needs</b> flowbit {}.").format(_c(gate_bits[0]))
    return Summary(plain, short, traffic, steps, needs, False, sets, noalert)


def _cap(s: str) -> str:
    return s[:1].upper() + s[1:]


def _join(parts: list[Markup]) -> Markup:
    if len(parts) == 1:
        return parts[0]
    out = Markup("")
    for i, p in enumerate(parts):
        if i == 0:
            out += p
        elif i == len(parts) - 1 and not str(p).startswith("followed"):
            out += Markup(" and ") + p
        else:
            out += (Markup(" ") if str(p).startswith("followed") else Markup(", ")) + p
    return out


def _ioc_line(kind: str, value: str, src: str, dst: str) -> Markup | None:
    if kind == "domain":
        return Markup("Connection from {} whose server name is {} or a subdomain of it").format(src, _c(value))
    if kind == "ja3":
        return Markup("TLS client hello whose JA3 hash is {}").format(_c(value))
    if kind == "ja3s":
        return Markup("TLS server hello whose JA3S hash is {}").format(_c(value))
    if kind == "ja4":
        return Markup("TLS client hello whose JA4 fingerprint is {}").format(_c(value))
    if kind == "cert_fingerprint":
        return Markup("TLS server certificate with SHA-1 {}").format(_c(value))
    if kind == "cert_serial":
        return Markup("TLS server certificate with serial {}").format(_c(value))
    if kind == "url":
        return Markup("HTTP request from {} to the URL {}").format(src, _c(value))
    if kind == "ip":
        return Markup("Traffic between {} and the address {}").format(src if src != value else dst, _c(value))
    return None


# ---------------------------------------------------------------------------------------------------------------
# revisions: one line saying what changed between two versions of a rule


def rev_diff(old_raw: str | None, new_raw: str) -> Markup:
    if not old_raw:
        return Markup("First seen")
    try:
        a, b = parse_rule(old_raw), parse_rule(new_raw)
    except ParseError:
        return Markup("Rule text changed")
    skip = {"rev", "sid", "metadata", "msg", "reference"}
    ao = [f"{o.name}:{o.value}" if o.value is not None else o.name for o in a.options if o.name not in skip]
    bo = [f"{o.name}:{o.value}" if o.value is not None else o.name for o in b.options if o.name not in skip]
    sa, sb = set(ao), set(bo)  # set membership: a rule with thousands of options stays linear
    added = [x for x in bo if x not in sa]
    removed = [x for x in ao if x not in sb]
    parts: list[Markup] = []
    if added:
        parts.append(
            Markup("added {}").format(_c("; ".join(added[:3]), 90))
            + (Markup(" and {} more").format(len(added) - 3) if len(added) > 3 else "")
        )
    if removed:
        parts.append(
            Markup("removed {}").format(_c("; ".join(removed[:3]), 90))
            + (Markup(" and {} more").format(len(removed) - 3) if len(removed) > 3 else "")
        )
    if not added and not removed and ao != bo:
        parts.append(Markup("same options, new order"))
    if a.msg != b.msg:
        parts.append(Markup("msg now {}").format(Markup("&ldquo;{}&rdquo;").format(b.msg or "")))
    if (a.src_addr, a.src_port, a.direction, a.dst_addr, a.dst_port, a.protocol) != (
        b.src_addr,
        b.src_port,
        b.direction,
        b.dst_addr,
        b.dst_port,
        b.protocol,
    ):
        parts.append(Markup("header now {}").format(_c(f"{b.protocol} {b.src_addr} {b.src_port} {b.direction} {b.dst_addr} {b.dst_port}")))
    if not parts:
        meta_a, meta_b = a.get_all("metadata"), b.get_all("metadata")
        if meta_a != meta_b:
            return Markup("Metadata only")
        if a.get_all("reference") != b.get_all("reference"):
            return Markup("References only")
        return Markup("No change in the logic")
    out = parts[0]
    for p in parts[1:]:
        out += Markup("; ") + p
    return Markup(str(out)[:1].upper()) + Markup(str(out)[1:])  # noqa: S704 (out is already Markup)
