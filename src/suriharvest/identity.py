"""Rule identity: content_hash, rule_key, logic_hash, semantic_hash (see docs/identity.md).

content_hash  - exact rule text (logical line, "#" stripped). Enabled state lives on the occurrence.
logic_hash    - canonical header + detection options in order; metadata, action, alerting and performance options out.
semantic_hash - parse tree normalised further: legacy content modifiers become sticky buffers, matches grouped per
                buffer, buffer groups sorted, startswith == depth at offset 0, pcre delimiters/flags normalised.
alerting_hash - threshold/detection_filter/noalert: how often a rule alerts, not what it matches.

Every hashed payload starts with a version string. Changing canonicalisation means bumping it (and re-indexing).
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Any

from suriharvest.parser import Option, ParseError, Rule, decode_content, encode_content, unquote

LOGIC_VERSION = "suriharvest-logic-v1"
SEMANTIC_VERSION = "suriharvest-semantic-v1"
ALERTING_VERSION = "suriharvest-alerting-v1"
FACTS_REVISION = "facts-9"  # bump when any fact computed at ingest changes (IOC rules, flags, ...)
FACTS_VERSION = f"{LOGIC_VERSION}|{SEMANTIC_VERSION}|{ALERTING_VERSION}|{FACTS_REVISION}"

# Options that describe a rule but do not change what it matches.
METADATA_OPTIONS = frozenset({"msg", "sid", "rev", "gid", "classtype", "priority", "reference", "metadata", "target"})
# Options that change how often a rule alerts, not what matches.
ALERTING_OPTIONS = frozenset({"threshold", "detection_filter", "noalert"})
# Options that only change prefilter performance.
PERFORMANCE_OPTIONS = frozenset({"fast_pattern", "prefilter"})

# Modifiers that belong to the preceding content (their order among themselves does not matter).
CONTENT_MODIFIERS = frozenset({"nocase", "depth", "offset", "distance", "within", "rawbytes", "fast_pattern", "startswith", "endswith"})
# Legacy content modifiers -> sticky buffer (Suricata 5+ names).
LEGACY_MODIFIER_BUFFERS = {
    "http_uri": "http.uri",
    "http_raw_uri": "http.uri.raw",
    "http_header": "http.header",
    "http_raw_header": "http.header.raw",
    "http_cookie": "http.cookie",
    "http_method": "http.method",
    "http_client_body": "http.request_body",
    "http_server_body": "http.response_body",
    "http_stat_code": "http.stat_code",
    "http_stat_msg": "http.stat_msg",
    "http_user_agent": "http.user_agent",
    "http_host": "http.host",
    "http_raw_host": "http.host.raw",
}
# Legacy sticky buffer names -> current names.
STICKY_ALIASES = {
    "file_data": "file.data",
    "dns_query": "dns.query",
    "tls_sni": "tls.sni",
    "tls_cert_subject": "tls.cert_subject",
    "tls_cert_issuer": "tls.cert_issuer",
    "tls_cert_serial": "tls.cert_serial",
    "tls_cert_fingerprint": "tls.cert_fingerprint",
    "ja3_hash": "ja3.hash",
    "ja3_string": "ja3.string",
    "ja3s_hash": "ja3s.hash",
    "ja3s_string": "ja3s.string",
    "http_request_line": "http.request_line",
    "http_response_line": "http.response_line",
    "http_header_names": "http.header_names",
    "http_accept": "http.accept",
    "http_accept_enc": "http.accept_enc",
    "http_accept_lang": "http.accept_lang",
    "http_referer": "http.referer",
    "http_content_type": "http.content_type",
    "http_content_len": "http.content_len",
    "http_connection": "http.connection",
    "http_start": "http.start",
    "http_protocol": "http.protocol",
    "ssh_proto": "ssh.proto",
    "ssh_software": "ssh.software",
    "smb_named_pipe": "smb.named_pipe",
    "smb_share": "smb.share",
    "krb5_cname": "krb5.cname",
    "krb5_sname": "krb5.sname",
    "sip_method": "sip.method",
    "sip_uri": "sip.uri",
}
# pcre flags that select an HTTP buffer.
PCRE_BUFFER_FLAGS = {
    "U": "http.uri",
    "I": "http.uri.raw",
    "H": "http.header",
    "D": "http.header.raw",
    "C": "http.cookie",
    "M": "http.method",
    "P": "http.request_body",
    "Q": "http.response_body",
    "S": "http.stat_code",
    "Y": "http.stat_msg",
    "V": "http.user_agent",
    "W": "http.host",
    "Z": "http.host.raw",
}
# Keywords that operate on the current buffer (their position relative to contents matters).
BUFFER_RELATIVE = frozenset(
    {
        "content",
        "uricontent",
        "pcre",
        "isdataat",
        "byte_test",
        "byte_jump",
        "byte_extract",
        "byte_math",
        "bsize",
        "base64_decode",
        "base64_data",
        "dataset",
        "datarep",
        "entropy",
        "from_base64",
        "lua",
        "luajit",
        "dotprefix",
        "to_md5",
        "to_sha1",
        "to_sha256",
        "to_lowercase",
        "to_uppercase",
        "strip_whitespace",
        "compress_whitespace",
        "url_decode",
        "xor",
        "pcrexform",
        "header_lowercase",
        "strip_pseudo_headers",
        "domain",
        "tld",
    }
)
# Keywords Snort supports and Suricata does not (foreign syntax).
SNORT_ONLY = frozenset(
    {
        "service",
        "file_type",
        "bufferlen",
        "js_data",
        "http_param",
        "http_raw_body",
        "http_true_ip",
        "http_version_match",
        "sd_pattern",
        "regex",
        "ber_data",
        "ber_skip",
        "so",
        "soid",
        "rem",
        "resp",
        "react",
        "logto",
        "session",
        "http_encode",
        "sip_stat_code",
        "sip_header",
        "sip_body",
        "gtp_type",
        "gtp_info",
        "gtp_version",
        "modbus_func",
        "modbus_unit",
        "modbus_data",
        "cvs",
        "replace_all",
        "activates",
        "activated_by",
        "count",
        "file_data:mime",
    }
)

# Dotted keywords without a value that are not sticky buffers.
NON_BUFFER_DOTTED = frozenset({"tls.store", "dns.opcode"})

IOC_BUFFERS = {
    "dns.query": "domain",
    "tls.sni": "domain",
    "http.host": "domain",
    "quic.sni": "domain",
    "ja3.hash": "ja3",
    "ja3s.hash": "ja3s",
    "ja4.hash": "ja4",
    "tls.cert_fingerprint": "cert_fingerprint",
    "tls.cert_serial": "cert_serial",
}
IOC_ALLOWED_GLOBALS = frozenset({"flow", "app-layer-protocol", "ssl_state", "noalert"})
IOC_ALLOWED_MODIFIERS = frozenset({"nocase", "endswith", "startswith", "fast_pattern", "dotprefix", "isdataat", "bsize", "depth", "offset"})

APP_PROTOCOLS = frozenset(
    {
        "http",
        "http1",
        "http2",
        "tls",
        "dns",
        "smb",
        "ssh",
        "ftp",
        "ftp-data",
        "smtp",
        "imap",
        "pop3",
        "dcerpc",
        "dhcp",
        "nfs",
        "ntp",
        "tftp",
        "ikev2",
        "ike",
        "krb5",
        "snmp",
        "sip",
        "rfb",
        "mqtt",
        "rdp",
        "modbus",
        "dnp3",
        "enip",
        "quic",
        "websocket",
        "ldap",
        "pgsql",
        "telnet",
        "bittorrent-dht",
        "doh2",
    }
)


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _hash(version: str, obj: Any) -> str:
    return sha256_hex(version + "\n" + json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")))


# ---------------------------------------------------------------------------------------------------------------
# header


def _split_list(s: str) -> list[str]:
    """Split "a,b,[c,d]" on top-level commas."""
    out, cur, depth = [], [], 0
    for ch in s:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
            continue
        cur.append(ch)
    if cur or out:
        out.append("".join(cur).strip())
    return [x for x in out if x]


def _canon_ip(tok: str) -> str:
    try:
        net = ipaddress.ip_network(tok, strict=False)
    except ValueError:
        return tok
    if net.num_addresses == 1:
        return str(net.network_address)
    return str(net)


MAX_ADDR_DEPTH = 64  # nested [..] lists; a deeper (hostile) one is a parse error, not a RecursionError for the file


def canon_addr(expr: str, kind: str = "addr", _depth: int = 0) -> str:
    """Canonical address/port expression: lists sorted, negation kept, variables kept, 'any' lower case."""
    if _depth > MAX_ADDR_DEPTH:
        raise ParseError(f"address list nested deeper than {MAX_ADDR_DEPTH} levels")
    e = expr.strip().replace(" ", "")
    neg = ""
    while e.startswith("!"):
        neg = "" if neg else "!"
        e = e[1:]
    if e.startswith("[") and e.endswith("]"):
        members = sorted({canon_addr(m, kind, _depth + 1) for m in _split_list(e[1:-1])})
        if len(members) == 1:
            return neg + members[0]
        return neg + "[" + ",".join(members) + "]"
    if e.lower() == "any":
        return neg + "any"
    if kind == "addr" and not e.startswith("$"):
        return neg + _canon_ip(e)
    return neg + e


def canon_header(rule: Rule) -> dict[str, Any]:
    src = [canon_addr(rule.src_addr), canon_addr(rule.src_port, "port")]
    dst = [canon_addr(rule.dst_addr), canon_addr(rule.dst_port, "port")]
    if rule.direction == "<>":
        src, dst = sorted([src, dst])
    return {"proto": rule.protocol, "src": src, "dir": rule.direction, "dst": dst}


# ---------------------------------------------------------------------------------------------------------------
# option values


def _norm_ws(v: str) -> str:
    """Collapse whitespace, remove spaces around commas, outside quotes."""
    out, q = [], False
    for ch in v:
        if ch == '"':
            q = not q
        out.append(ch)
    s = "".join(out).strip()
    if '"' in s:
        return s
    s = re.sub(r"\s*,\s*", ",", s)
    return re.sub(r"\s+", " ", s)


def canon_content(value: str, nocase: bool) -> str:
    data, neg = decode_content(value)
    if nocase:
        data = data.lower()
    return ("!" if neg else "") + encode_content(data)


def parse_pcre(value: str) -> tuple[bool, str, str]:
    """(negated, pattern, flags) of a pcre value. Raises ParseError."""
    v = value.strip()
    neg = v.startswith("!")
    if neg:
        v = v[1:].strip()
    if v.startswith('"') and v.endswith('"') and len(v) >= 2:
        v = v[1:-1]
    if v.startswith("m") and len(v) > 1 and not v[1].isalnum():
        delim, body = v[1], v[2:]
    elif v.startswith("/"):
        delim, body = "/", v[1:]
    else:
        raise ParseError("pcre without delimiter")
    end = body.rfind(delim)
    if end < 0:
        raise ParseError("pcre without closing delimiter")
    pattern, flags = body[:end], body[end + 1 :]
    if delim != "/":
        pattern = pattern.replace("/", "\\/")
    return neg, pattern.replace("\\;", ";").replace('\\"', '"'), "".join(sorted(set(flags)))


def canon_value(name: str, value: str | None, nocase: bool = False) -> str | None:
    if value is None:
        return None
    if name in ("content", "uricontent"):
        return canon_content(value, nocase)
    if name == "pcre":
        neg, pat, flags = parse_pcre(value)
        return ("!" if neg else "") + "/" + pat + "/" + flags
    if name == "flow":
        return ",".join(sorted(p.strip().lower() for p in value.split(",") if p.strip()))
    return _norm_ws(value)


# ---------------------------------------------------------------------------------------------------------------
# option groups


@dataclass
class Item:
    """A detection option with the content modifiers that follow it."""

    name: str
    value: str | None
    mods: list[tuple[str, str | None]] = field(default_factory=list)

    def mod(self, name: str) -> bool:
        return any(m[0] == name for m in self.mods)

    def as_list(self) -> list[Any]:
        return [self.name, self.value, sorted([list(m) for m in self.mods], key=json.dumps)]


def group_items(options: list[Option]) -> list[Item]:
    """Detection options in order, each content/pcre carrying its modifiers. Metadata options are dropped here;
    alerting and performance options are dropped too (they are hashed separately or not at all)."""
    items: list[Item] = []
    for o in options:
        n = o.name
        if n in METADATA_OPTIONS or n in ALERTING_OPTIONS or n in PERFORMANCE_OPTIONS:
            continue
        if (n in CONTENT_MODIFIERS or n in LEGACY_MODIFIER_BUFFERS) and items and items[-1].name in ("content", "uricontent"):
            items[-1].mods.append((n, _norm_ws(o.value) if o.value is not None else None))
            continue
        items.append(Item(n, o.value))
    return items


def logic_tree(rule: Rule) -> dict[str, Any]:
    items = group_items(rule.options)
    body = []
    for it in items:
        nocase = it.mod("nocase")
        body.append([it.name, canon_value(it.name, it.value, nocase), sorted([list(m) for m in it.mods], key=json.dumps)])
    return {"header": canon_header(rule), "options": body}


def logic_hash(rule: Rule) -> str:
    return _hash(LOGIC_VERSION, logic_tree(rule))


def alerting_hash(rule: Rule) -> str:
    alerting = sorted([o.name, _norm_ws(o.value) if o.value else None] for o in rule.options if o.name in ALERTING_OPTIONS)
    return _hash(ALERTING_VERSION, alerting)


# ---------------------------------------------------------------------------------------------------------------
# semantic layer


@dataclass
class Semantic:
    globals: list[list[Any]]
    buffers: dict[str, list[list[Any]]]  # buffer -> matches in order

    def tree(self, header: dict[str, Any]) -> dict[str, Any]:
        groups = sorted([[b, m] for b, m in self.buffers.items()], key=json.dumps)
        return {"header": header, "globals": sorted(self.globals, key=json.dumps), "buffers": groups}


def _semantic_match(it: Item) -> list[Any]:
    mods: dict[str, str | None] = {}
    for name, val in it.mods:
        if name in LEGACY_MODIFIER_BUFFERS or name in PERFORMANCE_OPTIONS:
            continue
        mods[name] = val
    value = canon_value(it.name, it.value, "nocase" in mods)
    name = "content" if it.name == "uricontent" else it.name
    if name == "content" and "startswith" in mods and value is not None:
        data, _ = decode_content(it.value or "")
        mods.pop("startswith")
        mods["depth"] = str(len(data))
        mods.setdefault("offset", "0")
    if name == "content" and mods.get("offset") == "0":
        mods.pop("offset")
    if name == "pcre" and value is not None:
        # Buffer flags were moved to the buffer; keep only matching flags.
        head, _, flags = value.rpartition("/")
        value = head + "/" + "".join(f for f in flags if f not in PCRE_BUFFER_FLAGS)
    return [name, value, sorted([[k, v] for k, v in mods.items()], key=json.dumps)]


def semantic(rule: Rule) -> Semantic:
    items = group_items(rule.options)
    sem = Semantic([], {})
    buf = "pkt"
    for it in items:
        n = STICKY_ALIASES.get(it.name, it.name)
        if it.value is None and n not in NON_BUFFER_DOTTED and (n in STICKY_ALIASES.values() or "." in n or n == "pkt_data"):
            buf = "pkt" if n == "pkt_data" else n
            continue
        if n in BUFFER_RELATIVE:
            target = buf
            if n == "uricontent":
                target = "http.uri"
            for m, _ in it.mods:
                if m in LEGACY_MODIFIER_BUFFERS:
                    target = LEGACY_MODIFIER_BUFFERS[m]
            if n == "pcre" and it.value:
                _, _, flags = parse_pcre(it.value)
                for f in flags:
                    if f in PCRE_BUFFER_FLAGS:
                        target = PCRE_BUFFER_FLAGS[f]
            sem.buffers.setdefault(target, []).append(_semantic_match(it))
        else:
            sem.globals.append([n, canon_value(n, it.value)])
    return sem


def semantic_hash(rule: Rule) -> str:
    return _hash(SEMANTIC_VERSION, semantic(rule).tree(canon_header(rule)))


# ---------------------------------------------------------------------------------------------------------------
# facts used by the index


@dataclass
class Facts:
    content_hash: str
    logic_hash: str
    semantic_hash: str | None
    alerting_hash: str
    gid: int
    sid: int
    rev: int | None
    msg: str | None
    action: str
    protocol: str
    app_layer: str
    classtype: str | None
    buffers: list[str]
    contents: list[str]  # "buffer:canonical content" for near-duplicate and search
    metadata: dict[str, list[str]]
    references: list[str]
    flowbits_set: list[str]
    flowbits_check: list[str]
    files: list[str]  # external files the rule needs (datasets, lua, iprep lists ...)
    ioc_type: str | None
    ioc_value: str | None
    flags: list[str]
    features: list[str]  # what near-duplicate detection compares


FEATURE_MIN_BYTES = 4


FEATURE_SKIP_GLOBALS = frozenset({"flow", "app-layer-protocol", "noalert", "ssl_state"})


def features(sem: Semantic) -> list[str]:
    """What a rule matches on, as a set: contents of 4+ bytes, every pcre and other buffer match (byte_test,
    isdataat, dataset ...), and detection globals (dce_opnum, dsize, flowbits checks ...). Short contents
    (|00|, "<", "GET") and flow say little about what a rule detects and would make unrelated rules look alike."""
    out = set()
    for buf, ms in sem.buffers.items():
        for m in ms:
            if m[0] == "content":
                if not m[1]:
                    continue
                try:
                    n = len(decode_content(m[1].lstrip("!"))[0])
                except ParseError:
                    continue
                if n >= FEATURE_MIN_BYTES:
                    out.add(f"{buf}:c:{m[1]}")
            else:
                out.add(f"{buf}:{m[0]}:{m[1] or ''}")
    for g in sem.globals:
        if g[0] in FEATURE_SKIP_GLOBALS:
            continue
        if g[0] in ("flowbits", "xbits") and (g[1] or "").split(",")[0].strip().lower() not in ("isset", "isnotset"):
            continue
        out.add(f"g:{g[0]}:{g[1] or ''}")
    return sorted(out)


def parse_metadata(values: list[str]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for v in values:
        for part in v.split(","):
            part = part.strip()
            if not part:
                continue
            key, _, val = part.partition(" ")
            out.setdefault(key.strip().lower(), []).append(val.strip())
    return out


def _bits(rule: Rule) -> tuple[list[str], list[str]]:
    sets, checks = [], []
    for kw in ("flowbits", "xbits"):
        for v in rule.get_all(kw):
            parts = [p.strip() for p in v.split(",")]
            if len(parts) < 2:
                continue
            op, names = parts[0].lower(), re.split(r"[|&]", parts[1])
            names = [f"{kw}:{n.strip()}" for n in names if n.strip()]
            if op in ("set", "toggle", "unset"):
                sets += names
            elif op in ("isset", "isnotset"):
                checks += names
    return sorted(set(sets)), sorted(set(checks))


def _files(rule: Rule) -> list[str]:
    out = []
    for v in rule.get_all("dataset") + rule.get_all("datarep"):
        out += re.findall(r"\b(?:load|state|save)\s+([^,\s]+)", v, re.IGNORECASE)
    for kw in ("lua", "luajit", "filemd5", "filesha1", "filesha256"):
        out += [unquote(v).lstrip("!") for v in rule.get_all(kw)]
    return sorted(set(out))


def _app_layer(rule: Rule, buffers: list[str]) -> str:
    if rule.protocol in APP_PROTOCOLS:
        return {"http1": "http", "http2": "http"}.get(rule.protocol, rule.protocol)
    for b in buffers:
        head = b.split(".")[0]
        if head in APP_PROTOCOLS:
            return head
        if head in ("ja3", "ja3s", "ja4"):
            return "tls"
        if head == "file":
            return "file"
    alp = rule.get("app-layer-protocol")
    if alp:
        return alp.strip().lstrip("!").lower()
    return rule.protocol


_ANCHORS = re.compile(r"\(\?:\^\|\\\.\)|\(\^\|\\\.\)|\(\?:\^\|\.\)|\(\^\|\.\)|\^|\$")


def _pcre_restates(content: str, pcre: str) -> bool:
    """True when a canonical pcre ("/pat/flags") is only the literal content with anchors, e.g. /(^|\\.)evil\\.com$/."""
    body, _, _flags = pcre.lstrip("!").rpartition("/")
    pattern = _ANCHORS.sub("", body[1:])
    if re.search(r"(?<!\\)[\[\]()*+?{}|]", pattern):
        return False
    literal = re.sub(r"\\(.)", r"\1", pattern)
    try:
        text = decode_content(content)[0].decode("utf-8", "replace")
    except ParseError:
        return False
    return literal.lower().lstrip(".") == text.lower().lstrip(".")


def _ioc(rule: Rule, sem: Semantic) -> tuple[str | None, str | None]:
    """One literal indicator and nothing else -> (type, value)."""
    if any(g[0] not in IOC_ALLOWED_GLOBALS for g in sem.globals):
        return None, None
    matches = [(b, m) for b, ms in sem.buffers.items() for m in ms]
    if not matches:
        # IP rules: a literal address on one side, "any"/variable on the other, no detection options.
        sides = [canon_addr(rule.src_addr), canon_addr(rule.dst_addr)]
        literal = [s for s in sides if s != "any" and not s.lstrip("!").startswith("$") and not s.startswith("!")]
        if len(literal) == 1:
            return "ip", literal[0]
        return None, None
    # Rules over an indicator list (dataset/datarep in an indicator buffer and nothing else).
    if (
        all(m[0] in ("dataset", "datarep", "domain", "dotprefix", "to_lowercase") for _, m in matches)
        and all(b in IOC_BUFFERS for b, _ in matches)
        and any(m[0] in ("dataset", "datarep") for _, m in matches)
    ):
        names = sorted({(m[1] or "").split(",")[1].strip() for _, m in matches if m[0] in ("dataset", "datarep") and "," in (m[1] or "")})
        return "dataset", ",".join(names) or None
    contents = [(b, m) for b, m in matches if m[0] == "content"]
    if any((m[1] or "").startswith("!") for _, m in contents):
        return None, None
    # A pcre that only re-states the content in the same buffer (domain anchoring) adds no logic.
    pcres = [(b, m) for b, m in matches if m[0] == "pcre"]
    for b, p in pcres:
        same = [c for cb, c in contents if cb == b]
        if not same or not any(_pcre_restates(c[1] or "", p[1] or "") for c in same):
            return None, None
    others = [m for _, m in matches if m[0] not in ("content", "pcre") and m[0] not in IOC_ALLOWED_MODIFIERS]
    if others:
        return None, None
    if any(k not in IOC_ALLOWED_MODIFIERS for _, c in contents for k, _ in c[2]):
        return None, None
    # URL indicator: one host and one uri literal.
    if len(contents) == 2 and {b for b, _ in contents} == {"http.host", "http.uri"}:
        parts = {b: decode_content(m[1] or "")[0].decode("utf-8", "replace") for b, m in contents}
        return "url", (parts["http.host"].lstrip(".") + parts["http.uri"]).lower()
    if len(contents) != 1:
        return None, None
    buf, m = contents[0]
    if buf not in IOC_BUFFERS or (m[1] or "").startswith("!"):
        return None, None
    if any(k not in IOC_ALLOWED_MODIFIERS for k, _ in m[2]):
        return None, None
    data, _ = decode_content(m[1])
    value = data.decode("utf-8", "replace").lstrip(".").lower()
    return IOC_BUFFERS[buf], value


# Header protocols Snort 2 understands; any other (http, dns, tls, smb ...) is a Suricata app-layer keyword.
SNORT_PROTOCOLS = frozenset({"tcp", "udp", "icmp", "ip"})
# Keywords Suricata has and Snort 2 does not (besides dotted sticky buffers, which are all Suricata's).
SURICATA_ONLY = frozenset(
    {
        "dataset",
        "datarep",
        "xbits",
        "flowint",
        "app-layer-protocol",
        "app-layer-event",
        "bsize",
        "startswith",
        "endswith",
        "luajit",
        "lua",
        "ja3_hash",
        "ja3s_hash",
        "ja3_string",
        "tls_sni",
        "tls_cert_subject",
        "tls_cert_issuer",
        "tls_cert_serial",
        "tls_cert_fingerprint",
        "dns_query",
        "filemd5",
        "filesha1",
        "filesha256",
        "filemagic",
        "filename",
        "fileext",
        "filestore",
        "filesize",
        "iprep",
        "dotprefix",
        "domain",
        "tld",
        "to_md5",
        "to_sha1",
        "to_sha256",
        "to_lowercase",
        "to_uppercase",
        "strip_whitespace",
        "compress_whitespace",
        "url_decode",
        "xor",
        "pcrexform",
        "entropy",
        "pkt_data",
        "tag",
        "target",
        "requires",
        "transforms",
        "frame",
        "noalert",
        "prefilter",
        "stream_size",
        "tcp.mss",
        "dce_iface",
        "dce_opnum",
    }
)


def dialect(rule: Rule) -> str:
    """suricata: needs Suricata (app-layer protocol in the header, dotted sticky buffers, Suricata-only keywords);
    snort: Snort-only keywords or Snort 3 sticky use of http_* before any content; both: classic syntax both
    engines read. Validation in a real Suricata is the final word on loading."""
    names = [o.name for o in rule.options]
    if set(names) & SNORT_ONLY:
        return "snort"
    seen_content = False
    for n in names:
        if n in ("content", "uricontent", "pcre"):
            seen_content = True
        elif n in LEGACY_MODIFIER_BUFFERS and not seen_content:
            return "snort"  # Snort 3 style: http_uri; content:"..."
    if rule.protocol not in SNORT_PROTOCOLS:
        return "suricata"
    if any("." in n for n in names) or set(names) & (SURICATA_ONLY - {"noalert", "tag", "dce_iface", "dce_opnum"}):
        return "suricata"
    return "both"


def compute_facts(rule: Rule) -> Facts:
    """Everything the corpus stores about a parsed rule. Raises ParseError on undecodable values."""
    lh = logic_hash(rule)
    try:
        sem = semantic(rule)
        sh: str | None = _hash(SEMANTIC_VERSION, sem.tree(canon_header(rule)))
    except ParseError:
        sem, sh = Semantic([], {}), None
    buffers = sorted(sem.buffers)
    contents = sorted({f"{b}:{m[1]}" for b, ms in sem.buffers.items() for m in ms if m[0] == "content" and m[1]})
    meta = parse_metadata(rule.get_all("metadata"))
    sets, checks = _bits(rule)
    flags: list[str] = []
    names = {o.name for o in rule.options}
    if names & SNORT_ONLY:
        flags.append("foreign_syntax")
    flags.append("dialect:" + dialect(rule))
    if rule.repaired:
        flags.append("repaired_multiline")
    if not rule.has("rev"):
        flags.append("no_rev")
    if not rule.has("msg"):
        flags.append("no_msg")
    if meta.get("deprecation_reason"):
        flags.append("deprecated")
    if re.match(r"^\S+ RETIRED\b", rule.msg or ""):
        flags.append("retired")  # ET moves unmaintained rules to emerging-retired.rules with this msg prefix
    if re.match(r"^\S+ DELETED\b", rule.msg or ""):
        flags.append("deleted")  # ET keeps removed rules, disabled, in emerging-deleted.rules
    ioc_type, ioc_value = _ioc(rule, sem)
    return Facts(
        content_hash=sha256_hex(rule.text),
        logic_hash=lh,
        semantic_hash=sh,
        alerting_hash=alerting_hash(rule),
        gid=rule.gid,
        sid=rule.sid or 0,
        rev=rule.rev,
        msg=rule.msg,
        action=rule.action,
        protocol=rule.protocol,
        app_layer=_app_layer(rule, buffers),
        classtype=(rule.get("classtype") or "").strip() or None,
        buffers=buffers,
        contents=contents,
        metadata=meta,
        references=[_norm_ws(r) for r in rule.get_all("reference")],
        flowbits_set=sets,
        flowbits_check=checks,
        files=_files(rule),
        ioc_type=ioc_type,
        ioc_value=ioc_value,
        flags=flags,
        features=features(sem),
    )
