#!/usr/bin/env python3
# shared file; keep identical in sigharvest and suriharvest (tests/test_privacy_gate.py pins its SHA-256)
"""Privacy gate: secrets, private paths, emails and files that must not be published.

Usage:
    python3 -I privacy_gate.py REPO [--allowlist FILE] [--terms FILE] [--history]
                                    [--gitleaks auto|off|PATH] [--md FILE] [--show-sensitive]

The built-in rules are generic (secrets, e-mail addresses, home/user paths,
databases, binaries, Zone.Identifier files, ...). Project-specific sensitive
terms are never stored in the repository: they are loaded from the file named
by --terms or by one of the environment variables SIGHARVEST_PRIVACY_TERMS,
SURIHARVEST_PRIVACY_TERMS or PRIVACY_TERMS (see load_terms for the format).
Findings of those rules are reported as "sensitive-term" without the matched
line, so that the terms themselves do not leak into CI logs; --show-sensitive
prints them (local use only).

Scans the working tree (git ls-files + untracked files that are not ignored)
and, with --history, every commit (diffs, commit messages, historic paths and
blob sizes). Commit author/committer emails, Co-authored-by trailers and the
repo's configured user.email are always checked.

Exit codes: 0 = no blocking findings, 1 = at least one blocking finding,
2 = usage / environment error. Secret values are never printed in full.

Stdlib only.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
BLOCK, WARN = "block", "warn"
MAX_TEXT_BYTES = 5 * 1024 * 1024  # do not regex-scan bigger files
LARGE_WARN = 1 * 1024 * 1024  # 1 MiB  -> warn
LARGE_BLOCK = 5 * 1024 * 1024  # 5 MiB  -> block
SNIPPET = 160

# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------


@dataclasses.dataclass
class Rule:
    id: str
    category: str
    severity: str
    pattern: str
    scope: str = "content"  # content | path
    flags: int = re.IGNORECASE
    secret: bool = False  # mask matched value in output
    url_severity: str | None = None  # severity when the match sits inside a URL
    group: int = 0  # regex group holding the value to mask
    description: str = ""
    sensitive: bool = False  # loaded from the terms file: rule id and matched line are not printed

    def __post_init__(self):
        self.rx = re.compile(self.pattern, self.flags)


EMAIL_RX = re.compile(r"(?<![\w.+-])([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})(?![\w-])")
SAFE_EMAIL_DOMAINS = (
    "example.com",
    "example.org",
    "example.net",
    "example",
    "invalid",
    "test",
    "localhost",
    "users.noreply.github.com",
    "noreply.github.com",
)
SAFE_EMAIL_LOCAL = re.compile(r"^(no-?reply|donotreply|do-not-reply|nobody|user|someone|test|foo|bar|you|me|name|email|security|maintainer)$", re.I)
# Things that look like emails but are not (package@version, git@host, image@2x)
NOT_EMAIL = re.compile(r"(^git@)|(\.(png|jpg|jpeg|gif|svg|webp)$)|(@\d+x\.)", re.I)
# Domains that can appear in public Sigma/Suricata metadata as attribution.
PUBLIC_ATTRIB_DOMAINS = ("openinfosecfoundation.org", "emergingthreats.net", "proofpoint.com", "sigmahq.io")

URL_RX = re.compile(r"https?://[^\s\"'<>)\]]+", re.I)
HOME_OK = r"(?:runner|user|username|you|your-user|example|ubuntu|vagrant|linuxbrew|me|USER|\$USER|<user>|\{user\})"

RULES: list[Rule] = [
    # ---- secrets ---------------------------------------------------------
    Rule(
        "secret-private-key",
        "secret",
        BLOCK,
        r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----",
        flags=0,
        secret=True,
        description="PEM/OpenSSH/PGP private key",
    ),
    Rule("secret-aws-key", "secret", BLOCK, r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b", flags=0, secret=True, group=1),
    Rule("secret-github-token", "secret", BLOCK, r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b", flags=0, secret=True, group=1),
    Rule("secret-slack-token", "secret", BLOCK, r"\b(xox[abposr]-[A-Za-z0-9-]{10,})", flags=0, secret=True, group=1),
    Rule("secret-google-api-key", "secret", BLOCK, r"\b(AIza[0-9A-Za-z_\-]{35})\b", flags=0, secret=True, group=1),
    Rule("secret-ai-api-key", "secret", BLOCK, r"\b(sk-(?:ant-|proj-)?[A-Za-z0-9_\-]{32,})\b", flags=0, secret=True, group=1),
    Rule(
        "secret-oinkcode",
        "secret",
        BLOCK,
        r"oinkcode[\"'\s:=/]+([0-9a-f]{32,40})\b|/([0-9a-f]{32,40})/(?:snortrules|opensource|community)",
        secret=True,
        description="Snort/ET oinkcode",
    ),
    Rule("secret-jwt", "secret", BLOCK, r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})", flags=0, secret=True, group=1),
    Rule(
        "secret-assignment",
        "secret",
        BLOCK,
        r"\b[A-Z0-9_]*(?:API_?KEY|SECRET|TOKEN|PASSWORD|PASSWD|OINKCODE)[A-Z0-9_]*\s*[:=]\s*[\"']?([A-Za-z0-9+/_\-]{24,}={0,2})[\"']?",
        flags=0,
        secret=True,
        group=1,
        description="KEY=long-literal (env/config style)",
    ),
    Rule(
        "secret-hex-key-assign",
        "secret",
        WARN,
        r"(?:key|token|secret)[\"']?\s*[:=]\s*[\"']([0-9a-f]{40,64})[\"']",
        secret=True,
        group=1,
        description="hex value assigned to *key/token/secret (could be a test vector)",
    ),
    Rule(
        "secret-url-credentials",
        "secret",
        BLOCK,
        r"\b[a-z][a-z0-9+.-]*://[^\s/:@\"']+:([^\s/@\"'$<{]{3,})@[^\s\"']+",
        secret=True,
        group=1,
        description="credentials embedded in URL",
    ),
    # ---- private paths and hosts (project-specific names come from the terms file) ----
    Rule("internal-path-home", "internal", BLOCK, rf"/home/(?!{HOME_OK}\b)[A-Za-z0-9_][\w. -]*/", flags=0, description="absolute /home/<name>/ path"),
    Rule(
        "internal-path-tmp-session",
        "internal",
        BLOCK,
        r"/tmp/[\w.-]+/-[\w.-]+/",  # noqa: S108 (a pattern, not a temp file)
        flags=0,
        description="per-session scratch folder under /tmp (path-encoded working directory)",
    ),
    Rule("internal-path-root", "internal", WARN, r"(?<![\w.])/root/[\w.-]+"),
    Rule("internal-path-windows-user", "internal", WARN, r"[A-Z]:\\\\?Users\\\\?(?!Public|Default|<|%|\{)[\w.-]+", flags=0),
    Rule(
        "internal-hostname",
        "internal",
        WARN,
        r"\b[\w-]+\.(?:corp|internal|intranet|lan)\b(?![.(])|\b[\w-]+\.local(?=:\d|/)",
        description="internal-looking hostname",
    ),
    Rule("internal-private-ip", "internal", WARN, r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b"),
    Rule("internal-confidential", "internal", WARN, r"\binternal\s+(?:report|measurement|dataset|use only)\b|\bconfidential\b|\bTLP:(?:AMBER|RED)\b"),
    # ---- path rules (files that must not be committed) -------------------
    Rule("file-zone-identifier", "file", BLOCK, r"Zone\.Identifier$", scope="path"),
    Rule("file-database", "file", BLOCK, r"\.(?:db|sqlite3?|db-wal|db-shm|duckdb)$", scope="path"),
    Rule("file-workspace-dir", "file", BLOCK, r"(?:^|/)workspace/", scope="path"),
    Rule("file-private-key", "file", BLOCK, r"(?:^|/)(?:id_rsa|id_ed25519|id_ecdsa)$|\.(?:pem|key|p12|pfx|jks|keystore)$", scope="path"),
    Rule("file-dotenv", "file", BLOCK, r"(?:^|/)\.env(?:\.(?!example$|sample$|template$)[\w.]+)?$|(?:^|/)api\.env$", scope="path"),
    Rule(
        "file-office-doc",
        "file",
        BLOCK,
        r"\.(?:pptx?|docx?|xlsx?|odp|odt|ods|msg|eml)$",
        scope="path",
        description="office documents / mails (internal presentations, reports)",
    ),
    Rule("file-archive", "file", WARN, r"\.(?:zip|tar|tgz|gz|bz2|xz|7z|rar)$", scope="path"),
    Rule(
        "file-internal-report-dir",
        "file",
        WARN,
        r"(?:^|/)(?:docs/reports|reports|lab|benchmarks|discovery)/|(?:^|/)HANDOFF[\w.-]*$|(?:^|/)DECISIONS\.md$",
        scope="path",
    ),
    Rule("file-suricata-rules", "file", WARN, r"\.rules$", scope="path", description="rule file - verify licence of its content"),
]
BUILTIN_RULES = list(RULES)  # run() resets RULES to these plus the rules of the terms file

# synthetic rule ids (not regex)
SYNTH = {
    "email-real": ("email", BLOCK),
    "email-commit-author": ("email", BLOCK),
    "email-git-config": ("email", WARN),
    "file-large-warn": ("file", WARN),
    "file-large-block": ("file", BLOCK),
    "file-binary": ("file", WARN),
}
BINARY_OK_EXT = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp", ".woff", ".woff2", ".ttf", ".otf", ".eot"}


# --------------------------------------------------------------------------
# Findings, allowlist
# --------------------------------------------------------------------------


@dataclasses.dataclass
class Finding:
    rule: str
    category: str
    severity: str
    where: str  # path (or commit:<sha10>:<path> / blob:<sha10>:<path> for history)
    line: int = 0
    snippet: str = ""
    source: str = "tree"  # tree | history | commits | gitleaks
    allowed_by: str = ""  # justification if allowlisted
    raw_line: str = ""  # used only for allowlist re: matching, never printed
    commit: str = ""  # full commit SHA of a history finding (commit-scoped allowlist entries match it)
    sensitive: bool = False  # found by a terms-file rule: reported as "sensitive-term", matched line hidden

    @property
    def path(self) -> str:
        # strip "commit:abcd1234:" / "blob:abcd1234:" prefixes so path globs work for history too
        m = re.match(r"^(?:commit|blob):[0-9a-f]*:(.*)$", self.where)
        return m.group(1) if m else self.where


@dataclasses.dataclass
class AllowEntry:
    glob: str
    rule: str
    regex: re.Pattern | None
    justification: str
    lineno: int
    hits: int = 0
    sensitive: bool = False  # entry from the terms file: glob, rule and justification are not printed

    def matches(self, f: Finding) -> bool:
        if self.rule != "*" and not fnmatch.fnmatchcase(f.rule, self.rule):
            return False
        scoped = _commit_glob(self.glob)
        if scoped is not None:
            # "commit:<sha-prefix>[*][:<path-glob>]" exempts findings of exactly the commits whose SHA starts with the
            # prefix (any length from 7 to 40), optionally limited to a path; it never matches tree findings.
            prefix, inner = scoped
            if not f.commit or not f.commit.lower().startswith(prefix) or not _glob_match(inner, f.path):
                return False
        elif not _glob_match(self.glob, f.path):
            return False
        return not (self.regex is not None and not self.regex.search(f.raw_line or f.snippet))


_COMMIT_GLOB = re.compile(r"commit:([0-9a-fA-F]+)\*?(?::(.*))?")
MIN_COMMIT_PREFIX = 7


def _commit_glob(glob: str) -> tuple[str, str] | None:
    """(SHA prefix, path glob) of a commit-scoped entry ("commit:0e6ca78*", "commit:0e6ca78def:*",
    "commit:<40 hex>:docs/*"), or None for a plain path glob."""
    m = _COMMIT_GLOB.fullmatch(glob)
    if not m:
        return None
    return m.group(1).lower(), m.group(2) or "*"


def _glob_match(glob: str, path: str) -> bool:
    if glob in ("*", "**"):
        return True
    if fnmatch.fnmatchcase(path, glob):
        return True
    # "dir/**" or "dir/" prefixes
    g = glob.rstrip("*").rstrip("/")
    return bool(glob.endswith(("/**", "/")) and (path == g or path.startswith(g + "/")))


def parse_allow_line(line: str, n: int, where: str) -> AllowEntry:
    """One allowlist entry: '<path-glob> <rule-id|rule-glob|*> [re:<python-regex>] -- <justification>'."""
    if " -- " not in line:
        raise SystemExit(f"{where}:{n}: allowlist entry needs ' -- <justification>'")
    left, just = line.split(" -- ", 1)
    if not just.strip():
        raise SystemExit(f"{where}:{n}: empty justification")
    regex = None
    if " re:" in left:
        left, rx = left.split(" re:", 1)
        try:
            regex = re.compile(rx.strip())
        except re.error as e:
            raise SystemExit(f"{where}:{n}: bad regex: {e}") from None
    parts = left.split()
    if len(parts) != 2:
        raise SystemExit(f"{where}:{n}: expected '<path-glob> <rule-id>' before ' -- '")
    if parts[0].startswith("commit:"):
        scoped = _commit_glob(parts[0])
        if scoped is None or not MIN_COMMIT_PREFIX <= len(scoped[0]) <= 40:
            raise SystemExit(f"{where}:{n}: commit entries need a SHA prefix of {MIN_COMMIT_PREFIX}-40 hex digits: 'commit:<sha>[*][:<path-glob>]'")
    return AllowEntry(parts[0], parts[1], regex, just.strip(), n)


def load_allowlist(path: Path | None) -> list[AllowEntry]:
    """Format, one entry per line:

        <path-glob> <rule-id|rule-glob|*> [re:<python-regex>] -- <justification>

    '#' starts a comment line. The justification is mandatory. The optional
    re: regex is matched against the offending line (or snippet), so an entry
    can be limited to e.g. 'author:' lines. The regex runs until ' -- '.
    A path glob 'commit:<sha-prefix>[*][:<path-glob>]' (7-40 hex digits)
    exempts only the history findings of the commits whose SHA starts with it.
    """
    entries: list[AllowEntry] = []
    if not path:
        return entries
    for n, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if line and not line.startswith("#"):
            entries.append(parse_allow_line(line, n, str(path)))
    return entries


# --------------------------------------------------------------------------
# Sensitive terms (kept outside the repository)
# --------------------------------------------------------------------------

# --terms wins; otherwise the variable named after the scanned tool, then the other one, then PRIVACY_TERMS.
TOOLS = ("sigharvest", "suriharvest")
TERMS_ENVS = (*(f"{t.upper()}_PRIVACY_TERMS" for t in TOOLS), "PRIVACY_TERMS")
SENSITIVE_LABEL = "sensitive-term"
HIDDEN = "(matched line hidden; run locally with --show-sensitive)"
TERMS_WHERE = "terms file"  # error messages name the line only, never the file's content
TERM_OPTIONS = {"scope=path", "url=warn", "url=block", "case"}


def terms_from_env(repo: Path) -> tuple[str, str]:
    """(variable name, value) of the terms file to use for `repo`, or ("", "")."""
    names = [f"{t.upper()}_PRIVACY_TERMS" for t in TOOLS if t in repo.name.lower() or (repo / "src" / t).is_dir()]
    for name in [*names, *TERMS_ENVS]:
        if os.environ.get(name):
            return name, os.environ[name]
    return "", ""


def load_terms(path: Path) -> tuple[list[Rule], list[AllowEntry]]:
    """Project-specific sensitive rules and their exceptions, from a file kept outside the repository.

    One entry per line, '#' comments and blank lines ignored. Two rule spellings are accepted:

        <rule-id> <block|warn> [scope=path] [url=warn] [case] re:<regex to the end of the line>
        <rule-id> <block|warn>[,url=<block|warn>] <content|path> <regex to the end of the line>
        allow <path-glob> <rule-id|glob|*> [re:<regex>] -- <justification>

    Regexes are case-insensitive unless `case` is given (or use (?-i:...) for a case-sensitive part);
    `scope=path`/`path` matches file paths instead of content; `url=warn` lowers the severity when the match
    sits inside a URL. Rule ids, matched lines and the justifications of `allow` lines are not printed.
    Error messages name the line only, never the term.
    """
    rules: list[Rule] = []
    allow: list[AllowEntry] = []
    for n, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("allow "):
            entry = parse_allow_line(line[6:].strip(), n, TERMS_WHERE)
            entry.sensitive = True
            allow.append(entry)
            continue
        parts = line.split(None, 3)
        sev, *sev_opts = parts[1].split(",") if len(parts) > 1 else ("",)
        if len(parts) == 4 and parts[2] in ("content", "path"):
            opts = {*sev_opts, *(["scope=path"] if parts[2] == "path" else [])}
            rx = parts[3]
        else:
            head, sep, rx = line.partition(" re:")
            head_parts = head.split()
            if not sep or len(head_parts) < 2:
                raise SystemExit(
                    f"{TERMS_WHERE}:{n}: expected '<rule-id> <block|warn> [options] re:<regex>' or '<rule-id> <block|warn> <content|path> <regex>'"
                )
            sev, *sev_opts = head_parts[1].split(",")
            opts = {*sev_opts, *head_parts[2:]}
        if sev not in (BLOCK, WARN) or opts - TERM_OPTIONS:
            raise SystemExit(f"{TERMS_WHERE}:{n}: bad severity or option")
        url_sev = WARN if "url=warn" in opts else BLOCK if "url=block" in opts else None
        try:
            rules.append(
                Rule(
                    parts[0],
                    "sensitive",
                    sev,
                    rx,
                    scope="path" if "scope=path" in opts else "content",
                    flags=0 if "case" in opts else re.IGNORECASE,
                    url_severity=url_sev,
                    sensitive=True,
                )
            )
        except re.error:
            raise SystemExit(f"{TERMS_WHERE}:{n}: bad regex") from None
    return rules, allow


SHOW_SENSITIVE = False  # --show-sensitive: print rule ids and matched lines of terms-file rules (never in CI)


def shown_rule(f: Finding) -> str:
    return SENSITIVE_LABEL if f.sensitive and not SHOW_SENSITIVE else f.rule


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def mask(value: str) -> str:
    value = value.strip()
    if len(value) <= 8:
        return "****"
    return f"{value[:4]}****(len={len(value)})"


def git(repo: Path, *args: str, check: bool = True) -> str:
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, encoding="utf-8", errors="replace")
    if check and r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {r.stderr.strip()}")
    return r.stdout


def is_git_repo(repo: Path) -> bool:
    r = subprocess.run(["git", "-C", str(repo), "rev-parse", "--git-dir"], capture_output=True, text=True)
    return r.returncode == 0


def list_tree_files(repo: Path) -> list[str]:
    if is_git_repo(repo):
        out = git(repo, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
        files = sorted({p for p in out.split("\0") if p})
        return [p for p in files if (repo / p).is_file() and not (repo / p).is_symlink()]
    skip = {".git", ".venv", "__pycache__", "node_modules"}
    res = []
    for root, dirs, fnames in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in skip]
        for fn in fnames:
            res.append(str(Path(root, fn).relative_to(repo)))
    return sorted(res)


def is_binary(data: bytes) -> bool:
    return b"\0" in data[:8192]


def in_url(line: str, start: int, end: int) -> bool:
    return any(m.start() <= start and end <= m.end() for m in URL_RX.finditer(line))


PLACEHOLDER_RX = re.compile(r"secret|passw|changeme|dummy|fake|example|redacted|synthetic|placeholder|test|sample|^x+$|^\*+$|^[<$%{]", re.I)
SAFE_HOST_RX = re.compile(r"@(?:[\w-]+\.)*(?:example(?:\.\w+)?|invalid|test|localhost|host)(?:[:/]|$)", re.I)


def secret_value(rule: Rule, m: re.Match) -> str:
    if rule.group and m.group(rule.group):
        return m.group(rule.group)
    return next((g for g in m.groups() if g), m.group(0))


SECRET_RULES = [r for r in RULES if r.secret]


def mask_line(line: str) -> str:
    """Replace every secret-looking value in the line with its mask."""
    for rule in SECRET_RULES:
        for m in list(rule.rx.finditer(line)):
            val = secret_value(rule, m)
            if val:
                line = line.replace(val, mask(val))
    return line


def redact_email(email: str) -> str:
    """An address as shown in reports and CI logs: 'a***@e***.com'. A public log must not repeat the address it blocks;
    the full address stays in raw_line (allowlist matching only) and in the local git history."""
    local, _, dom = email.rpartition("@")
    name, dot, tld = dom.rpartition(".")
    return f"{local[:1]}***@{name[:1]}***.{tld}" if dot else f"{local[:1]}***@***"


def redact_emails(text: str) -> str:
    """Every address in `text` that is not safe to publish, redacted (redact_email)."""
    return EMAIL_RX.sub(lambda m: m.group(1) if email_is_safe(m.group(1)) else redact_email(m.group(1)), text)


def make_snippet(line: str, rule: Rule | None, m: re.Match | None) -> str:
    """Snippet for display. Secret values are always masked and unsafe addresses redacted, whatever rule fired."""
    s = redact_emails(mask_line(line))
    if len(s) > SNIPPET:
        a = max(0, (m.start() if m is not None else 0) - 60)
        a = min(a, max(0, len(s) - SNIPPET))
        s = ("…" if a else "") + s[a : a + SNIPPET].strip() + "…"
    return s.strip()


def email_is_safe(email: str) -> bool:
    local, _, dom = email.lower().rpartition("@")
    if NOT_EMAIL.search(email):
        return True
    if any(dom == d or dom.endswith("." + d) for d in SAFE_EMAIL_DOMAINS):
        return True
    if dom.endswith(PUBLIC_ATTRIB_DOMAINS) and SAFE_EMAIL_LOCAL.match(local):
        return True
    return bool(re.match(r"^(no-?reply|noreply)", local))


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------


def scan_text(where: str, text: str, source: str, line_offset_map=None) -> list[Finding]:
    out: list[Finding] = []
    content_rules = [r for r in RULES if r.scope == "content"]
    for i, line in enumerate(text.split("\n"), 1):  # "\n" only: the history line map counts "\n" lines
        if len(line) > 20000:  # minified blobs; scan a prefix only
            line = line[:20000]
        lno = line_offset_map[i - 1] if line_offset_map else i
        for rule in content_rules:
            for m in rule.rx.finditer(line):
                sev = rule.severity
                if rule.url_severity and in_url(line, m.start(), m.end()):
                    sev = rule.url_severity
                if rule.secret and rule.group and sev == BLOCK:
                    val = secret_value(rule, m)
                    if PLACEHOLDER_RX.search(val) or (rule.id == "secret-url-credentials" and SAFE_HOST_RX.search(m.group(0))):
                        sev = WARN  # obvious placeholder / test fixture
                snip = HIDDEN if rule.sensitive and not SHOW_SENSITIVE else make_snippet(line, rule, m)
                out.append(Finding(rule.id, rule.category, sev, where, lno, snip, source, raw_line=line, sensitive=rule.sensitive))
                break  # one finding per rule per line
        for m in EMAIL_RX.finditer(line):
            em = m.group(1)
            if in_url(line, m.start(), m.end()):
                continue  # user:pass@host inside a URL (handled by secret-url-credentials)
            if not email_is_safe(em):
                out.append(Finding("email-real", "email", BLOCK, where, lno, make_snippet(line, None, None), source, raw_line=line))
                break
    return out


def scan_path(where: str, path: str, source: str) -> list[Finding]:
    out = []
    for rule in RULES:
        if rule.scope == "path" and rule.rx.search(path):
            snip = HIDDEN if rule.sensitive and not SHOW_SENSITIVE else path
            out.append(Finding(rule.id, rule.category, rule.severity, where, 0, snip, source, raw_line=path, sensitive=rule.sensitive))
    return out


def size_findings(where: str, size: int, path: str, binary: bool, source: str) -> list[Finding]:
    out = []
    if size >= LARGE_BLOCK:
        out.append(Finding("file-large-block", "file", BLOCK, where, 0, f"{size / 1048576:.1f} MiB", source, raw_line=path))
    elif size >= LARGE_WARN:
        out.append(Finding("file-large-warn", "file", WARN, where, 0, f"{size / 1048576:.1f} MiB", source, raw_line=path))
    if binary and Path(path).suffix.lower() not in BINARY_OK_EXT:
        out.append(Finding("file-binary", "file", WARN, where, 0, f"binary file, {size} bytes", source, raw_line=path))
    return out


def scan_tree(repo: Path) -> tuple[list[Finding], int]:
    findings: list[Finding] = []
    files = list_tree_files(repo)
    for rel in files:
        p = repo / rel
        findings += scan_path(rel, rel, "tree")
        try:
            size = p.stat().st_size
        except OSError:
            continue
        try:
            with open(p, "rb") as fh:
                head = fh.read(8192)
        except OSError:
            continue
        binary = is_binary(head)
        findings += size_findings(rel, size, rel, binary, "tree")
        if binary or size > MAX_TEXT_BYTES:
            continue
        text = p.read_bytes().decode("utf-8", errors="replace")
        findings += scan_text(rel, text, "tree")
    return findings, len(files)


def scan_commit_identities(repo: Path) -> list[Finding]:
    out: list[Finding] = []
    if not is_git_repo(repo):
        return out
    cfg = git(repo, "config", "user.email", check=False).strip()
    if cfg and not email_is_safe(cfg):
        out.append(
            Finding(
                "email-git-config", "email", WARN, "git config user.email", 0, f"next commits will be authored as {redact_email(cfg)}", "commits", raw_line=cfg
            )
        )
    log = git(repo, "log", "--all", "--format=%H%x1f%an%x1f%ae%x1f%cn%x1f%ce%x1f%B%x1e", check=False)
    seen = set()
    for rec in log.split("\x1e"):
        rec = rec.strip("\n")
        if not rec:
            continue
        parts = rec.split("\x1f")
        if len(parts) < 6:
            continue
        sha, an, ae, cn, ce, body = parts[:6]
        emails = [("author", an, ae), ("committer", cn, ce)]
        for m in re.finditer(r"^(?:Co-authored-by|Signed-off-by):\s*(.*?)\s*<([^>]+)>", body, re.M | re.I):
            emails.append(("trailer", m.group(1), m.group(2)))
        for role, name, em in emails:
            key = (sha, role, em.lower())  # per commit, so an allowlisted commit cannot hide another one
            if not em or email_is_safe(em) or key in seen:
                continue
            seen.add(key)
            out.append(
                Finding(
                    "email-commit-author",
                    "email",
                    BLOCK,
                    f"commit:{sha[:10]}:<{role}>",
                    0,
                    f"{role} {name} <{redact_email(em)}>",
                    "commits",
                    raw_line=em,
                    commit=sha,
                )
            )
    return out


def scan_history(repo: Path) -> list[Finding]:
    findings: list[Finding] = []
    if not is_git_repo(repo) or not git(repo, "rev-list", "--all", check=False).strip():
        return findings
    # 1. every historic path + blob size
    objs = git(repo, "rev-list", "--objects", "--all")
    blob_paths: dict[str, str] = {}
    for line in objs.splitlines():
        sha, _, path = line.partition(" ")
        if path:
            blob_paths.setdefault(sha, path)
    if blob_paths:
        r = subprocess.run(
            ["git", "-C", str(repo), "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
            input="\n".join(blob_paths) + "\n",
            capture_output=True,
            text=True,
        )
        seen_paths = set()
        for line in r.stdout.splitlines():
            sha, typ, size = line.split()
            if typ != "blob":
                continue
            path = blob_paths[sha]
            where = f"blob:{sha[:10]}:{path}"  # a blob, not a commit: commit-scoped entries do not apply
            if path not in seen_paths:
                seen_paths.add(path)
                findings += scan_path(where, path, "history")
            if int(size) >= LARGE_WARN:
                findings += size_findings(where, int(size), path, False, "history")
    # 2. added lines of every commit
    proc = subprocess.Popen(
        ["git", "-C", str(repo), "log", "--all", "-p", "--no-color", "--no-ext-diff", "-U0", "--format=\x1fCOMMIT %H"],
        stdout=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    sha, path, lno = "", "", 0
    buf: list[str] = []
    lines_map: list[int] = []

    def flush():
        nonlocal buf, lines_map
        if buf and path and path != "/dev/null":
            found = scan_text(f"commit:{sha[:10]}:{path}", "\n".join(buf), "history", lines_map)
            for f in found:
                f.commit = sha
            findings.extend(found)
        buf, lines_map = [], []

    assert proc.stdout is not None
    for line in proc.stdout:
        line = line.rstrip("\n")
        if line.startswith("\x1fCOMMIT "):
            flush()
            sha = line.split()[1]
            path = ""
        elif line.startswith("diff --git "):
            flush()
            path = ""
        elif line.startswith("+++ "):
            p = line[4:]
            path = p[2:] if p.startswith("b/") else p
        elif line.startswith("@@"):
            m = re.search(r"\+(\d+)", line)
            lno = int(m.group(1)) if m else 0
        elif line.startswith("+") and path:
            buf.append(line[1:])
            lines_map.append(lno)
            lno += 1
    flush()
    proc.wait()
    # 3. commit messages
    msgs = git(repo, "log", "--all", "--format=%H%x1f%B%x1e")
    for rec in msgs.split("\x1e"):
        rec = rec.strip("\n")
        if "\x1f" not in rec:
            continue
        s, body = rec.split("\x1f", 1)
        for f in scan_text(f"commit:{s[:10]}:<message>", body, "history"):
            if f.rule != "email-real":  # trailers handled by identity scan
                f.commit = s
                findings.append(f)
    return findings


# --------------------------------------------------------------------------
# gitleaks (optional)
# --------------------------------------------------------------------------


def find_gitleaks(spec: str) -> str | None:
    if spec == "off":
        return None
    if spec != "auto":
        return spec if Path(spec).is_file() else None
    p = shutil.which("gitleaks")
    if p:
        return p
    local = HERE / "bin" / "gitleaks"
    return str(local) if local.is_file() and os.access(local, os.X_OK) else None


def run_gitleaks(binary: str, repo: Path, files: list[str], history: bool) -> tuple[list[Finding], str]:
    findings: list[Finding] = []
    notes = []
    with tempfile.TemporaryDirectory(prefix="privacy-gate-") as td:
        td = Path(td)
        stage = td / "tree"
        # stage only the files the gate considers part of the repo (no .venv / ignored data)
        for rel in files:
            src = repo / rel
            try:
                if src.stat().st_size > MAX_TEXT_BYTES:
                    continue
            except OSError:
                continue
            dst = stage / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dst)
        runs = [("tree", ["dir", str(stage)])]
        if history and is_git_repo(repo) and git(repo, "rev-list", "--all", check=False).strip():
            runs.append(("history", ["git", str(repo)]))
        for label, args in runs:
            rep = td / f"{label}.json"
            cmd = [binary, *args, "--no-banner", "--redact", "--report-format", "json", "--report-path", str(rep), "--exit-code", "0", "--log-level", "error"]
            r = subprocess.run(cmd, capture_output=True, text=True)
            if r.returncode != 0:
                notes.append(f"gitleaks {label} failed (rc={r.returncode}): {r.stderr.strip()[:200]}")
                continue
            data = json.loads(rep.read_text() or "[]") if rep.exists() else []
            for d in data:
                fpath = d.get("File", "")
                commit = ""
                if label == "tree":
                    with contextlib.suppress(ValueError):
                        fpath = str(Path(fpath).resolve().relative_to(stage.resolve()))
                    where = fpath
                else:
                    where = f"commit:{d.get('Commit', '')[:10]}:{fpath}"
                    commit = d.get("Commit", "")
                snippet = (d.get("Match") or "").strip()
                if len(snippet) > SNIPPET:
                    snippet = snippet[:SNIPPET] + "…"
                findings.append(
                    Finding(
                        f"gitleaks:{d.get('RuleID')}",
                        "secret",
                        BLOCK,
                        where,
                        int(d.get("StartLine") or 0),
                        snippet + " (redacted by gitleaks)",
                        f"gitleaks-{label}",
                        raw_line=d.get("Match") or "",
                        commit=commit,
                    )
                )
            notes.append(f"gitleaks {label}: {len(data)} finding(s)")
    return findings, "; ".join(notes)


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------


def dedupe(findings: list[Finding]) -> list[Finding]:
    seen, out = set(), []
    for f in findings:
        k = (f.rule, f.where, f.line, f.source)
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out


def render(repo: Path, findings: list[Finding], allow: list[AllowEntry], nfiles: int, opts, notes: list[str], md: bool = False, max_per_rule: int = 15) -> str:
    active = [f for f in findings if not f.allowed_by]
    allowed = [f for f in findings if f.allowed_by]
    blocks = [f for f in active if f.severity == BLOCK]
    warns = [f for f in active if f.severity == WARN]
    L: list[str] = []

    def h(t, lvl=2):
        return L.append(("#" * lvl + " " + t) if md else ("\n" + t.upper() + "\n" + "=" * len(t)))

    status = "FAIL" if blocks else "PASS"
    if md:
        L.append(f"# Privacy gate report: `{repo.name}`\n")
    else:
        L.append(f"privacy-gate: {repo}")
    L.append(
        f"- result: **{status}** ({len(blocks)} block, {len(warns)} warn, {len(allowed)} allowlisted)"
        if md
        else f"result: {status}  ({len(blocks)} block, {len(warns)} warn, {len(allowed)} allowlisted)"
    )
    pre = "- " if md else ""
    L.append(f"{pre}files scanned (tree): {nfiles}; history: {'yes' if opts.history else 'no'}; allowlist: {opts.allowlist or '-'}")
    for n in notes:
        L.append(f"{pre}{n}")

    def section(title: str, items: list[Finding]):
        if not items:
            return
        h(title)
        by_rule: dict[str, list[Finding]] = {}
        for f in items:
            by_rule.setdefault(shown_rule(f), []).append(f)
        if md:
            L.append("")
            L.append("| rule | category | count | files |")
            L.append("|---|---|---:|---:|")
            for rid, fs in sorted(by_rule.items(), key=lambda kv: -len(kv[1])):
                L.append(f"| `{rid}` | {fs[0].category} | {len(fs)} | {len({x.where for x in fs})} |")
            L.append("")
        for rid, fs in sorted(by_rule.items(), key=lambda kv: -len(kv[1])):
            nf = len({x.where for x in fs})
            L.append(f"\n{'### ' if md else '-- '}{rid} ({fs[0].category}): {len(fs)} hit(s) in {nf} location(s)")
            if md:
                L.append("")
            for f in fs[:max_per_rule]:
                loc = f"{f.where}:{f.line}" if f.line else f.where
                snip = f.snippet.replace("|", "\\|").replace("`", "'") if md else f.snippet
                L.append(f"- `{loc}` {snip}" if md else f"   {loc}  {snip}")
            if len(fs) > max_per_rule:
                rest = sorted({x.where for x in fs[max_per_rule:]})
                more = ", ".join(rest[:20]) + (" …" if len(rest) > 20 else "")
                L.append(f"- … +{len(fs) - max_per_rule} more in: {more}" if md else f"   … +{len(fs) - max_per_rule} more in: {more}")

    section("Blocking findings", blocks)
    section("Warnings", warns)
    if allowed:
        h("Allowlisted")
        cnt: dict[tuple[str, str], int] = {}
        for f in allowed:
            key = (shown_rule(f), f.allowed_by)
            cnt[key] = cnt.get(key, 0) + 1
        for (rid, why), c in sorted(cnt.items()):
            L.append(f"{pre}{rid}: {c} hit(s) -- {why}")
    unused = [e for e in allow if e.hits == 0]
    if unused:
        h("Unused allowlist entries")
        for e in unused:
            L.append(f"{pre}terms file line {e.lineno}" if e.sensitive else f"{pre}line {e.lineno}: {e.glob} {e.rule} -- {e.justification}")
    return "\n".join(L) + "\n"


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------


def run(argv: list[str] | None = None) -> int:
    global SHOW_SENSITIVE
    ap = argparse.ArgumentParser(description="Pre-push privacy gate")
    ap.add_argument("repo")
    ap.add_argument("--allowlist", help="allowlist file (see load_allowlist docstring)")
    ap.add_argument("--terms", help=f"sensitive terms file kept outside the repo (see load_terms); default: ${' / $'.join(TERMS_ENVS)}")
    ap.add_argument("--history", action="store_true", help="also scan full git history")
    ap.add_argument("--gitleaks", default="auto", help="auto (PATH or ./bin/gitleaks), off, or a path")
    ap.add_argument("--md", help="also write a Markdown report to this file")
    ap.add_argument("--max-per-rule", type=int, default=15)
    ap.add_argument("--json", help="write all findings as JSON (masked) to this file")
    ap.add_argument("--show-sensitive", action="store_true", help="print rule ids and lines matched by terms-file rules (local use only, never in CI)")
    opts = ap.parse_args(argv)

    repo = Path(opts.repo).resolve()
    if not repo.is_dir():
        print(f"not a directory: {repo}", file=sys.stderr)
        return 2
    SHOW_SENSITIVE = opts.show_sensitive
    RULES[:] = BUILTIN_RULES
    notes: list[str] = []
    try:
        allow = load_allowlist(Path(opts.allowlist) if opts.allowlist else None)
        source, terms = ("--terms", opts.terms) if opts.terms else terms_from_env(repo)
        if terms:
            tpath = Path(terms)
            if not tpath.is_file():
                print(f"terms file not found ({source})", file=sys.stderr)
                return 2
            trules, tallow = load_terms(tpath)
            RULES.extend(trules)
            allow += tallow
            notes.append(f"sensitive terms: {len(trules)} rule(s), {len(tallow)} exception(s) loaded ({source})")
        else:
            notes.append(f"sensitive terms: NOT loaded (set {' or '.join(TERMS_ENVS)}, or --terms); only generic rules ran")
    except (OSError, SystemExit) as e:
        print(e, file=sys.stderr)
        return 2
    findings, nfiles = scan_tree(repo)
    findings += scan_commit_identities(repo)
    if opts.history:
        findings += scan_history(repo)
        if is_git_repo(repo) and not git(repo, "rev-list", "--all", check=False).strip():
            notes.append("history: repository has no commits yet")
    gl = find_gitleaks(opts.gitleaks)
    if gl:
        gf, note = run_gitleaks(gl, repo, list_tree_files(repo), opts.history)
        findings += gf
        notes.append(note)
    elif opts.gitleaks != "off":
        notes.append("gitleaks: not found (skipped)")
    findings = dedupe(findings)

    for f in findings:
        for e in allow:
            if e.matches(f):
                f.allowed_by = "exception from the terms file" if e.sensitive else e.justification
                e.hits += 1
                break

    text = render(repo, findings, allow, nfiles, opts, notes, md=False, max_per_rule=opts.max_per_rule)
    sys.stdout.write(text)
    if opts.md:
        Path(opts.md).write_text(render(repo, findings, allow, nfiles, opts, notes, md=True, max_per_rule=opts.max_per_rule), encoding="utf-8")
    if opts.json:
        Path(opts.json).write_text(
            json.dumps([{**{k: v for k, v in dataclasses.asdict(f).items() if k != "raw_line"}, "rule": shown_rule(f)} for f in findings], indent=1),
            encoding="utf-8",
        )
    return 1 if any(f.severity == BLOCK and not f.allowed_by for f in findings) else 0


if __name__ == "__main__":
    sys.exit(run())
