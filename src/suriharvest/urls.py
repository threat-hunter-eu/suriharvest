"""Source URLs that are safe to show in published files.

A fetch URL may carry credentials: userinfo before the host, a token in the query string (`?key=...`), a
`${secret}` placeholder, or a local path that names the build machine. Anything written into release files, exports
or recipes goes through `redact_url` first: scheme, host (and port) and path are kept; userinfo, query and fragment
are dropped. With `keep_placeholders=True` (recipes, which tell users how to fetch a source themselves) query
parameters and userinfo made only of `${...}` placeholders are kept literally, so the recipe still says where the
user's own key goes, but no literal value ever leaves the machine.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit, urlunsplit

_PLACEHOLDER = re.compile(r"^(?:\$\{[A-Za-z0-9_.-]+\})+$")
# git "scp-like" syntax: user@host:path
_SCP = re.compile(r"^(?:[^@/:]+@)?([A-Za-z0-9.-]+):(?!//)(.+)$")
# A Windows drive (C:\x, C:/x, C:x) or UNC path (\\server\share), which _SCP would read as host "C".
_WINDOWS_PATH = re.compile(r"^(?:[A-Za-z]:|\\\\)")


def _is_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER.fullmatch(value))


def redact_url(url: str | None, *, keep_placeholders: bool = False) -> str | None:
    """Return `url` without userinfo, query string and fragment, or None when it is not a network URL (a local path,
    an empty value). Never raises."""
    if not url:
        return None
    url = url.strip()
    if "://" not in url:
        if _WINDOWS_PATH.match(url):
            return None  # C:\rules or \\server\share: a local path, not host:path
        m = _SCP.match(url)
        if m and not url.startswith(("/", ".", "~")):
            return f"{m.group(1)}:{m.group(2).split('?')[0].split('#')[0]}"
        return None  # a local path (type: local) or something we cannot parse: never published
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if not parts.scheme or not parts.netloc:
        return None
    userinfo, at, hostport = parts.netloc.rpartition("@")
    netloc = hostport
    if at and keep_placeholders and all(_is_placeholder(x) for x in userinfo.split(":") if x):
        netloc = f"{userinfo}@{hostport}"
    query = ""
    if keep_placeholders and parts.query:
        kept = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if _is_placeholder(v)]
        query = "&".join(f"{k}={v}" for k, v in kept)
    return urlunsplit((parts.scheme, netloc, parts.path, query, ""))


def public_link(homepage: str | None, url: str | None) -> str:
    """The one link to show for a source in anything users see or share (NOTICE files, exports, web pages):
    its homepage when it has one (the fetch URL is never shown then), else the redacted fetch URL, else ""."""
    return redact_url(homepage) or ("" if homepage else redact_url(url) or "")
