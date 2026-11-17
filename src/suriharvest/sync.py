"""Fetch sources into corpus/<name>/ and report which files changed.

git          - bare, shallow, blob-filtered clone in data/cache/git/<name>.git; `git diff old new` on later runs;
               only files that look like Suricata rules are written to corpus/<name>/, plus the source's licence
               files (`licence_files`, or LICENSE / COPYING / NOTICE ... at the repository root) for release LICENSES/.
http-tarball - download, extract with path and size checks into a staging folder, swap it in, diff by file hash.
http-file    - one rules file, diffed by hash.
local        - a folder read in place, diffed by hash against the last ingest.

Sources are untrusted input: git URLs/refs starting with "-" are refused, only https/ssh/file
transports, hooks disabled, archive members with absolute or ".." paths or links are skipped, size caps everywhere,
tokens go through the environment, never argv or .git/config; the git token header is scoped to the source's
origin and git does not follow redirects.
"""

from __future__ import annotations

import fnmatch
import io
import os
import re
import subprocess
import tarfile
import time
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import httpcore
import httpx

from suriharvest.config import LICENCE_FILE, MAX_LICENCE_BYTES, SourceConfig, Workspace
from suriharvest.identity import sha256_hex
from suriharvest.parser import HAS_SID, looks_like_rules_bytes
from suriharvest.portable import rmtree

MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024
MAX_EXTRACTED_BYTES = 2 * 1024 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 20000  # no rule feed ships more files than this
MAX_FILE_BYTES = 256 * 1024 * 1024  # single-file feeds can be large (all rules of a vendor in one file)
ALLOWED_GIT_URL = ("https://", "ssh://", "git@", "file://")
_SAFE_REF = re.compile(r"^[A-Za-z0-9._/+-]{1,200}$")
USER_AGENT = "suriharvest/0.1"


class SyncError(RuntimeError):
    pass


@dataclass
class SyncResult:
    old_commit: str | None
    new_commit: str | None
    root: Path
    added: set[str] = field(default_factory=set)
    changed: set[str] = field(default_factory=set)
    removed: set[str] = field(default_factory=set)
    full_scan: bool = False
    too_large: list[str] = field(default_factory=list)  # files skipped because of MAX_FILE_BYTES (reported, never silent)
    validators_file: Path | None = None  # http: where to store `validators` once the download has been ingested
    validators: dict | None = None


def path_selected(path: str, src: SourceConfig) -> bool:
    """Does a glob of `paths` select this file? A per-major copy (`@8/rules/x.rules`) is matched without its prefix."""
    m = re.match(r"@\d+/", path) if src.type in ("http-tarball", "http-file") else None
    path = path[m.end() :] if m else path
    return any(fnmatch.fnmatchcase(path, pat) or (pat.startswith("**/") and fnmatch.fnmatchcase(path, pat[3:])) for pat in src.paths)


def looks_like_rules(data: bytes) -> bool:
    head = data[: 4 * 1024 * 1024]
    return looks_like_rules_bytes(head) and bool(HAS_SID.search(head))


# ---------------------------------------------------------------------------------------------------------------
# git


def _check_git_inputs(url: str, ref: str | None) -> None:
    if url.startswith("-") or (not url.startswith(ALLOWED_GIT_URL) and not Path(url).is_absolute()):
        raise SyncError(f"refusing git url {url!r}: only https, ssh and local absolute paths are allowed")
    if ref is not None and (ref.startswith("-") or not _SAFE_REF.match(ref) or ".." in ref):
        raise SyncError(f"refusing git ref {ref!r}")


def _git_auth_env(url: str | None, token: str | None) -> dict[str, str]:
    """Bearer header for git, scoped to the exact origin (scheme, host, port) of the source URL.

    `http.<origin>/.extraHeader` instead of a global `http.extraHeader`: git sends it only to that origin, so a
    redirect or a submodule/alternate on another host never sees the token. Nothing for ssh, file or local paths.
    """
    if not token or not url:
        return {}
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        return {}
    host = parts.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    origin = f"{parts.scheme}://{host}" + (f":{parts.port}" if parts.port else "")
    return {
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": f"http.{origin}/.extraHeader",
        "GIT_CONFIG_VALUE_0": f"Authorization: Bearer {token}",
    }


# http.followRedirects=false: a git source that redirects (to another host or anywhere else) fails instead of being
# followed; update the URL in the source instead.
GIT_BASE_CONFIG = (
    *("-c", "protocol.allow=never", "-c", "protocol.https.allow=always", "-c", "protocol.ssh.allow=always"),
    *("-c", "protocol.file.allow=always", "-c", "core.hooksPath=/dev/null", "-c", "http.followRedirects=false"),
)


def _git(args: list[str], cwd: Path | None = None, token: str | None = None, timeout: int = 1800, url: str | None = None) -> str:
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1"}
    cmd = ["git", *GIT_BASE_CONFIG]
    env |= _git_auth_env(url, token)
    try:
        proc = subprocess.run(
            [*cmd, *args],
            cwd=cwd,
            env=env,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise SyncError(f"git {args[0]} timed out after {timeout}s") from None
    if proc.returncode != 0:
        raise SyncError(f"git {args[0]} failed: {proc.stderr.strip()[:400]}")
    return proc.stdout


def _git_bytes(args: list[str], cwd: Path, stdin: bytes | None = None) -> bytes:
    try:
        proc = subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", *args],
            cwd=cwd,
            check=False,
            input=stdin,
            capture_output=True,
            timeout=1800,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_NO_LAZY_FETCH": "1"},
        )
    except subprocess.TimeoutExpired:
        raise SyncError(f"git {args[0]} timed out") from None
    if proc.returncode != 0:
        raise SyncError(f"git {args[0]} failed: {proc.stderr.decode(errors='replace').strip()[:400]}")
    return proc.stdout


def _tree(repo: Path, commit: str) -> dict[str, tuple[str, int]]:
    out: dict[str, tuple[str, int]] = {}
    for entry in _git_bytes(["ls-tree", "-r", "-l", "-z", commit], repo).split(b"\0"):
        if not entry:
            continue
        meta, _, path = entry.partition(b"\t")
        parts = meta.split()
        if len(parts) == 4 and parts[1] == b"blob" and parts[0] in (b"100644", b"100755"):
            size = int(parts[3]) if parts[3].isdigit() else -1
            out[path.decode("utf-8", "surrogateescape")] = (parts[2].decode(), size)
    return out


def _read_blobs(repo: Path, oids: list[str]) -> dict[str, bytes]:
    if not oids:
        return {}
    data = _git_bytes(["cat-file", "--batch"], repo, stdin="".join(f"{o}\n" for o in oids).encode())
    out: dict[str, bytes] = {}
    pos = 0
    for oid in oids:
        nl = data.index(b"\n", pos)
        header = data[pos:nl].split()
        pos = nl + 1
        if len(header) == 2 and header[1] == b"missing":
            continue
        size = int(header[2])
        out[oid] = data[pos : pos + size]
        pos += size + 1
    return out


def _materialise(repo: Path, paths: list[str], dest: Path, tree: dict[str, tuple[str, int]]) -> set[str]:
    """Write the files that look like rules into dest; remove the others. Returns the paths written."""
    root = dest.resolve()
    wanted = [p for p in paths if p in tree and 0 <= tree[p][1] <= MAX_FILE_BYTES]
    written: set[str] = set()
    for i in range(0, len(wanted), 500):
        chunk = wanted[i : i + 500]
        blobs = _read_blobs(repo, list(dict.fromkeys(tree[p][0] for p in chunk)))
        for p in chunk:
            target = (root / p).resolve()
            if not target.is_relative_to(root):
                continue
            content = blobs.get(tree[p][0])
            if content is not None and looks_like_rules(content):
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
                written.add(p)
            elif target.is_file():
                target.unlink()
    for p in set(paths) - set(wanted):
        target = (root / p).resolve()
        if target.is_relative_to(root) and target.is_file():
            target.unlink()
    return written


def licence_paths(src: SourceConfig, tree: dict[str, tuple[str, int]]) -> list[str]:
    """The licence files a git source keeps next to its rules: its declared `licence_files`, else the LICENSE /
    LICENCE / COPYING / COPYRIGHT / NOTICE files at the repository root (Apache NOTICE propagation, copyright lines)."""
    wanted = (
        [p for p in src.licence_files if p in tree] if src.licence_files else [p for p in tree if "/" not in p and LICENCE_FILE.match(p)]
    )
    return sorted(p for p in wanted if 0 <= tree[p][1] <= MAX_LICENCE_BYTES)


def _keep_licence_files(repo: Path, src: SourceConfig, dest: Path, tree: dict[str, tuple[str, int]]) -> None:
    """Write the source's licence files (licence_paths) into dest, as the repository has them at the synced commit;
    remove root licence files the repository no longer has. Never a rules path: ingest only reads path_selected
    files that look like rules."""
    root = dest.resolve()
    keep = [p for p in licence_paths(src, tree) if not path_selected(p, src)]
    blobs = _read_blobs(repo, list(dict.fromkeys(tree[p][0] for p in keep)))
    for p in keep:
        target = (root / p).resolve()
        content = blobs.get(tree[p][0])
        if content is None or not target.is_relative_to(root):
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    for f in root.iterdir() if root.is_dir() else []:
        if f.is_file() and not f.is_symlink() and LICENCE_FILE.match(f.name) and f.name not in keep and not path_selected(f.name, src):
            f.unlink()


def sync_git(src: SourceConfig, ws: Workspace, last_commit: str | None) -> SyncResult:
    dest = ws.source_dir(src.name)
    repo = ws.git_repo(src.name)
    token = src.token()
    _check_git_inputs(src.url, src.ref)
    ref = src.ref or "HEAD"
    fresh = not (repo / "HEAD").exists()
    if not fresh:
        marker = subprocess.run(
            ["git", "rev-parse", "--verify", "--quiet", "refs/suriharvest/synced"], cwd=repo, capture_output=True, check=False
        )
        fresh = marker.returncode != 0
    if fresh:
        if repo.exists():
            rmtree(repo)
        repo.parent.mkdir(parents=True, exist_ok=True)
        args = ["clone", "--bare", "--depth", "1", "--filter=blob:limit=64m", "--no-tags", "--single-branch"]
        if src.ref and src.ref != "HEAD":
            args += ["--branch", src.ref.removeprefix("refs/heads/").removeprefix("refs/tags/")]
        _git([*args, "--", src.url, str(repo)], token=token, url=src.url)
        old, new = None, _git(["rev-parse", "HEAD"], cwd=repo).strip()
    else:
        old = _git(["rev-parse", "--verify", "--quiet", "refs/suriharvest/synced"], cwd=repo).strip() or None
        _git(["fetch", "--depth", "1", "--filter=blob:limit=64m", "--no-tags", "--", src.url, ref], cwd=repo, token=token, url=src.url)
        new = _git(["rev-parse", "FETCH_HEAD^{commit}"], cwd=repo).strip()
    result = SyncResult(old, new, dest)
    tree = _tree(repo, new)
    full = fresh or old is None or last_commit != old or not dest.exists()
    if full:
        if dest.exists():
            rmtree(dest)
        dest.mkdir(parents=True)
        result.added = _materialise(repo, [p for p in tree if path_selected(p, src)], dest, tree)
        result.full_scan = True
    elif new != old:
        raw = _git_bytes(["diff", "--name-status", "--no-renames", "-z", old, new, "--"], repo)  # type: ignore[list-item]
        fields = raw.split(b"\0")
        for status, path_b in zip(fields[0::2], fields[1::2], strict=False):
            path = path_b.decode("utf-8", "surrogateescape")
            if path_selected(path, src):
                {"A": result.added, "D": result.removed}.get(status.decode()[:1], result.changed).add(path)
        _materialise(repo, sorted(result.added | result.changed | result.removed), dest, tree)
    _keep_licence_files(repo, src, dest, tree)
    _git(["update-ref", "refs/suriharvest/synced", new], cwd=repo)
    if new != old:
        subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", "gc", "--quiet", "--prune=now"], cwd=repo, capture_output=True, check=False
        )
    return result


# ---------------------------------------------------------------------------------------------------------------
# http and local


def hash_tree(root: Path) -> dict[str, str]:
    out = {}
    if not root.exists():
        return out
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for f in filenames:
            p = Path(dirpath) / f
            if p.is_symlink() or not p.is_file() or p.stat().st_size > MAX_FILE_BYTES:
                continue
            out[str(p.relative_to(root)).replace(os.sep, "/")] = sha256_hex(p.read_bytes())
    return out


def _diff(before: dict[str, str], after: dict[str, str], result: SyncResult) -> SyncResult:
    result.added = set(after) - set(before)
    result.removed = set(before) - set(after)
    result.changed = {p for p in set(after) & set(before) if after[p] != before[p]}
    return result


DOWNLOAD_DEADLINE = float(os.environ.get("SURIHARVEST_DOWNLOAD_DEADLINE", "900"))  # seconds for one whole download
MAX_REDIRECTS = 10

# ---------------------------------------------------------------------------------------------------------------
# Where a download may connect.
#
# A source URL (or a redirect it answers with) must not make suriharvest talk to loopback, private, link-local or
# otherwise non-global addresses: that would let an upstream probe the build machine's network (SSRF). The check
# runs where the TCP connection is made, on the address actually used:
#   - `_GuardedBackend.connect_tcp` resolves the host name once, refuses the connection unless every address is
#     global, and connects to that already-checked address (no second DNS lookup, so no DNS rebinding between the
#     check and the connection). TLS still uses the URL's host name for SNI and certificate checks (httpcore takes
#     server_hostname from the request, not from the socket).
#   - a failed lookup is an error (fail closed), and a mixed answer (one public, one private) is refused.
# Internal mirrors are allowed only explicitly: `allow_private: true` on the source, the environment variable
# SURIHARVEST_ALLOW_PRIVATE_DOWNLOADS=1, or a configured URL whose host is itself a private IP literal.
# Redirects are followed by hand (at most MAX_REDIRECTS), so each hop goes through the same backend, an https URL
# never redirects to http, and the Authorization header is never sent to another host.


def _resolve(host: str, port: int) -> list[str]:
    """Addresses of `host` (IP strings, scope ids stripped). Raises OSError when the lookup fails."""
    import socket

    return sorted({i[4][0].split("%")[0] for i in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)})


_NUMERIC_HOST = re.compile(r"(?:0x[0-9a-f]*|\d+)(?:\.(?:0x[0-9a-f]*|\d+))*", re.IGNORECASE)


def _ip_literal(host: str):  # type: ignore[no-untyped-def]
    """The address a host string stands for, in every form resolvers and proxies accept: dotted, decimal
    (2130706433), hex (0x7f000001), octal (0177.0.0.1) and short (127.1) IPv4 are normalised to the dotted
    address (which is what is connected to); IPv6 is returned as is. None for a name. A numeric-looking host that
    is no valid address raises."""
    import ipaddress
    import socket

    h = host.strip("[]").split("%", 1)[0].rstrip(".")
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    if not _NUMERIC_HOST.fullmatch(h):
        return None
    try:
        return ipaddress.IPv4Address(socket.inet_aton(h))
    except OSError:
        raise SyncError(f"refusing host {host!r}: numeric but not a valid address") from None


def _ip_ok(ip) -> bool:  # type: ignore[no-untyped-def]
    """Allowed only when the address itself is global AND nothing embedded in it is internal. Transition forms
    that tunnel to an embedded IPv4 (6to4 2002::/16, IPv4-compatible ::/96, Teredo 2001::/32) are refused
    outright; IPv4-mapped and NAT64 (64:ff9b::/96) need their embedded IPv4 to be global too."""
    import ipaddress

    if not ip.is_global:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        n = int(ip)
        if ip.sixtofour is not None or ip.teredo is not None or n >> 32 == 0:
            return False
        embedded = ip.ipv4_mapped or (ipaddress.IPv4Address(n & 0xFFFFFFFF) if n >> 32 == 0x64FF9B << 64 else None)
        if embedded is not None and not embedded.is_global:
            return False
    return True


def _is_global(addr: str) -> bool:
    ip = _ip_literal(addr)
    return ip is not None and _ip_ok(ip)


class _DeadlineStream(httpcore.NetworkStream):
    """A network stream whose reads and writes never wait past the download's wall-clock deadline (connect, TLS,
    response headers and body: a server that trickles bytes cannot hold a download longer than the deadline)."""

    def __init__(self, inner: httpcore.NetworkStream, deadline: float, sni: dict[str, str] | None = None) -> None:
        self.inner, self.deadline = inner, deadline
        self.sni = sni if sni is not None else {}  # pinned IP -> real host name (TLS through a proxy tunnel)

    def _left(self, timeout: float | None) -> float:
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise SyncError(f"download took longer than {DOWNLOAD_DEADLINE:.0f} s")
        return left if timeout is None else min(timeout, left)

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return self.inner.read(max_bytes, timeout=self._left(timeout))

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self.inner.write(buffer, timeout=self._left(timeout))

    def close(self) -> None:
        self.inner.close()

    def start_tls(self, ssl_context, server_hostname=None, timeout=None):  # type: ignore[no-untyped-def]
        name = self.sni.get(server_hostname or "", server_hostname)  # certificate and SNI: the real host name
        return _DeadlineStream(
            self.inner.start_tls(ssl_context, server_hostname=name, timeout=self._left(timeout)), self.deadline, self.sni
        )

    def get_extra_info(self, info: str):  # type: ignore[no-untyped-def]
        return self.inner.get_extra_info(info)


class _GuardedBackend(httpcore.NetworkBackend):
    """httpcore network backend: resolve once, check every address, connect to the checked one; every stream is
    bounded by the download deadline. `check=False` (connection to a configured proxy): deadline only."""

    def __init__(
        self, allow_private: bool, inner: httpcore.NetworkBackend | None = None, *, deadline: float | None = None, check: bool = True
    ) -> None:
        self.allow_private = allow_private
        self.inner = inner or httpcore.SyncBackend()
        self.deadline = deadline if deadline is not None else time.monotonic() + DOWNLOAD_DEADLINE
        self.check = check
        self.sni: dict[str, str] = {}

    def connect_tcp(self, host: str, port: int, timeout: float | None = None, local_address: str | None = None, socket_options=None):  # type: ignore[no-untyped-def]

        left = self.deadline - time.monotonic()
        if left <= 0:
            raise SyncError(f"download took longer than {DOWNLOAD_DEADLINE:.0f} s")
        timeout = left if timeout is None else min(timeout, left)
        if not self.check:
            stream = self.inner.connect_tcp(host, port, timeout=timeout, local_address=local_address, socket_options=socket_options)
            return _DeadlineStream(stream, self.deadline, self.sni)
        literal = _ip_literal(host)
        try:
            addrs = [str(literal)] if literal is not None else _resolve(host, port)
        except OSError as e:
            raise SyncError(f"cannot resolve {host}: {type(e).__name__}") from None
        if not addrs:
            raise SyncError(f"cannot resolve {host}")
        if not self.allow_private:
            bad = [a for a in addrs if not _is_global(a)]
            if bad:
                raise SyncError(f"refusing to connect to {host}: private or internal address {bad[0]} (allow_private)")
        stream = self.inner.connect_tcp(addrs[0], port, timeout=timeout, local_address=local_address, socket_options=socket_options)
        return _DeadlineStream(stream, self.deadline)

    def sleep(self, seconds: float) -> None:
        self.inner.sleep(seconds)


def _pinned_address(host: str) -> str:
    """For a request through a proxy: resolve the name here, refuse unless every address is public (fail closed,
    also when the name does not resolve), and return the address the proxy must connect to. The request then goes
    to that IP literal (Host header and TLS SNI/certificate name stay the real host), so the proxy cannot be steered
    to another address by a second DNS answer."""

    h = host.strip("[]")
    literal = _ip_literal(h)
    try:
        addrs = [str(literal)] if literal is not None else _resolve(h, 443)
    except OSError as e:
        raise SyncError(
            f"cannot resolve {host} locally: {type(e).__name__} (behind a proxy without local DNS, set SURIHARVEST_TRUST_PROXY=1)"
        ) from None
    if not addrs:
        raise SyncError(f"cannot resolve {host}")
    bad = [a for a in addrs if not _is_global(a)]
    if bad:
        raise SyncError(f"refusing to connect to {host}: private or internal address {bad[0]} (allow_private)")
    return addrs[0]


def _trusted_proxy_check(host: str) -> None:
    """SURIHARVEST_TRUST_PROXY=1: the proxy resolves and must enforce its own internal-address policy; refuse only
    what is visibly internal here (local names, internal IP literals)."""

    h = host.strip("[]").lower().rstrip(".")
    if h == "localhost" or h.endswith(".localhost"):
        raise SyncError(f"refusing to fetch {host} through the proxy: local name (allow_private)")
    literal = _ip_literal(h)
    if literal is not None:
        if not _ip_ok(literal):
            raise SyncError(f"refusing to fetch {host}: private or internal address {literal} (allow_private)")
        return
    try:  # best effort: what the local resolver knows about the name must not be internal either
        addrs = _resolve(h, 443)
    except OSError:
        return  # unknown here: the trusted proxy resolves it and enforces its own policy
    bad = [a for a in addrs if not _is_global(a)]
    if bad:
        raise SyncError(f"refusing to fetch {host}: private or internal address {bad[0]} (allow_private)")


def _proxy_for(url: httpx.URL) -> str | None:
    """The proxy the environment (HTTPS_PROXY / HTTP_PROXY / ALL_PROXY, NO_PROXY) sets for this URL, if any."""
    import urllib.request

    proxies = urllib.request.getproxies()
    if not proxies or urllib.request.proxy_bypass(url.host):
        return None
    return proxies.get(url.scheme) or proxies.get("all")


def _make_client(allow_private: bool, headers: dict[str, str], proxy: str | None = None, deadline: float | None = None) -> httpx.Client:
    """Direct: the guarded backend (address pinning + deadline). Through a proxy: the proxy is reached without the
    address check (it is usually on the local network), the target is pinned by `_pinned_address` (or, with
    SURIHARVEST_TRUST_PROXY=1, checked by `_trusted_proxy_check`)."""
    transport = httpx.HTTPTransport(proxy=proxy) if proxy else httpx.HTTPTransport()
    # httpx has no public hook for the network backend
    transport._pool._network_backend = _GuardedBackend(allow_private, deadline=deadline, check=proxy is None)
    return httpx.Client(transport=transport, follow_redirects=False, timeout=120, headers=headers, trust_env=False)


def download(
    url: str,
    token: str | None = None,
    validators: dict[str, str] | None = None,
    *,
    allow_private: bool = False,
    max_bytes: int | None = None,
    truncate: bool = False,
    user_agent: str = USER_AGENT,
) -> tuple[bytes | None, dict[str, str]]:
    """GET with size cap and total deadline. With `validators` (etag / last-modified of the last run) a 304 returns
    (None, validators). `allow_private`: the source is an internal mirror (see the comment above). `max_bytes`:
    a smaller cap; with `truncate` the first max_bytes are returned instead of an error (a reachability probe)."""
    cap = MAX_DOWNLOAD_BYTES if max_bytes is None else max_bytes
    if not url.startswith(("https://", "http://")):
        raise SyncError("http source must use http(s)")
    first = httpx.URL(url)
    literal = _ip_literal(first.host)
    allow_private = (
        allow_private
        or os.environ.get("SURIHARVEST_ALLOW_PRIVATE_DOWNLOADS") == "1"
        or (literal is not None and not literal.is_global)  # a configured internal literal
    )
    headers = {"User-Agent": user_agent}
    if validators and validators.get("etag"):
        headers["If-None-Match"] = validators["etag"]
    if validators and validators.get("last-modified"):
        headers["If-Modified-Since"] = validators["last-modified"]
    buf = bytearray()
    deadline = time.monotonic() + DOWNLOAD_DEADLINE
    clients: dict[str | None, httpx.Client] = {}
    try:
        current = first
        for _ in range(MAX_REDIRECTS + 1):
            proxy = _proxy_for(current)
            target = current
            extra = {"Authorization": f"Bearer {token}"} if token and current.host == first.host else {}
            if proxy and not allow_private:
                if os.environ.get("SURIHARVEST_TRUST_PROXY") == "1":
                    _trusted_proxy_check(current.host)
                else:
                    ip = _pinned_address(current.host)
                    target = current.copy_with(host=ip)
                    extra["Host"] = current.netloc.decode("ascii")
            client = clients.get(proxy) or clients.setdefault(proxy, _make_client(allow_private, headers, proxy, deadline))
            if target is not current:
                client._transport._pool._network_backend.sni[ip] = current.host  # type: ignore[attr-defined]
            with client.stream("GET", target, headers=extra) as resp:
                if resp.is_redirect and resp.headers.get("location"):
                    nxt = current.join(resp.headers["location"])
                    if current.scheme == "https" and nxt.scheme != "https":
                        raise SyncError("refusing redirect from https to http")
                    if nxt.scheme not in ("https", "http"):
                        raise SyncError("refusing redirect to a non-http URL")
                    current = nxt
                    continue
                if resp.status_code == 304:
                    return None, validators or {}
                resp.raise_for_status()
                new_validators = {k: resp.headers[k] for k in ("etag", "last-modified") if k in resp.headers}
                for chunk in resp.iter_bytes():
                    buf.extend(chunk)
                    if len(buf) > cap:
                        if truncate:
                            return bytes(buf[:cap]), new_validators
                        raise SyncError(f"download larger than {cap} bytes")
                    if time.monotonic() > deadline:
                        raise SyncError(f"download took longer than {DOWNLOAD_DEADLINE:.0f} s")
                return bytes(buf), new_validators
        raise SyncError(f"more than {MAX_REDIRECTS} redirects")
    except httpx.HTTPError as e:
        if isinstance(e, httpx.TimeoutException) and time.monotonic() >= deadline - 0.05:
            raise SyncError(f"download took longer than {DOWNLOAD_DEADLINE:.0f} s") from None
        # The URL may hold a secret (${secret}): never echo it.
        raise SyncError(f"download failed: {type(e).__name__}: {getattr(getattr(e, 'response', None), 'status_code', '')}") from None
    finally:
        for c in clients.values():
            c.close()


ARCHIVE_ERRORS = (tarfile.TarError, zipfile.BadZipFile, zipfile.LargeZipFile, EOFError, zlib.error, ValueError, NotImplementedError)


def extract_archive(data: bytes, name: str, dest: Path) -> None:
    """Extract a tar(.gz)/zip archive (or write a single file) into dest with path and size checks.
    A corrupt or truncated archive raises SyncError (never a tarfile/zipfile/zlib exception)."""
    try:
        _extract_archive(data, name, dest)
    except ARCHIVE_ERRORS as e:
        raise SyncError(f"corrupt archive {name!r}: {type(e).__name__}: {str(e)[:200]}") from None


MAX_TAR_HEADER_BYTES = 1024 * 1024  # GNU longname/longlink and pax headers: real ones are a few hundred bytes


class _BoundedTarInfo(tarfile.TarInfo):
    """tarfile reads a GNU longname or pax header whole into memory before any member check runs: a few MB of gzip
    can declare a header of many GB. Refuse oversized headers first."""

    def _proc_gnulong(self, tarfile):  # type: ignore[no-untyped-def]
        if self.size > MAX_TAR_HEADER_BYTES:
            raise SyncError(f"archive has a {self.size}-byte long-name header; refusing it")
        return super()._proc_gnulong(tarfile)  # type: ignore[misc]

    def _proc_pax(self, tarfile):  # type: ignore[no-untyped-def]
        if self.size > MAX_TAR_HEADER_BYTES:
            raise SyncError(f"archive has a {self.size}-byte pax header; refusing it")
        return super()._proc_pax(tarfile)  # type: ignore[misc]


def _extract_archive(data: bytes, name: str, dest: Path) -> None:
    root = dest.resolve()
    total = 0
    members = 0

    def count() -> None:
        nonlocal members
        members += 1
        if members > MAX_ARCHIVE_MEMBERS:
            raise SyncError(f"archive has more than {MAX_ARCHIVE_MEMBERS} entries")

    def target(member: str, size: int) -> Path | None:
        nonlocal total
        parts = Path(member).parts
        if not member or Path(member).is_absolute() or ".." in parts or size > MAX_FILE_BYTES:
            return None
        t = (root / member).resolve()
        if not t.is_relative_to(root):
            return None
        total += size
        if total > MAX_EXTRACTED_BYTES:
            raise SyncError("archive expands beyond the size limit")
        t.parent.mkdir(parents=True, exist_ok=True)
        return t

    low = name.lower()
    if low.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for m in zf.infolist():
                count()
                if not m.is_dir() and (t := target(m.filename, m.file_size)) is not None:
                    with zf.open(m) as fh:
                        t.write_bytes(fh.read(MAX_FILE_BYTES + 1)[:MAX_FILE_BYTES])
    elif low.endswith((".tar.gz", ".tgz", ".tar")) or data[:2] == b"\x1f\x8b":
        with tarfile.open(fileobj=io.BytesIO(data), tarinfo=_BoundedTarInfo) as tf:
            for m in tf:
                count()
                if not m.isfile():  # links, devices, dirs
                    continue
                if (t := target(m.name, m.size)) is not None and (fh := tf.extractfile(m)) is not None:
                    t.write_bytes(fh.read(MAX_FILE_BYTES))
    else:
        (root / (Path(name).name or "rules.rules")).write_bytes(data)


def sync_http(
    src: SourceConfig, ws: Workspace, suricata_version: str, last_commit: str | None, previous: dict[str, str] | None = None
) -> SyncResult:
    """Changes are computed against `previous` (the files last ingested, from the manifest), not against what was on
    disk before the download, so a file that was on disk but never ingested is picked up."""
    import json

    dest = ws.source_dir(src.name)
    state_file = ws.cache / "http" / f"{src.name}.json"
    state = json.loads(state_file.read_text()) if state_file.exists() else {}
    url = src.resolved_url(suricata_version)
    url_key = sha256_hex(url)  # the URL may contain a secret: store only its hash
    usable = state.get("url") == url_key and dest.exists() and last_commit is not None
    data, validators = download(url, src.token(), state.get("validators") if usable else None, allow_private=src.allow_private)
    prev = previous if previous is not None else hash_tree(dest)
    if data is None or (usable and sha256_hex(data) == last_commit):
        if data is not None:
            state_file.write_text(json.dumps({"url": url_key, "validators": validators}), newline="\n")
        return _diff(prev, hash_tree(dest), SyncResult(last_commit, last_commit, dest))
    # The new validators are only stored once the download has been extracted and swapped in (and the caller has
    # ingested it: see SyncResult.validators / save_validators). Until then the old ones are dropped, so a failed
    # extraction or ingest is retried with a full download on the next run instead of a 304 "unchanged".
    state_file.unlink(missing_ok=True)
    before = prev
    stage = _stage(dest)
    try:
        _unpack(src, data, stage)
    except BaseException:
        rmtree(stage, ignore_errors=True)
        raise
    _swap(stage, dest)
    res = _diff(before, hash_tree(dest), SyncResult(None, sha256_hex(data), dest))
    res.too_large = large_files(dest)
    res.validators_file = state_file
    res.validators = {"url": url_key, "validators": validators}
    return res


def _stage(dest: Path) -> Path:
    stage = dest.with_name(dest.name + ".staging")
    if stage.exists():
        rmtree(stage)
    stage.mkdir(parents=True)
    return stage


def _unpack(src: SourceConfig, data: bytes, stage: Path) -> None:
    url_name = src.url.split("?")[0].rstrip("/").rsplit("/", 1)[-1]
    if src.type == "http-file":
        name = url_name if url_name.endswith(".rules") else url_name + ".rules"
        (stage / name).write_bytes(data)
    else:
        extract_archive(data, url_name, stage)


def _swap(stage: Path, dest: Path) -> None:
    old = dest.with_name(dest.name + ".old")
    if old.exists():
        rmtree(old)
    if dest.exists():
        dest.rename(old)
    stage.rename(dest)
    if old.exists():
        rmtree(old)


def sync_http_majors(
    src: SourceConfig, ws: Workspace, versions: dict[str, str], last_commit: str | None, previous: dict[str, str] | None = None
) -> SyncResult:
    """One download per Suricata major (majors.py): `versions` maps a major to the version that fills
    ${suricata_version}; each copy is extracted into corpus/<name>/@<major>/. The source's commit is the hash of the
    per-major download hashes; validators (ETag / Last-Modified) are kept per major."""
    import json
    import shutil

    dest = ws.source_dir(src.name)
    state_file = ws.cache / "http" / f"{src.name}.json"
    state = json.loads(state_file.read_text()) if state_file.exists() else {}
    old = state.get("majors") if isinstance(state.get("majors"), dict) else {}
    prev = previous if previous is not None else hash_tree(dest)
    got: dict[str, tuple[bytes | None, dict | None, str, str]] = {}  # major -> (data or None = 304, validators, url key, sha)
    for m, version in sorted(versions.items()):
        url = src.resolved_url(version)
        url_key = sha256_hex(url)  # the URL may contain a secret: store only its hash
        st = old.get(m) or {}
        usable = st.get("url") == url_key and bool(st.get("sha")) and (dest / f"@{m}").is_dir() and last_commit is not None
        data, validators = download(url, src.token(), st.get("validators") if usable else None, allow_private=src.allow_private)
        if data is None and not usable:
            raise SyncError(f"{src.name}: no content for Suricata {m}")
        got[m] = (data, validators, url_key, st["sha"] if data is None else sha256_hex(data))
    digest = sha256_hex("".join(f"{m}:{sha}\n" for m, (_, _, _, sha) in sorted(got.items())))
    new_state = {"majors": {m: {"url": k, "validators": v, "sha": sha} for m, (_, v, k, sha) in got.items()}}
    on_disk = {p.name for p in dest.iterdir()} if dest.is_dir() else set()
    if digest == last_commit and on_disk == {f"@{m}" for m in got}:
        state_file.parent.mkdir(parents=True, exist_ok=True)
        state_file.write_text(json.dumps(new_state), newline="\n")
        return _diff(prev, hash_tree(dest), SyncResult(last_commit, last_commit, dest))
    state_file.unlink(missing_ok=True)  # stored again once the download has been ingested (save_validators)
    stage = _stage(dest)
    try:
        for m, (data, _, _, _) in got.items():
            sub = stage / f"@{m}"
            if data is None:  # 304: this major's copy is unchanged
                shutil.copytree(dest / f"@{m}", sub, symlinks=True)
            else:
                sub.mkdir()
                _unpack(src, data, sub)
    except BaseException:
        rmtree(stage, ignore_errors=True)
        raise
    _swap(stage, dest)
    res = _diff(prev, hash_tree(dest), SyncResult(None, digest, dest))
    res.too_large = large_files(dest)
    res.validators_file = state_file
    res.validators = new_state
    return res


def save_validators(res: SyncResult) -> None:
    """Persist the HTTP validators (ETag / Last-Modified) of a download, after it was ingested successfully."""
    import json

    if res.validators_file is not None and res.validators is not None:
        res.validators_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = res.validators_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(res.validators), newline="\n")
        tmp.replace(res.validators_file)


def large_files(root: Path) -> list[str]:
    out = []
    for p in root.rglob("*"):
        if p.is_file() and not p.is_symlink() and p.stat().st_size > MAX_FILE_BYTES:
            out.append(str(p.relative_to(root)))
    return sorted(out)


def sync_local(src: SourceConfig, previous: dict[str, str], base: Path | None = None) -> SyncResult:
    root = Path(src.url).expanduser()
    if not root.is_absolute() and base is not None:  # relative to the workspace, so the workspace can be moved
        root = base / root
    root = root.resolve()
    if not root.is_dir():
        raise SyncError(f"local source path does not exist: {root}")
    # only the files this source selects: several sources can share one folder
    after = {k: v for k, v in hash_tree(root).items() if path_selected(k, src)}
    previous = {k: v for k, v in previous.items() if path_selected(k, src)}
    digest = sha256_hex("".join(f"{k}:{v}\n" for k, v in sorted(after.items())))
    return _diff(previous, after, SyncResult(None, digest, root))


def fetch(
    src: SourceConfig,
    ws: Workspace,
    last_commit: str | None,
    previous: dict[str, str],
    suricata_version: str,
    per_major: dict[str, str] | None = None,
) -> SyncResult:
    """`per_major` (majors.source_rulesets): major -> version for a source downloaded once per Suricata major."""
    if src.type == "git":
        return sync_git(src, ws, last_commit)
    if src.type in ("http-tarball", "http-file"):
        if per_major:
            return sync_http_majors(src, ws, per_major, last_commit, previous)
        return sync_http(src, ws, suricata_version, last_commit, previous)
    return sync_local(src, previous, ws.root)
