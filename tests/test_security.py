"""Security guards: Host check, archive limits, Lua off in validation, https-only upload."""

from __future__ import annotations

import contextlib
import io
import tarfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from suriharvest import sync, validate
from suriharvest.config import Workspace
from suriharvest.web.app import create_app
from tests.test_pipeline import run, ws  # noqa: F401 - fixture


def test_bracketed_host_is_checked(ws: Path):  # noqa: F811
    c = TestClient(create_app(Workspace(ws), allowed_hosts={"testserver"}))
    assert c.get("/", headers={"host": "[::1]:8077"}).status_code == 200
    assert c.get("/", headers={"host": "[2001:db8::1]:8077"}).status_code == 421


def test_archive_member_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(sync, "MAX_ARCHIVE_MEMBERS", 5)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for i in range(10):
            info = tarfile.TarInfo(f"r{i}.rules")
            tf.addfile(info, io.BytesIO(b""))
    with pytest.raises(sync.SyncError, match="more than 5 entries"):
        sync.extract_archive(buf.getvalue(), "x.tar.gz", tmp_path)


def test_validation_never_enables_lua_or_passes_keys(monkeypatch: pytest.MonkeyPatch):
    assert "security.lua.allow-rules=no" in validate.OVERRIDES
    monkeypatch.setenv("SOURCE_TOKEN", "secret")
    monkeypatch.setenv("PATH", "/usr/bin")
    env = validate._env()
    assert "SOURCE_TOKEN" not in env and env["PATH"] == "/usr/bin"


class _FakeInner:
    """Records where the guarded backend connects instead of opening sockets."""

    def __init__(self) -> None:
        self.connected: list[str] = []

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):  # type: ignore[no-untyped-def]
        self.connected.append(host)
        return object()

    def sleep(self, seconds):  # type: ignore[no-untyped-def]
        pass


def test_guarded_backend_pins_checked_addresses(monkeypatch):
    import pytest

    from suriharvest import sync

    answers = {"feeds.example.org": [["93.184.216.34"], ["10.0.0.5"]], "mixed.example.org": [["93.184.216.34", "127.0.0.1"]]}

    def resolve(host, port):  # type: ignore[no-untyped-def]
        if host not in answers:
            raise OSError("NXDOMAIN")
        return answers[host].pop(0) if len(answers[host]) > 1 else answers[host][0]

    monkeypatch.setattr(sync, "_resolve", resolve)
    inner = _FakeInner()
    b = sync._GuardedBackend(allow_private=False, inner=inner)
    b.connect_tcp("feeds.example.org", 443)
    assert inner.connected == ["93.184.216.34"]  # connects to the address it checked, not to the name
    with pytest.raises(sync.SyncError, match="private"):  # rebinding: the next lookup answers a private address
        b.connect_tcp("feeds.example.org", 443)
    with pytest.raises(sync.SyncError, match="private"):  # mixed public + loopback answer
        b.connect_tcp("mixed.example.org", 443)
    with pytest.raises(sync.SyncError, match="cannot resolve"):  # lookup failure fails closed
        b.connect_tcp("nowhere.example.org", 443)
    with pytest.raises(sync.SyncError, match="private"):
        b.connect_tcp("169.254.169.254", 80)
    sync._GuardedBackend(allow_private=True, inner=inner).connect_tcp("10.1.2.3", 80)
    assert inner.connected[-1] == "10.1.2.3"


def test_guarded_backend_falls_back_to_the_next_checked_address(monkeypatch):
    import httpcore
    import pytest

    from suriharvest import sync

    class NoIPv6(_FakeInner):
        def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):  # type: ignore[no-untyped-def]
            self.connected.append(host)
            if ":" in host:
                raise httpcore.ConnectError("[Errno 101] Network is unreachable")
            return object()

    # A dual-stack name on a host without an IPv6 route: the IPv4 address still works.
    monkeypatch.setattr(sync, "_resolve", lambda host, port: ["2600:9000::1", "93.184.216.34"])
    inner = NoIPv6()
    sync._GuardedBackend(allow_private=False, inner=inner).connect_tcp("feeds.example.org", 443)
    assert inner.connected == ["2600:9000::1", "93.184.216.34"]
    # Every address fails: the last connection error is raised (the download reports it as failed).
    monkeypatch.setattr(sync, "_resolve", lambda host, port: ["2600:9000::1", "2600:9000::2"])
    with pytest.raises(httpcore.ConnectError):
        sync._GuardedBackend(allow_private=False, inner=NoIPv6()).connect_tcp("feeds.example.org", 443)


def test_resolve_keeps_the_resolver_order(monkeypatch):
    import socket

    from suriharvest import sync

    answer = [(socket.AF_INET, 1, 6, "", ("3.0.0.1", 443)), (socket.AF_INET6, 1, 6, "", ("2600::1%eth0", 443, 0, 0))]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: answer + answer)
    assert sync._resolve("feeds.example.org", 443) == ["3.0.0.1", "2600::1"]


def test_download_redirects_deadline_and_token(monkeypatch):
    import httpx
    import pytest

    from suriharvest import sync

    seen: list[tuple[str, str | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((str(request.url), request.headers.get("authorization")))
        if request.url.path == "/down":
            return httpx.Response(302, headers={"location": "http://feeds.example.org/r.rules"})
        if request.url.path == "/other":
            return httpx.Response(302, headers={"location": "https://cdn.example.net/r.rules"})
        if request.url.path == "/loop":
            return httpx.Response(302, headers={"location": "/loop"})
        return httpx.Response(200, content=b'alert tcp any any -> any any (msg:"x"; sid:1; rev:1;)\n')

    made: list[bool] = []

    def make_client(allow_private, headers, proxy=None, deadline=None):  # type: ignore[no-untyped-def]
        made.append(allow_private)
        return httpx.Client(transport=httpx.MockTransport(handler), headers=headers, follow_redirects=False)

    monkeypatch.setattr(sync, "_make_client", make_client)
    with pytest.raises(sync.SyncError, match="https to http"):
        sync.download("https://feeds.example.org/down")
    with pytest.raises(sync.SyncError, match="redirects"):
        sync.download("https://feeds.example.org/loop")
    data, _ = sync.download("https://feeds.example.org/other", token="t0k")
    assert data and b"sid:1" in data
    assert seen[-2] == ("https://feeds.example.org/other", "Bearer t0k") and seen[-1] == ("https://cdn.example.net/r.rules", None)
    # internal-ness is explicit: per source, by env var, or a private IP literal; never inferred from DNS
    sync.download("https://feeds.example.org/r.rules")
    sync.download("https://feeds.example.org/r.rules", allow_private=True)
    sync.download("http://10.0.0.7/r.rules")
    assert made[-3:] == [False, True, True]
    monkeypatch.setattr(sync, "DOWNLOAD_DEADLINE", -1.0)
    with pytest.raises(sync.SyncError, match="longer than"):
        sync.download("https://feeds.example.org/r.rules")


def test_git_token_header_is_scoped_to_the_source_origin():
    env = sync._git_auth_env("https://Git.Example.org:8443/owner/repo.git", "tok")
    assert env["GIT_CONFIG_KEY_0"] == "http.https://git.example.org:8443/.extraHeader"
    assert env["GIT_CONFIG_VALUE_0"] == "Authorization: Bearer tok"
    assert sync._git_auth_env("https://git.example.org/o/r.git", "tok")["GIT_CONFIG_KEY_0"] == ("http.https://git.example.org/.extraHeader")
    assert sync._git_auth_env("ssh://git.example.org/o/r.git", "tok") == {}
    assert sync._git_auth_env("/srv/repo", "tok") == {}
    assert sync._git_auth_env("https://git.example.org/o/r.git", None) == {}
    assert "http.followRedirects=false" in sync.GIT_BASE_CONFIG


def test_git_redirect_is_not_followed_and_token_stays_on_its_origin():
    """A git source redirecting to another host: git stops; even if redirects were followed, no token goes there."""
    import os
    import subprocess
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    seen: dict[str, list[str | None]] = {"a": [], "b": []}

    def handler(name: str, location: str | None):
        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                seen[name].append(self.headers.get("Authorization"))
                if location:
                    self.send_response(302)
                    self.send_header("Location", location + self.path)
                else:
                    self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass

        return H

    b = ThreadingHTTPServer(("127.0.0.1", 0), handler("b", None))
    a = ThreadingHTTPServer(("127.0.0.1", 0), handler("a", f"http://localhost:{b.server_port}"))
    for srv in (a, b):
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{a.server_port}/o/r.git"
    env = {k: v for k, v in os.environ.items() if "proxy" not in k.lower()}
    env |= {"GIT_TERMINAL_PROMPT": "0", **sync._git_auth_env(url, "tok")}
    # plain http only for this local test; production allows https only
    base = ["git", *sync.GIT_BASE_CONFIG, "-c", "protocol.http.allow=always"]
    try:
        r = subprocess.run([*base, "ls-remote", url], check=False, env=env, capture_output=True, timeout=30)
        assert r.returncode != 0
        assert seen["a"] and seen["a"][0] == "Bearer tok"
        assert seen["b"] == []  # redirect not followed
        # Even with redirects forced on, the scoped header is not sent to the other origin.
        subprocess.run([*base, "-c", "http.followRedirects=true", "ls-remote", url], check=False, env=env, capture_output=True, timeout=30)
        assert seen["b"] and all(h is None for h in seen["b"])
    finally:
        a.shutdown()
        b.shutdown()


def _serve(handler_body):  # type: ignore[no-untyped-def]
    """A one-thread TCP server on 127.0.0.1; handler_body(conn, request_bytes) answers. Returns (port, seen)."""
    import socket
    import threading

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    seen: list[bytes] = []

    def loop() -> None:
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            with conn:
                req = b""
                while b"\r\n\r\n" not in req:
                    part = conn.recv(4096)
                    if not part:
                        break
                    req += part
                seen.append(req)
                with contextlib.suppress(OSError):
                    handler_body(conn, req)

    threading.Thread(target=loop, daemon=True).start()
    return srv, seen


RULE = b'alert tcp any any -> any any (msg:"x"; sid:1; rev:1;)\n'


def _ok(conn, req):  # type: ignore[no-untyped-def]
    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(RULE) + RULE)


def test_http_proxy_from_the_environment_is_used_with_the_address_pinned(monkeypatch):
    import pytest

    from suriharvest import sync

    srv, seen = _serve(_ok)
    port = srv.getsockname()[1]
    for k in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy", "SURIHARVEST_TRUST_PROXY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("http_proxy", f"http://127.0.0.1:{port}")
    monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{port}")
    answers = {
        "feeds.example.org": ["93.184.216.34"],
        "inside.example.org": ["10.0.0.5"],
        "mixed.example.org": ["93.184.216.34", "127.0.0.1"],
    }

    def resolve(host, port):  # type: ignore[no-untyped-def]
        if host not in answers:
            raise OSError("NXDOMAIN")
        return answers[host]

    monkeypatch.setattr(sync, "_resolve", resolve)
    # pinned: the proxy is asked for the checked address, the Host header keeps the name
    data, _ = sync.download("http://feeds.example.org/r.rules")
    assert data == RULE
    assert seen[-1].startswith(b"GET http://93.184.216.34/r.rules HTTP/1.1") and b"\r\nHost: feeds.example.org\r\n" in seen[-1]
    n = len(seen)
    for url, msg in [
        ("http://nowhere.example.org/r.rules", "cannot resolve"),  # fail closed
        ("http://inside.example.org/r.rules", "private"),
        ("http://mixed.example.org/r.rules", "private"),
        ("http://localhost/r.rules", "cannot resolve"),
    ]:
        with pytest.raises(sync.SyncError, match=msg):
            sync.download(url)
    assert len(seen) == n  # nothing reached the proxy
    sync.download("http://inside.example.org/r.rules", allow_private=True)  # an internal mirror, explicitly
    assert seen[-1].startswith(b"GET http://inside.example.org/r.rules")
    # opt-in: the proxy resolves (and must refuse internal targets itself); visibly internal names are still refused
    monkeypatch.setenv("SURIHARVEST_TRUST_PROXY", "1")
    sync.download("http://nowhere.example.org/r.rules")
    assert seen[-1].startswith(b"GET http://nowhere.example.org/r.rules")
    with pytest.raises(sync.SyncError, match="local name"):
        sync.download("http://localhost/r.rules")
    monkeypatch.delenv("SURIHARVEST_TRUST_PROXY")
    # NO_PROXY: direct connection through the guarded backend
    monkeypatch.setenv("no_proxy", "nowhere.example.org")
    monkeypatch.setenv("NO_PROXY", "nowhere.example.org")
    with pytest.raises(sync.SyncError, match="cannot resolve"):
        sync.download("http://nowhere.example.org/r.rules")
    srv.close()


def test_tls_through_a_pinned_tunnel_checks_the_real_host_name():
    import time

    from suriharvest import sync

    class Inner:
        def __init__(self) -> None:
            self.names: list[str | None] = []

        def start_tls(self, ssl_context, server_hostname=None, timeout=None):  # type: ignore[no-untyped-def]
            self.names.append(server_hostname)
            return self

    inner = Inner()
    stream = sync._DeadlineStream(inner, time.monotonic() + 60, {"93.184.216.34": "feeds.example.org"})  # type: ignore[arg-type]
    stream.start_tls(None, server_hostname="93.184.216.34")
    stream.start_tls(None, server_hostname="other.example.net")
    assert inner.names == ["feeds.example.org", "other.example.net"]


def test_deadline_covers_connect_and_response_headers(monkeypatch):
    import time

    import pytest

    from suriharvest import sync

    def trickle(conn, req):  # type: ignore[no-untyped-def]
        conn.sendall(b"HTTP/1.1 200 OK\r\n")
        for i in range(30):  # one header line every 0.2 s: 6 s of headers
            time.sleep(0.2)
            conn.sendall(b"X-Slow-%d: y\r\n" % i)

    srv, _ = _serve(trickle)
    for k in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(sync, "DOWNLOAD_DEADLINE", 1.0)
    t0 = time.monotonic()
    with pytest.raises(sync.SyncError, match="longer than"):
        sync.download(f"http://127.0.0.1:{srv.getsockname()[1]}/r.rules")
    assert time.monotonic() - t0 < 3
    srv.close()


@pytest.mark.parametrize(
    ("host", "internal"),
    [
        ("127.0.0.1", True),
        ("2130706433", True),  # decimal
        ("0x7f000001", True),  # hex
        ("0177.0.0.1", True),  # octal
        ("127.1", True),  # short form
        ("0x7f.1", True),
        ("10.0.0.5", True),
        ("169.254.169.254", True),
        ("[::ffff:127.0.0.1]", True),  # IPv4-mapped
        ("::ffff:7f00:1", True),
        ("[::127.0.0.1]", True),  # IPv4-compatible
        ("64:ff9b::7f00:1", True),  # NAT64
        ("2002:7f00:1::", True),  # 6to4 of 127.0.0.1
        ("[::1]", True),
        ("93.184.216.34", False),
        ("1572395042", False),  # 93.184.216.34 as a decimal
        ("[::ffff:93.184.216.34]", False),
        ("2606:4700::1111", False),
        ("2002:5db8:d822::1", True),  # 6to4 of a public IPv4: refused outright (tunnels to the embedded address)
        ("2001:0:4136:e378:8000:63bf:3fff:fdd2", True),  # Teredo: refused outright
        ("[::93.184.216.34]", True),  # IPv4-compatible: refused outright
        ("64:ff9b::5db8:d822", False),  # NAT64 of a public IPv4
    ],
)
def test_every_ip_literal_form_is_normalised_before_the_check(host: str, internal: bool):
    from suriharvest import sync

    ip = sync._ip_literal(host)
    assert ip is not None and (not sync._ip_ok(ip)) == internal
    assert sync._is_global(str(ip)) == (not internal)  # the checked string is the one connected to
    if internal:  # also refused on the trusted-proxy path, which never resolves names
        with pytest.raises(sync.SyncError, match="internal"):
            sync._trusted_proxy_check(host)
    else:
        sync._trusted_proxy_check(host)


@pytest.mark.parametrize("host", ["0x", "1.2.3.4.5", "99999999999", "0x1ffffffff"])
def test_numeric_hosts_that_are_no_address_are_refused(host: str):
    from suriharvest import sync

    with pytest.raises(sync.SyncError, match="numeric"):
        sync._ip_literal(host)


def test_trusted_proxy_still_refuses_names_that_resolve_internally(monkeypatch):
    from suriharvest import sync

    monkeypatch.setattr(sync, "_resolve", lambda h, p: {"inside.example.org": ["10.1.2.3"]}.get(h) or (_ for _ in ()).throw(OSError("x")))
    with pytest.raises(sync.SyncError, match="private"):
        sync._trusted_proxy_check("inside.example.org")
    sync._trusted_proxy_check("unknown.example.org")  # unknown locally: left to the trusted proxy
