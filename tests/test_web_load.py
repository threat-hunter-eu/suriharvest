"""Web server under load: search never answers 500, downloads queue and stream, cross-site
GETs and chunked bodies are refused, the overview is cached, memory stays bounded."""

from __future__ import annotations

import random
import re
import sqlite3
import threading
import tracemalloc
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from suriharvest.config import Workspace
from suriharvest.search import _fts_query
from suriharvest.web.app import ExportQueue, create_app, sweep_stale_downloads
from tests.test_pipeline import run, ws  # noqa: F401 - fixture

ORIGIN = {"origin": "http://testserver"}
HOSTS = {"testserver"}
SAME = SimpleNamespace(headers={})  # a request with no browser headers (curl, suricata-update)


@pytest.fixture
def client(ws: Path) -> TestClient:  # noqa: F811
    return TestClient(create_app(Workspace(ws), allowed_hosts=HOSTS))


# ---------------------------------------------------------------------------------------------------------------
# the FTS query is always valid


def test_three_words_with_a_long_one_and_nul_are_not_500(client: TestClient):
    for q in ("powershell download cradle", "ransomware http dns", "gate.php cobaltstrike beacon", "abc\x00def", "a\x00", "\x00"):
        for url in ("/api/search", "/search", "/export"):
            r = client.get(url, params={"q": q})
            assert r.status_code < 500, (url, q, r.status_code, r.text[:200])
    assert client.get("/api/search", params={"q": "powershell download cradle"}).status_code == 200


ALPHABET = ['"', "'", "(", ")", "*", ":", "-", "^", "+", "\x00", "\x01", "\x7f", " ", "é", "恶", "\ud800", "😀", "NEAR", "OR", "AND", "NOT"]


def _fuzz_words(rng: random.Random) -> list[str]:
    words = []
    for _ in range(rng.randint(0, 8)):
        if rng.random() < 0.4:
            words.append("".join(rng.choice("abcdefghijklmnop") for _ in range(rng.randint(1, 14))))
        else:
            words.append("".join(rng.choice(ALPHABET + list("abcxyz")) for _ in range(rng.randint(1, 10))))
    return words


def test_fts_query_builder_is_total():
    """Every word list gives a MATCH expression FTS5 accepts (or "", meaning no full-text condition)."""
    db = sqlite3.connect(":memory:")
    db.execute("CREATE VIRTUAL TABLE rules_fts USING fts5(msg, contents, metadata, refs, raw, tokenize='unicode61 remove_diacritics 2')")
    db.execute("INSERT INTO rules_fts VALUES ('powershell download cradle', '', '', '', '')")
    rng = random.Random(20261114)
    cases = [["powershell", "download", "cradle"], ["ransomware", "http", "dns"], ["cobalt", "strike"], ["a\x00b"], ['"'], ["\x00"]]
    cases += [_fuzz_words(rng) for _ in range(3000)]
    for words in cases:
        m = _fts_query(words)
        if m:
            db.execute(
                "SELECT count(*) FROM rules_fts WHERE rules_fts MATCH ?", (m.encode("utf-8", "surrogatepass").decode("utf-8", "replace"),)
            )
    assert (
        db.execute(
            "SELECT count(*) FROM rules_fts WHERE rules_fts MATCH ?", (_fts_query(["powershell", "download", "cradle"]),)
        ).fetchone()[0]
        == 1
    )


def test_web_search_fuzz_never_500(client: TestClient):
    rng = random.Random(7)
    for _ in range(150):
        q = " ".join(_fuzz_words(rng)).encode("utf-8", "replace").decode()
        if rng.random() < 0.3:
            q += rng.choice([" proto:tcp", " sid:12", " msg:x", " cve:*", " source:et"])
        r = client.get("/api/search", params={"q": q})
        assert r.status_code < 500, (q, r.status_code, r.text[:200])


def test_an_escaped_exception_is_a_normal_500_and_the_next_request_works(client: TestClient, monkeypatch: pytest.MonkeyPatch):
    from suriharvest.web import ui

    def boom(*a, **k):  # type: ignore[no-untyped-def]
        raise RuntimeError("boom")

    monkeypatch.setattr(ui, "split_query", boom)
    r = client.get("/api/search", params={"q": "x"})
    assert r.status_code == 500 and "internal error" in r.text and "boom" not in r.text
    assert client.get("/about").status_code == 200


# ---------------------------------------------------------------------------------------------------------------
# downloads queue, stream and refuse cross-site requests


def test_export_queue_bounds_running_and_waiting():
    q = ExportQueue(running=1, waiting=1, wait_seconds=5)
    entered, release = threading.Event(), threading.Event()

    def hold() -> None:
        with q.slot(SAME):
            entered.set()
            release.wait(5)

    first = threading.Thread(target=hold)
    first.start()
    assert entered.wait(5)
    waiter_done = threading.Event()

    def wait_turn() -> None:
        with q.slot(SAME):
            waiter_done.set()

    second = threading.Thread(target=wait_turn)
    second.start()
    for _ in range(100):  # the second request is admitted (waiting)
        if q._admitted == 2:
            break
        threading.Event().wait(0.01)
    with pytest.raises(HTTPException) as e, q.slot(SAME):
        pass
    assert e.value.status_code == 429 and e.value.headers["Retry-After"]
    release.set()
    first.join(5)
    second.join(5)
    assert waiter_done.is_set() and q._admitted == 0
    with q.slot(SAME):  # free again
        pass


def test_downloads_stream_from_disk_and_clean_up(client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    import tempfile

    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    r = client.get("/export/download", params={"q": "gate.php"})
    assert r.status_code == 200 and "gate.php" in r.text and "attachment" in r.headers["content-disposition"]
    z = client.get("/export/download", params={"q": "gate.php", "fmt": "zip"})
    assert z.status_code == 200 and z.content[:2] == b"PK"
    assert not [p for p in tmp_path.iterdir() if p.name.startswith("suriharvest-web-")]


def test_expensive_gets_refuse_cross_site_requests(client: TestClient):
    for url in ("/export/download?q=gate.php", "/api/search?q=gate.php", "/export?q=gate.php"):
        assert client.get(url, headers={"sec-fetch-site": "cross-site"}).status_code == 403, url
        assert client.get(url, headers={"sec-fetch-site": "same-site"}).status_code == 403, url
        assert client.get(url, headers={"origin": "http://evil.example"}).status_code == 403, url
        assert client.get(url, headers={"sec-fetch-site": "same-origin"}).status_code == 200, url
        assert client.get(url).status_code == 200, url  # curl, suricata-update
    assert client.get("/about", headers={"sec-fetch-site": "cross-site"}).status_code == 200  # a link from elsewhere


# ---------------------------------------------------------------------------------------------------------------
# request bodies and allowed hosts


def test_post_bodies_need_a_length(client: TestClient):
    def chunks():  # type: ignore[no-untyped-def]
        yield b"h=" + b"a" * 1000

    r = client.post("/export/download", content=chunks(), headers={**ORIGIN, "content-type": "application/x-www-form-urlencoded"})
    assert r.status_code == 411
    big = client.post("/export/download", content=b"x" * (1024 * 1024 + 1), headers=ORIGIN)
    assert big.status_code == 413


def test_testserver_is_not_a_production_host(ws: Path):  # noqa: F811
    c = TestClient(create_app(Workspace(ws)))
    assert c.get("/").status_code == 421
    assert c.get("/", headers={"host": "127.0.0.1:8077"}).status_code == 200


# ---------------------------------------------------------------------------------------------------------------
# cached aggregates and bounded memory


def test_overview_aggregates_are_cached(client: TestClient):
    from sqlalchemy import event
    from sqlalchemy.engine import Engine

    seen: list[str] = []

    def count(conn, cursor, statement, *a):  # type: ignore[no-untyped-def]
        seen.append(statement)

    event.listen(Engine, "before_cursor_execute", count)
    try:
        first = client.get("/")
        second = client.get("/")
    finally:
        event.remove(Engine, "before_cursor_execute", count)
    assert first.status_code == second.status_code == 200
    assert first.text.count("rules") == second.text.count("rules")
    agg = [x for x in seen if x.startswith("SELECT j.value, count(*) FROM logic_groups, json_each(logic_groups.loads_in)")]
    assert len(agg) == 1, "the second overview recomputed its aggregates"


def test_memory_stays_bounded_over_a_mixed_soak(client: TestClient):
    urls = [
        "/",
        "/search?q=gate.php",
        "/api/search?q=powershell+download+cradle",
        "/sources",
        "/export?q=gate.php",
        "/export/download?q=gate.php",
    ]
    for u in urls:  # warm caches, templates, imports
        client.get(u)
    tracemalloc.start()
    try:
        base = tracemalloc.take_snapshot()
        for i in range(120):
            assert client.get(urls[i % len(urls)]).status_code == 200
        after = tracemalloc.take_snapshot()
    finally:
        tracemalloc.stop()
    grown = sum(s.size_diff for s in after.compare_to(base, "filename"))
    assert grown < 8 * 1024 * 1024, f"{grown / 1e6:.1f} MB retained after 120 requests"


def test_every_route_that_takes_a_download_slot_refuses_cross_site(client: TestClient):
    """The same-origin check sits in ExportQueue.slot, so a download route outside EXPENSIVE_GET is covered too."""
    run("profile", "create", "default", "--query", "source:et")
    run("profile", "build", "default")
    build = re.search(r"/profiles/default/builds/(\d+)/", client.get("/profiles").text).group(1)  # type: ignore[union-attr]
    q = ExportQueue()
    with pytest.raises(HTTPException) as e, q.slot(SimpleNamespace(headers={"sec-fetch-site": "cross-site"})):
        pass
    assert e.value.status_code == 403
    urls = [
        "/export/download?q=gate.php",
        "/export/download?profile=default",
        "/feed/default/all.tar.gz",
        f"/profiles/default/export/{build}/download",
        f"/profiles/default/export/{build}/download?fmt=zip",
    ]
    for url in urls:
        assert client.get(url).status_code == 200, url
        for bad in ({"sec-fetch-site": "cross-site"}, {"sec-fetch-site": "same-site"}, {"origin": "http://evil.example"}):
            assert client.get(url, headers=bad).status_code == 403, (url, bad)


def test_an_aborted_download_leaves_no_temp_folder(client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    import tempfile

    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    with client.stream("GET", "/export/download", params={"q": "gate.php", "fmt": "zip"}) as r:
        assert r.status_code == 200 and int(r.headers["content-length"]) > 0
        next(r.iter_bytes(16))  # read a little, then hang up
    assert not [p for p in tmp_path.iterdir() if p.name.startswith("suriharvest-web-")]


def test_stale_download_folders_are_swept(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    import os
    import tempfile
    import time

    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    old, fresh, other = tmp_path / "suriharvest-web-old", tmp_path / "suriharvest-feed-new", tmp_path / "suriharvest-other"
    for d in (old, fresh, other):
        (d / "out").mkdir(parents=True)
    past = time.time() - 7200
    for d in (old, other):
        os.utime(d, (past, past))
    assert sweep_stale_downloads() == 1
    assert not old.exists() and fresh.exists() and other.exists()


def test_downloads_are_built_in_a_child_process():
    """Exports run in a fresh process: the server's memory and GIL stay free, and the memory goes back when it exits."""
    import os

    from suriharvest.web.downloads import run_isolated

    assert run_isolated(os.getpid) != os.getpid()


def test_sources_page_is_cached_until_something_changes(client: TestClient):
    from sqlalchemy import event
    from sqlalchemy.engine import Engine

    seen: list[str] = []

    def count(conn, cursor, statement, *a):  # type: ignore[no-untyped-def]
        seen.append(statement)

    event.listen(Engine, "before_cursor_execute", count)
    try:
        first = client.get("/sources")
        second = client.get("/sources")
    finally:
        event.remove(Engine, "before_cursor_execute", count)
    assert first.status_code == second.status_code == 200 and first.text.count("<tr") == second.text.count("<tr")
    assert sum("json_each(g.flags)" in x for x in seen) == 1


def test_sweep_never_follows_a_planted_link_nor_removes_others_folders(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The temp folder is shared: a link named like a download folder must not be followed, chmod-ed or emptied."""
    import os
    import stat
    import tempfile
    import time

    from suriharvest.portable import rmtree

    shared = tmp_path / "tmp"
    shared.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(shared))
    victim = tmp_path / "victim"
    (victim / "keep").mkdir(parents=True)
    victim.chmod(0o755)
    link = shared / "suriharvest-web-planted"
    link.symlink_to(victim, target_is_directory=True)
    past = time.time() - 7200
    os.utime(link, (past, past), follow_symlinks=False)
    os.utime(victim, (past, past))
    assert sweep_stale_downloads() == 0
    assert stat.S_IMODE(victim.stat().st_mode) == 0o755 and (victim / "keep").exists() and link.is_symlink()
    # rmtree on a link (as the sweep did before) refuses without touching the target's mode
    rmtree(link, ignore_errors=True)
    assert stat.S_IMODE(victim.stat().st_mode) == 0o755 and (victim / "keep").exists()
    # a folder owned by another user is left alone
    other = shared / "suriharvest-web-other"
    other.mkdir()
    os.utime(other, (past, past))
    monkeypatch.setattr(os, "getuid", lambda: os.stat(other).st_uid + 1)
    assert sweep_stale_downloads() == 0 and other.exists()


def test_finished_downloads_being_sent_are_bounded(client: TestClient, monkeypatch: pytest.MonkeyPatch):
    queue = client.app.state.exports
    queue._max_sending = 0
    r = client.get("/export/download", params={"q": "gate.php", "fmt": "rules"})
    assert r.status_code == 429 and "being sent" in r.text and r.headers["retry-after"] == "15"  # kept by the error page
    api = client.get("/api/search?limit=0")
    assert api.status_code == 400
    missing = client.get("/no/such/page")
    assert missing.status_code == 404 and "text/html" in missing.headers["content-type"]  # the HTML error page
    assert client.get("/api/nothing-here").json() == {"detail": "Not Found"}
    queue._max_sending = 1
    r = client.get("/export/download", params={"q": "gate.php", "fmt": "rules"})
    assert r.status_code == 200 and queue.sending == 0  # released when the body was sent


def test_a_client_that_stops_reading_is_disconnected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Real server, a client that reads one chunk then stalls: the send times out, the chunks are closed (the temp
    file with them) and the send no longer counts."""
    import socket
    import threading
    import time

    import uvicorn
    from fastapi import FastAPI

    from suriharvest.web import app as web_app

    monkeypatch.setattr(web_app, "SEND_IDLE_SECONDS", 1.0)
    closed, done = threading.Event(), threading.Event()

    def chunks():  # type: ignore[no-untyped-def]
        try:
            for _ in range(4096):  # 4 GiB if anyone read it all
                yield b"x" * (1 << 20)
        finally:
            closed.set()

    api = FastAPI()

    @api.middleware("http")  # as the real app (guard): the body passes through the middleware's stream
    async def passthrough(request, call_next):  # type: ignore[no-untyped-def]
        return await call_next(request)

    @api.get("/big")
    def big():  # type: ignore[no-untyped-def]
        return web_app._TimedStream(chunks(), done=done.set, media_type="application/octet-stream")

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    server = uvicorn.Server(uvicorn.Config(api, log_level="error"))
    th = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    th.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    c = socket.socket()
    c.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    c.connect(sock.getsockname())
    c.sendall(b"GET /big HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
    assert c.recv(4096).startswith(b"HTTP/1.1 200")  # one chunk read, then the client stalls
    try:
        assert closed.wait(30) and done.wait(5), "the stalled send was not given up"
    finally:
        c.close()
        server.should_exit = True
        th.join(10)


def test_an_aborted_download_is_cleaned_up_at_once_where_open_files_cannot_be_deleted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Windows keeps an open file's folder: the response closes the chunks (file and folder) when it ends, also when
    the client goes away before reading; nothing waits for the garbage collector. Real server, POSIX run as if NT."""
    import gc
    import os
    import socket
    import threading
    import time

    import uvicorn
    from fastapi import FastAPI

    from suriharvest.web import app as web_app

    gc.disable()  # the cleanup must not depend on a collection
    try:
        folders = []

        def make():  # type: ignore[no-untyped-def]
            tmp = tmp_path / f"suriharvest-web-{len(folders)}"
            tmp.mkdir()
            (tmp / "out.zip").write_bytes(os.urandom(1 << 22))
            folders.append(tmp)
            with monkeypatch.context() as m:
                m.setattr(web_app.os, "name", "nt")  # keep the folder while the file is open, as on Windows
                chunks = web_app._stream_then_remove(tmp / "out.zip", tmp)
            assert tmp.exists()
            return web_app._TimedStream(chunks, done=lambda: None, media_type="application/zip")

        api = FastAPI()
        api.get("/dl")(make)
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        server = uvicorn.Server(uvicorn.Config(api, log_level="error"))
        th = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
        th.start()
        for _ in range(100):
            if server.started:
                break
            time.sleep(0.05)
        try:
            for read in (16, 0):  # read a little then hang up; hang up before reading anything
                c = socket.socket()
                c.connect(sock.getsockname())
                c.sendall(b"GET /dl HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                if read:
                    c.recv(read)
                c.close()
                for _ in range(100):
                    if folders and not folders[-1].exists():
                        break
                    time.sleep(0.05)
                assert folders and not folders[-1].exists(), "the folder of an aborted download is still there"
        finally:
            server.should_exit = True
            th.join(10)
    finally:
        gc.enable()
