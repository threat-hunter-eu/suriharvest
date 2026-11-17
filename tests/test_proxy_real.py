"""Integration test through a REAL forward proxy (opt-in: `-m proxy`, needs network and a running proxy).

    SURIHARVEST_TEST_PROXY=http://127.0.0.1:8899           the proxy (e.g. `proxy --port 8899` from proxy.py)
    SURIHARVEST_TEST_PROXY_LOG=/path/to/proxy.log          optional: the proxy's access log (proxy.py --log-file),
                                                           to check the CONNECT went to the pinned address
    uv run pytest -m proxy tests/test_proxy_real.py

Checks: a small https source is synced through the proxy with the target address pinned (resolved once here, the
proxy is asked for the IP literal, TLS still verifies the real host name); a name that resolves to a private address
is refused before the proxy is contacted; a DNS answer that changes after the check (rebinding) is never used.
"""

from __future__ import annotations

import os
import re
import time
from pathlib import Path

import pytest

from suriharvest import sync
from suriharvest.config import SourceConfig, Workspace

PROXY = os.environ.get("SURIHARVEST_TEST_PROXY", "")
LOG = os.environ.get("SURIHARVEST_TEST_PROXY_LOG", "")
URL = "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/suricata.rules"
HOST = "raw.githubusercontent.com"

# a skipif mark (not a module-level skip): deselected runs (-m engine, the default) must not count a skipped test
pytestmark = [
    pytest.mark.network,
    pytest.mark.proxy,
    pytest.mark.skipif(not PROXY, reason="set SURIHARVEST_TEST_PROXY to a running forward proxy"),
]


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch):
    for k in ("NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy", "SURIHARVEST_TRUST_PROXY", "SURIHARVEST_ALLOW_PRIVATE_DOWNLOADS"):
        monkeypatch.delenv(k, raising=False)
    for k in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        monkeypatch.setenv(k, PROXY)


def _log_lines() -> list[str]:
    if not LOG:
        return []
    return Path(LOG).read_text(encoding="utf-8", errors="replace").splitlines()


def _connects_since(n: int) -> list[str]:
    time.sleep(0.5)  # the proxy writes its access log line when the tunnel closes
    return [m.group(1) for ln in _log_lines()[n:] if (m := re.search(r"CONNECT (\S+)", ln))]


def test_sync_a_small_https_source_through_the_proxy_with_pinning(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    real = sync._resolve
    calls: list[str] = []

    def resolve(host: str, port: int) -> list[str]:
        calls.append(host)
        return real(host, port)

    monkeypatch.setattr(sync, "_resolve", resolve)
    ws = Workspace(tmp_path / "ws")
    src = SourceConfig(name="echap-proxy-test", type="http-file", url=URL, licence="CC-BY-4.0")
    n = len(_log_lines())
    t0 = time.monotonic()
    res = sync.sync_http(src, ws, "8.0.0", None)
    took = time.monotonic() - t0
    files = list(res.root.rglob("*.rules"))
    assert files and b"alert " in files[0].read_bytes()
    assert calls == [HOST]  # resolved once, here
    if LOG:
        connects = _connects_since(n)
        assert connects and all(re.fullmatch(r"\[?[0-9a-f.:]+\]?:443", c) for c in connects), connects  # an IP, not the name
    print(f"\nsynced {files[0].stat().st_size} bytes through {PROXY} in {took:.2f} s")


def test_private_target_is_refused_before_the_proxy(monkeypatch: pytest.MonkeyPatch):
    n = len(_log_lines())
    with pytest.raises(sync.SyncError, match=r"private or internal|cannot resolve"):
        sync.download("https://localhost/r.rules")
    monkeypatch.setattr(sync, "_resolve", lambda host, port: ["10.1.2.3"])
    with pytest.raises(sync.SyncError, match="private or internal"):
        sync.download("https://inside.example.org/r.rules")
    if LOG:
        assert _connects_since(n) == []  # nothing reached the proxy


def test_rebinding_after_the_check_is_never_used(monkeypatch: pytest.MonkeyPatch):
    real = sync._resolve
    answers: list[list[str]] = []

    def rebinding(host: str, port: int) -> list[str]:
        out = real(host, port) if not answers else ["127.0.0.1"]  # first answer public, every later one internal
        answers.append(out)
        return out

    monkeypatch.setattr(sync, "_resolve", rebinding)
    n = len(_log_lines())
    data, _ = sync.download(URL)
    assert data and b"alert " in data
    assert len(answers) == 1  # one lookup: the pinned address is what the proxy is asked for
    if LOG:
        assert _connects_since(n) == [f"{answers[0][0]}:443"]
    # the other way round: the first (checked) answer is internal -> refused, whatever the proxy would resolve
    answers.clear()
    monkeypatch.setattr(sync, "_resolve", lambda host, port: answers.append(["127.0.0.1"]) or ["127.0.0.1"])
    with pytest.raises(sync.SyncError, match="private or internal"):
        sync.download(URL)
