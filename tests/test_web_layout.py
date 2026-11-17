"""Every web page fits a 390 px wide phone screen: no sideways scrolling, light and dark theme.

Needs Playwright with Chromium (`uv sync --group ui && uv run --group ui playwright install chromium-headless-shell`);
skipped without it, unless SURIHARVEST_REQUIRE_PLAYWRIGHT=1 (the CI job), where a missing browser fails the test.
"""

from __future__ import annotations

import os
import re
import socket
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from suriharvest.config import Workspace
from tests.test_pipeline import run, ws  # noqa: F401 - fixture

REQUIRED = os.environ.get("SURIHARVEST_REQUIRE_PLAYWRIGHT") == "1"


def _sync_api():  # type: ignore[no-untyped-def]
    """Imported in the test, not at module level: a module-level skip is reported by every run that collects this
    file, also `-m engine`, whose CI job fails on any skip."""
    if REQUIRED:
        import playwright.sync_api as sync_api

        return sync_api
    return pytest.importorskip("playwright.sync_api")


WIDTH = 390


@pytest.fixture
def base_url(ws: Path) -> Iterator[str]:  # noqa: F811
    import uvicorn

    from suriharvest.web.app import create_app

    run("profile", "create", "default", "--query", "source:et")
    run("profile", "exclude", "default", "2000004", "--kind", "sid", "--reason", "a long reason that has to wrap on a phone screen")
    run("profile", "build", "default")
    run("update", "--no-validate")  # a run for /builds and /runs/ID
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(create_app(Workspace(ws)), host="127.0.0.1", port=port, log_level="warning"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    for _ in range(200):
        if server.started:
            break
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    t.join(10)


def _pages(base: str) -> list[str]:
    import httpx

    search = httpx.get(f"{base}/search?q=gate.php&all=1").text
    rule = re.search(r"/rule/[0-9a-f]{64}", search).group(0)
    paths = [
        "/",
        "/search?q=gate.php",
        "/search?q=gate.php&view=table",
        "/search?q=sid:",
        rule,
        "/sources",
        "/sources/et",
        "/builds",
        "/profiles",
        "/profiles/default/exclusions",
        "/profiles/default/new",
        "/profiles/default/diff",  # one build only: the "two builds are needed" page
        "/export",
        "/about",
        "/jobs",
        "/rule/" + "0" * 64,  # error page
    ]
    run_link = re.search(r'href="(/runs/[^"]+)"', httpx.get(f"{base}/builds").text)
    if run_link:
        paths.append(run_link.group(1))
    return paths


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_no_horizontal_scroll_at_390px(base_url: str, theme: str):
    sync_api = _sync_api()
    try:
        pw = sync_api.sync_playwright().start()
    except Exception as e:
        if REQUIRED:
            raise
        pytest.skip(f"playwright: {e}")
    try:
        try:
            browser = pw.chromium.launch()
        except Exception as e:
            if REQUIRED:
                raise
            pytest.skip(f"no Chromium for Playwright: {e}")
        ctx = browser.new_context(viewport={"width": WIDTH, "height": 844}, color_scheme=theme, device_scale_factor=1)
        ctx.add_init_script(f"try {{ localStorage.setItem('suriharvest-theme', '{theme}'); }} catch (e) {{}}")
        page = ctx.new_page()
        wide = []
        for path in _pages(base_url):
            page.goto(base_url + path)
            page.wait_for_load_state("networkidle")
            assert page.evaluate("document.documentElement.getAttribute('data-theme')") == theme, path
            sw, cw = page.evaluate("[document.documentElement.scrollWidth, document.documentElement.clientWidth]")
            if sw > cw:
                culprits = page.evaluate(
                    """(cw) => [...document.querySelectorAll('body *')]
                        .filter(e => e.getBoundingClientRect().right > cw + 1 && getComputedStyle(e).position !== 'fixed')
                        .filter(e => ![...e.children].some(c => c.getBoundingClientRect().right > cw + 1))
                        .slice(0, 5).map(e => e.tagName.toLowerCase() + (e.className ? '.' + String(e.className).split(' ').join('.') : '')
                                          + ' ' + Math.round(e.getBoundingClientRect().right) + 'px')""",
                    cw,
                )
                wide.append(f"{path}: scrollWidth {sw} > clientWidth {cw} ({', '.join(culprits)})")
        browser.close()
        assert not wide, "\n".join(wide)
    finally:
        pw.stop()


def test_keyboard_j_k_and_enter_open_a_result(base_url: str):
    """j / k move through the results and Enter opens the rule, with no JS error. A `var cur` added for the phone
    navigation shadowed the cursor: j threw "Cannot read properties of undefined (reading 'classList')"."""
    sync_api = _sync_api()
    try:
        pw = sync_api.sync_playwright().start()
    except Exception as e:
        if REQUIRED:
            raise
        pytest.skip(f"playwright: {e}")
    try:
        try:
            browser = pw.chromium.launch()
        except Exception as e:
            if REQUIRED:
                raise
            pytest.skip(f"no Chromium for Playwright: {e}")
        page = browser.new_page(viewport={"width": 1280, "height": 900})
        errors: list[str] = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        for view in ("", "&view=table"):
            page.goto(f"{base_url}/search?q=gate.php{view}")
            page.wait_for_load_state("networkidle")
            for key in ("j", "j", "k"):
                page.keyboard.press(key)
            assert page.locator("#results .is-focused, #results tr.cur").count() == 1, (view, errors)
            with page.expect_navigation():
                page.keyboard.press("Enter")
            assert "/rule/" in page.url and not errors, (view, page.url, errors)
        browser.close()
    finally:
        pw.stop()
