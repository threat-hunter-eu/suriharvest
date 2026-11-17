"""Web UI: pages render, guards hold, workflow, exclusions, diff and export work."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from suriharvest.config import Workspace
from suriharvest.web.app import create_app
from tests.test_pipeline import run, ws  # noqa: F401 - fixture

ORIGIN = {"origin": "http://testserver"}


@pytest.fixture
def client(ws: Path) -> TestClient:  # noqa: F811
    return TestClient(create_app(Workspace(ws), allowed_hosts={"testserver"}))


def wait_job(c: TestClient, resp) -> dict:  # type: ignore[no-untyped-def]
    import time

    assert resp.status_code == 303 and resp.headers["location"].startswith("/jobs/"), resp.text[:300]
    jid = resp.headers["location"].rsplit("/", 1)[1]
    for _ in range(300):
        j = c.get(f"/api/jobs/{jid}").json()
        if j["status"] != "running":
            return j
        time.sleep(0.1)
    raise AssertionError("job did not finish")


def token(c: TestClient) -> str:
    m = re.search(r'name="csrf-token" content="([^"]+)"', c.get("/").text)
    assert m
    return m.group(1)


def test_pages_render(client: TestClient):
    paths = [
        "/",
        "/search?q=gate.php",
        "/search?q=gate.php&view=table",
        "/sources",
        "/sources/et",
        "/builds",
        "/profiles",
        "/export",
        "/about",
        "/jobs",
        "/search?q=sid:",
        "/search?q=%22unclosed",
    ]
    for path in paths:
        r = client.get(path)
        assert r.status_code == 200, (path, r.text[:300])
        assert "Content-Security-Policy" in r.headers and "object-src 'none'" in r.headers["Content-Security-Policy"]
        assert "<script>" not in r.text and 'style="' not in r.text, path  # CSP: no inline script or style
    assert "local source" in client.get("/sources/et").text  # source URLs go through redact_url, local paths never show
    # the index is not empty: no onboarding
    assert "Welcome to suriharvest" not in client.get("/").text
    lh = re.search(r"/rule/([0-9a-f]{64})", client.get("/search?q=gate.php&all=1").text).group(1)
    page = client.get(f"/rule/{lh}").text
    assert "Where it comes from" in page and "In plain words" in page and 'class="k-act"' in page
    r = client.get("/rule/" + "0" * 64)
    assert r.status_code == 404 and "not in the index" in r.text


def test_search_table_view_and_layout_alias(client: TestClient):
    """view=table is the shared name (docs/conventions.md); layout=table, sigharvest's old name, works too."""
    for url in ("/search?q=gate.php&view=table", "/search?q=gate.php&layout=table"):
        assert '<table class="rows" id="results">' in client.get(url).text
    assert '<table class="rows" id="results">' not in client.get("/search?q=gate.php").text


def test_old_addresses_redirect(client: TestClient):
    for old, new in [("/workflow", "/"), ("/runs", "/builds#runs"), ("/help", "/about"), ("/doctor", "/jobs")]:
        r = client.get(old, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == new
    assert client.get("/workflow?dest=https://evil.example", follow_redirects=False).headers["location"] == "/"


def test_search_filters_and_facets(client: TestClient):
    page = client.get("/search?q=flowbits:ET.login&all=1").text
    assert "ET INFO set bit" in page and "ET INFO after login" in page and "needs a bit" not in page
    assert "Severity" in page and "Kind" in page  # facets
    page = client.get("/search?q=gate.php+metadata:nosuchkey=x").text
    assert "No rules match" in page and "alone matches" in page
    assert client.get("/search?q=severity:unrated&all=1").status_code == 200
    assert "could not be read" in client.get("/search?q=metadata:=x").text


def test_guards(client: TestClient):
    assert client.get("/", headers={"host": "evil.example"}).status_code == 421
    t = token(client)
    r = client.post("/jobs/update", data={"token": t}, headers={"origin": "http://evil.example"})
    assert r.status_code == 403
    r = client.post("/jobs/update", data={"token": "wrong"}, headers=ORIGIN)
    assert r.status_code == 403
    for gone in ["/playbooks", "/import", "/profiles/x/push"]:  # not in the web UI
        assert client.get(gone).status_code in (404, 405)


def test_token_auth(ws: Path):  # noqa: F811
    c = TestClient(create_app(Workspace(ws), token="s3cret-token-0123456789", allowed_hosts={"testserver"}))
    assert c.get("/").status_code == 401
    assert c.get("/", auth=("any", "s3cret-token-0123456789")).status_code == 200
    assert c.get("/", headers={"authorization": "Bearer s3cret-token-0123456789"}).status_code == 200


def test_profile_pages_and_flow(client: TestClient):
    run("profile", "create", "default", "--query", "source:et")
    t = token(client)
    r = client.post(
        "/profiles/default/exclusions",
        data={"kind": "category", "value": "ET INFO", "reason": "noise", "token": t},
        headers=ORIGIN,
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert "noise" in client.get("/profiles/default/exclusions").text
    assert client.get("/profiles/default", follow_redirects=False).headers["location"] == "/profiles/default/exclusions"
    job = wait_job(client, client.post("/profiles/default/build", data={"token": t}, headers=ORIGIN, follow_redirects=False))
    assert job["status"] == "done", job["lines"]
    page = client.get("/profiles").text
    build_id = re.search(r"/profiles/default/builds/(\d+)/suricata.rules", page).group(1)
    rules = client.get(f"/profiles/default/builds/{build_id}/suricata.rules").text
    assert "ET INFO" not in rules and "Foo CnC" in rules
    assert client.get(f"/profiles/default/builds/{build_id}/../../etc/passwd").status_code == 404
    assert client.get("/profiles/default/new").status_code == 200
    assert client.get("/profiles/default/diff").status_code == 404  # one build: nothing to compare yet
    job = wait_job(client, client.post("/profiles/default/build", data={"token": t}, headers=ORIGIN, follow_redirects=False))
    assert job["status"] == "done"
    assert "Added (0)" in client.get("/profiles/default/diff").text
    assert "New to review" in client.get("/builds?profile=default&tab=review").text
    lh = re.search(r"/rule/([0-9a-f]{64})", client.get("/search?q=gate.php&all=1").text).group(1)
    assert "Exclude from default" in client.get(f"/rule/{lh}").text
    # export: the build, a search, picked rules, the suricata-update feed
    assert "Download suricata.rules" in client.get("/export").text
    assert "Foo CnC" in client.get("/export/download?profile=default").text
    assert "gate.php" in client.get("/export/download?q=gate.php").text
    one = client.get(f"/export/download?h={lh}")
    assert one.status_code == 200 and "attachment" in one.headers["content-disposition"]
    r = client.post("/export/download", data={"h": [lh], "token": t}, headers=ORIGIN)
    assert r.status_code == 200 and "gate.php" in r.text
    assert client.post("/export/download", data={"h": [lh], "token": "bad"}, headers=ORIGIN).status_code == 403
    import io
    import tarfile

    feed = client.get("/feed/default/all.tar.gz")
    assert feed.status_code == 200
    with tarfile.open(fileobj=io.BytesIO(feed.content)) as tf:
        names = tf.getnames()
    assert "rules/suricata.rules" in names and "NOTICE.md" in names
    assert client.get("/feed/default/nope.tar.gz").status_code == 404
    assert client.get("/feed/nosuch/all.tar.gz").status_code == 404


def test_workflow_update(client: TestClient, ws: Path):  # noqa: F811
    from tests.test_pipeline import run

    run("profile", "create", "default", "--query", "source:et")
    t = token(client)
    page = client.get("/").text
    assert "Download new rules" in page and "default" in page and "Upload" not in page
    job = wait_job(client, client.post("/jobs/update", data={"token": t}, headers=ORIGIN, follow_redirects=False))
    assert job["status"] == "done", job["lines"]
    text = "\n".join(job["lines"])
    assert "ok et:" in text and "build default #1" in text
    assert client.get(f"/jobs/{job['id']}").status_code == 200
    page = client.get("/export").text
    assert "Download suricata.rules" in page
    # exclusion file on disk follows web changes
    client.post(
        "/profiles/default/exclusions", data={"kind": "category", "value": "ET INFO", "reason": "noise", "token": t}, headers=ORIGIN
    )
    assert "ET INFO" in (ws / "exclusions" / "default.yaml").read_text()


def test_exclusions_page_by_name_and_search(client: TestClient, ws: Path):  # noqa: F811
    from tests.test_pipeline import run

    run("profile", "create", "default", "--query", "source:et")
    t = token(client)
    assert "Add by name" in client.get("/profiles/default/exclusions").text
    r = client.post(
        "/profiles/default/exclusions/by-name",
        data={"value": "Foo CnC", "reason": "noise", "token": t},
        headers=ORIGIN,
        follow_redirects=False,
    )
    assert r.status_code == 303 and "matches+1+rules" in r.headers["location"]
    page = client.get("/profiles/default/exclusions?q=ET%20INFO").text
    assert "2 rule(s) match" in page
    keys = re.findall(r'name="keys" value="([^"]+)"', page)
    assert len(keys) == 2
    r = client.post(
        "/profiles/default/exclusions/selected",
        data={"keys": keys[:1], "q": "ET INFO", "reason": "picked", "token": t},
        headers=ORIGIN,
        follow_redirects=False,
    )
    assert r.status_code == 303
    page = client.get("/profiles/default/exclusions?q=ET%20INFO").text
    assert page.count('name="keys"') == 1 and "excluded</span>" in page
    r = client.post(
        "/profiles/default/exclusions/selected", data={"q": "gate.php", "whole": "1", "token": t}, headers=ORIGIN, follow_redirects=False
    )
    assert "future+ones+too" in r.headers["location"]
    import yaml

    data = yaml.safe_load((ws / "exclusions" / "default.yaml").read_text())
    assert data["rule_exclusions"][0]["msg"] == "Foo CnC" and {e["kind"] for e in data["exclusions"]} == {"rule_key", "query"}
    job = wait_job(client, client.post("/profiles/default/build", data={"token": t}, headers=ORIGIN, follow_redirects=False))
    assert job["status"] == "done"
    # by-source export
    page = client.get("/profiles").text
    build_id = re.search(r"/profiles/default/builds/(\d+)/", page).group(1)
    r = client.get(f"/profiles/default/export/{build_id}", follow_redirects=False)
    assert r.status_code == 303 and "format=by-source" in r.headers["location"]
    assert "Pick sources" in client.get(r.headers["location"]).text
    one = client.get(f"/profiles/default/export/{build_id}/download?sources=et&fmt=rules").text
    assert "sid:2000003" in one and "Foo CnC" not in one
    z = client.get(f"/profiles/default/export/{build_id}/download?sources=et&fmt=zip")
    assert z.headers["content-type"] == "application/zip"
    assert client.get(f"/profiles/default/export/{build_id}/download?sources=../../x").status_code == 400


def test_dialect_facets(client: TestClient):
    page = client.get("/search?q=dialect:suricata&all=1").text
    assert "Suricata only" in page and 'aria-current="true"' in page
    assert "Suricata / both / Snort" in client.get("/sources").text


def test_download_one_source(client: TestClient, ws: Path):  # noqa: F811
    t = token(client)
    assert "Download only this" in client.get("/sources").text
    job = wait_job(client, client.post("/jobs/source/et", data={"token": t}, headers=ORIGIN, follow_redirects=False))
    assert job["status"] == "done", job["lines"]
    text = "\n".join(job["lines"])
    assert "ok et:" in text and "et downloaded" in text and "repoA" not in text  # only that source
    assert client.post("/jobs/source/nope", data={"token": t}, headers=ORIGIN).status_code == 404


def test_hostile_inputs_do_not_500(ws: Path, client: TestClient):  # noqa: F811
    assert client.get("/search", params={"q": "x", "page": "99999999999999999999"}).status_code in (200, 400)
    assert client.get("/search", params={"q": "x", "page": "999999999999"}).status_code == 200
    r = client.post("/jobs/update", content=b"token=x", headers={**ORIGIN, "content-length": "abc"})
    assert r.status_code in (400, 413)
    assert "--allow-host" in client.get("/", headers={"host": "lan.example"}).text
    c = TestClient(create_app(Workspace(ws), token="s3cret-token-0123456789", allowed_hosts={"testserver"}))
    import base64

    bad = base64.b64encode("any:pässwörd".encode()).decode()
    assert c.get("/", headers={"authorization": f"Basic {bad}"}).status_code == 401


def test_reserved_profile_names(ws: Path):  # noqa: F811
    from typer.testing import CliRunner

    from suriharvest.cli import app

    for name in ("all", "all-profiles"):
        assert CliRunner().invoke(app, ["profile", "create", name]).exit_code != 0


def test_sources_add_refuses_what_sync_would_refuse(ws: Path):  # noqa: F811
    from typer.testing import CliRunner

    from suriharvest.cli import app

    r = CliRunner()
    assert r.invoke(app, ["sources", "add", "bad", "--type", "git", "--", "-oops"]).exit_code == 2
    assert r.invoke(app, ["sources", "add", "bad2", "ftp://x/y.rules", "--type", "http-file"]).exit_code == 2
    assert r.invoke(app, ["sources", "add", "ok", "https://example.org/r.rules", "--type", "http-file"]).exit_code == 0
    assert r.invoke(app, ["--version"]).output.startswith("suriharvest ")


def test_json_api_search_and_stats(client: TestClient):
    r = client.get("/api/search?q=gate.php&all=1")
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/json")
    d = r.json()
    assert d["total"] >= 1 and d["offset"] == 0 and d["limit"] == 50 and set(d) >= {"query", "total", "offset", "limit", "results"}
    assert {"logic_hash", "rule_key", "sid", "msg", "sources"} <= set(d["results"][0])
    # pagination: one per page walks every hit exactly once
    everything = client.get("/api/search?all=1&limit=200").json()
    seen = []
    for o in range(min(everything["total"], 5)):
        seen += [x["logic_hash"] for x in client.get(f"/api/search?all=1&limit=1&offset={o}").json()["results"]]
    assert seen == [x["logic_hash"] for x in everything["results"][: len(seen)]]
    # the old page/per_page parameters still work
    assert client.get("/api/search?all=1&per_page=1&page=2").json()["results"] == everything["results"][1:2]
    bad = client.get("/api/search?q=metadata:=x")
    assert bad.status_code == 400 and list(bad.json()) == ["detail"] and isinstance(bad.json()["detail"], str)
    # the same {"detail": "..."} shape as sigharvest for every /api/ error, out-of-range parameters included
    for url in ("/api/search?per_page=1000", "/api/search?page=0"):
        r = client.get(url)
        assert r.status_code == 400 and r.json()["detail"].startswith("Invalid request: "), r.json()
    assert client.get("/api/search?limit=0").json() == {"detail": "Invalid request: limit must be greater than or equal to 1."}
    nope = client.get("/api/nope")
    assert nope.status_code == 404 and list(nope.json()) == ["detail"]
    # a pasted blob or a huge number is a 400, never a 500 or a slow request
    assert client.get("/api/search?q=" + "a" * 5000).status_code == 400
    assert client.get("/api/search?q=" + "+".join(["w"] * 40)).status_code == 400
    for q in ("sid:99999999999999999999999", "sid:4294967296", "sid:%C2%B2"):
        r = client.get(f"/api/search?q={q}")
        assert r.status_code == 400 and "sid" in r.json()["detail"], q
    assert client.get("/api/search?q=score>=99999999999999999999").status_code == 200
    assert client.get("/search?q=sid:99999999999999999999999").status_code == 200  # the page shows the error
    assert client.get("/search?q=" + "a" * 5000).status_code == 200
    s = client.get("/api/stats").json()
    assert {"versions_total", "occurrences_present", "validation", "indexed_at", "version"} <= set(s)
    # read-only: no write verbs
    assert client.post("/api/search", headers=ORIGIN).status_code == 405


def test_unknown_filters_and_values_are_reported(client: TestClient, ws: Path):  # noqa: F811
    """An unknown filter key or engine is refused (CLI error, API 400, web notice) instead
    of returning 0 results; a filter value no rule has gets a hint with the closest values."""
    from typer.testing import CliRunner

    from suriharvest.cli import app

    r = CliRunner().invoke(app, ["search", "protocol:http cobalt"])
    assert r.exit_code == 2 and "unknown filter protocol:" in r.output and "proto:" in r.output
    r = CliRunner().invoke(app, ["search", "loads:9"])
    assert r.exit_code == 2 and "no such engine" in r.output
    r = CliRunner().invoke(app, ["search", "app:htp", "--json"])
    assert r.exit_code == 0 and "no rule has app:htp (closest: http" in r.output
    assert client.get("/api/search", params={"q": "protocol:http"}).status_code == 400
    body = client.get("/api/search", params={"q": "app:htp"}).json()
    assert body["total"] == 0 and body["warnings"][0].startswith("no rule has app:htp")
    page = client.get("/search", params={"q": "app:htp"}).text
    assert "no rule has app:htp" in page
    assert "unknown filter" in client.get("/search", params={"q": "foo:bar("}).text
    assert client.get("/api/search", params={"q": "http://example.org/x"}).status_code == 200  # a URL is a word


def test_show_with_a_source_name_as_namespace_names_the_real_key(ws: Path):  # noqa: F811
    """`show et-open:1:...` names the rule key that exists (`et:1:...`)."""
    from typer.testing import CliRunner

    from suriharvest.cli import app

    r = CliRunner().invoke(app, ["show", "et-open:1:2000003"])
    assert r.exit_code == 1 and "et:1:2000003" in r.output and "sid namespace" in r.output


@pytest.mark.parametrize(
    "path",
    ["/runs/99999999999999999999", "/profiles/default/export/99999999999999999999/download"],
)
def test_an_id_beyond_sqlite_integers_is_a_404_not_a_500(client: TestClient, path: str):
    """Found crawling with hostile URLs: SQLite's OverflowError on a 20-digit id reached the user as a 500."""
    from tests.test_pipeline import run

    run("profile", "create", "default", "--query", "source:et")
    r = client.get(path)
    assert r.status_code == 404 and "out of range" in r.text, (r.status_code, r.text[:200])


def test_back_redirect_never_leaves_the_site(client: TestClient):
    """A same-host Referer whose path starts with // (or /\\) must not become a protocol-relative redirect."""
    run("profile", "create", "default", "--query", "source:et")
    t = token(client)
    for path in ("//evil.example/x", "/\\evil.example/x"):
        r = client.post(
            "/profiles/default/exclusions",
            data={"kind": "category", "value": "ET INFO", "reason": "noise", "token": t},
            headers={**ORIGIN, "referer": f"http://testserver{path}"},
            follow_redirects=False,
        )
        assert r.status_code == 303 and r.headers["location"] == "/profiles/default/exclusions", r.headers.get("location")


def test_source_homepage_link_is_http_only(ws: Path):  # noqa: F811
    import yaml

    cfg = yaml.safe_load((ws / "sources.yaml").read_text())
    cfg["sources"][0]["homepage"] = "javascript:alert(document.domain)"
    cfg["sources"][1]["homepage"] = "https://example.org/repoA"
    (ws / "sources.yaml").write_text(yaml.safe_dump(cfg))
    c = TestClient(create_app(Workspace(ws), allowed_hosts={"testserver"}))
    page = c.get("/sources/et").text
    assert "javascript:alert" in page and 'href="javascript:' not in page
    assert 'href="https://example.org/repoA"' in c.get("/sources/repoA").text
