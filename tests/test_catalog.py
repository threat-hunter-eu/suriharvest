"""The bundled curated catalog: schema mapping, tiers, stale sources, per-major URLs, catalog check, licences."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import yaml

from suriharvest import catalog_check
from suriharvest.config import CATALOG, SourceConfig, catalog_sources, preset_sources


def test_bundled_catalog_parses_with_the_sources_schema():
    raw = yaml.safe_load(CATALOG.read_text())
    srcs = catalog_sources()
    assert len(srcs) == len(raw["sources"]) >= 30
    assert {s.tier for s in srcs} == {"core", "community", "experimental", "user-fetch"}
    # the measurement snapshot stays in the catalog; it is not a source field
    assert all(not hasattr(s, "measured") for s in srcs)
    assert all(s.paths for s in srcs)  # `paths: []` of http-file entries -> default glob
    names = [x["name"] for x in raw["excluded"]]
    assert "abuse.ch-urlhaus" in names and not {s.name for s in srcs} & set(names)


def test_core_preset_enables_exactly_the_curated_core():
    srcs = preset_sources("core", "7.0.3")
    on = {s.name for s in srcs if s.enabled}
    curated = {e["name"] for e in yaml.safe_load(CATALOG.read_text())["sources"] if e["tier"] == "core"}
    assert on == curated and "et-open" in on
    assert all(s.redistribute == "yes" for s in srcs if s.enabled)
    stale = next(s for s in srcs if s.name == "oisf-trafficid")
    assert stale.status == "stale" and stale.active  # still served: synced like active


def test_min_suricata_major_disables_too_new_sources():
    on = {s.name: s.enabled for s in preset_sources("community", "7.0.3")}
    assert on["ipfire-dbl"] is False  # min_suricata 8
    assert {s.name: s.enabled for s in preset_sources("community", "8.0.2")}["ipfire-dbl"] is True


def test_url_versions_pick_the_value_per_major():
    s = SourceConfig(
        name="e", type="http-tarball", url="https://x/suricata-${suricata_version}/r.tar.gz", url_versions={7: "7.0.3", 8: "8.0"}
    )
    assert s.resolved_url("7.0.17") == "https://x/suricata-7.0.3/r.tar.gz"
    assert s.resolved_url("8.0.8") == "https://x/suricata-8.0/r.tar.gz"
    assert s.resolved_url("9.1.0") == "https://x/suricata-9.1.0/r.tar.gz"


INDEX = {
    "version": 1,
    "sources": {
        "et/open": {"url": "https://rules.emergingthreats.net/open/suricata-%(__version__)s/emerging.rules.tar.gz", "license": "MIT"},
        "abuse.ch/urlhaus": {"url": "https://urlhaus.abuse.ch/downloads/urlhaus_suricata.tar.gz", "license": "CC0-1.0"},
        "abuse.ch/sslbl-c2": {"url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.tar.gz", "license": "CC0-1.0", "deprecated": True},
        "sslbl/ssl-fp-blacklist": {"url": "https://sslbl.abuse.ch/blacklist/sslblacklist_tls_cert.tar.gz", "deprecated": True},
        "abuse.ch/sslbl-blacklist": {"url": "https://sslbl.abuse.ch/blacklist/sslblacklist_tls_cert.tar.gz", "license": "CC0-1.0"},
    },
}


def test_catalog_check_matches_oisf_entries_by_url():
    full = {"version": 1, "sources": {n: {"url": u} for n, u in OISF_INDEX_URLS.items()} | INDEX["sources"]}
    res = catalog_check.check(index_text=yaml.safe_dump(full), do_health=False)
    assert res.candidates == [] and res.attention == []
    assert res.health["et-open"]["oisf"]["name"] == "et/open"
    assert res.health["abuse.ch-sslbl"]["oisf"]["name"] == "abuse.ch/sslbl-blacklist"  # the live alias, not the deprecated one
    assert "abuse.ch/sslbl-c2" in res.excluded


# The OISF suricata-update index entries (https://www.openinfosecfoundation.org/rules/index.yaml, read 2026-11-14) that
# the catalog carries: oisf_name -> index URL. Renamed aliases (sslbl/ssl-fp-blacklist, sslbl/ja3-fingerprints) are
# not used: suricata-update lists the live names.
OISF_INDEX_URLS = {
    "et/open": "https://rules.emergingthreats.net/open/suricata-%(__version__)s/emerging.rules.tar.gz",
    "oisf/trafficid": "https://openinfosecfoundation.org/rules/trafficid/trafficid.rules",
    "abuse.ch/sslbl-blacklist": "https://sslbl.abuse.ch/blacklist/sslblacklist_tls_cert.tar.gz",
    "abuse.ch/sslbl-ja3": "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.tar.gz",
    "abuse.ch/feodotracker": "https://feodotracker.abuse.ch/downloads/feodotracker.tar.gz",
    "etnetera/aggressive": "https://security.etnetera.cz/feeds/etn_aggressive.rules",
    "tgreen/hunting": "https://github.com/travisbgreen/hunting-rules/raw/master/hunting.rules.tar.gz",
    "stamus/lateral": "https://ti.stamus-networks.io/open/stamus-lateral-rules.tar.gz",
    "pawpatrules": "https://rules.pawpatrules.fr/suricata/paw-patrules.tar.gz",
    "ptrules/open": "https://ptrules.com/files/ptopen.rules.tar.gz",
    "aleksibovellan/nmap": "https://raw.githubusercontent.com/aleksibovellan/opnsense-suricata-nmaps/main/local.rules",
    "ipfire/dbl": "https://dbl.ipfire.org/lists/suricata.tar.gz",
    "julioliraup/antiphishing": "https://raw.githubusercontent.com/julioliraup/Antiphishing/refs/heads/main/antiphishing.tar.gz",
    "the-hunters-ledger/open": "https://the-hunters-ledger.com/feeds/suricata/hunters-ledger.rules",
    "echap/stalkerware": "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/generated/suricata.rules",
}


def test_every_catalog_source_in_the_oisf_index_has_its_oisf_name():
    """suricata-update export: a source with oisf_name is left to suricata-update (disable.conf carries exclusions)."""
    by_url = {u.replace("%(__version__)s", "${suricata_version}"): n for n, u in OISF_INDEX_URLS.items()}
    srcs = catalog_sources()
    for s in srcs:
        assert s.oisf_name == by_url.get(s.url), s.name  # set exactly when the URL is in the index
    assert {s.oisf_name for s in srcs if s.oisf_name} == set(OISF_INDEX_URLS)
    assert next(s for s in srcs if s.name == "et-open").oisf_name == "et/open"
    # the schema keeps it through init (sources.yaml)
    assert all(s.oisf_name for s in preset_sources("core", "7.0.3") if s.enabled)
    # and catalog_check finds the same names in a copy of the index
    index = {"version": 1, "sources": {n: {"url": u, "license": "x"} for n, u in OISF_INDEX_URLS.items()}}
    res = catalog_check.check(index_text=yaml.safe_dump(index), do_health=False)
    assert res.candidates == []
    assert {k: v["oisf"]["name"] for k, v in res.health.items() if v.get("oisf")} == {s.name: s.oisf_name for s in srcs if s.oisf_name}


def test_licence_fingerprints_flag_a_changed_text(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    texts = {"v": b"MIT License\n"}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/HEAD/LICENSE"):
            return httpx.Response(200, content=texts["v"])
        return httpx.Response(404)

    from suriharvest import sync

    def make_client(allow_private, headers, proxy=None, deadline=None):  # type: ignore[no-untyped-def]
        return httpx.Client(transport=httpx.MockTransport(handler), headers=headers, follow_redirects=False)

    monkeypatch.setattr(sync, "_make_client", make_client)
    cat = tmp_path / "cat.yaml"
    cat.write_text(yaml.safe_dump({"sources": [{"name": "r", "type": "git", "url": "https://github.com/org/repo.git"}]}))
    first = catalog_check.check(cat, index_text="sources: {}", do_health=False, licences=True)
    h = first.health["r"]
    assert h["licence_url"] == "https://raw.githubusercontent.com/org/repo/HEAD/LICENSE" and len(h["licence_sha256"]) == 64
    prev = yaml.safe_load(catalog_check.render_health(first))
    assert catalog_check.check(cat, index_text="sources: {}", do_health=False, licences=True, previous_health=prev).exit_code == 0
    texts["v"] = b"Some other licence\n"
    again = catalog_check.check(cat, index_text="sources: {}", do_health=False, licences=True, previous_health=prev)
    assert again.health["r"]["licence_changed"] is True and again.exit_code == 1


def test_catalog_check_uses_the_guarded_client(monkeypatch: pytest.MonkeyPatch):
    """Health and licence probes go through sync.download (no https->http, address guard, size cap)."""
    from suriharvest import sync

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/down":
            return httpx.Response(302, headers={"location": "http://plain.example.org/x"})
        if request.url.path == "/big":
            return httpx.Response(200, content=b"x" * (catalog_check.MAX_LICENCE_BYTES + 10))
        if request.url.path == "/gone":
            return httpx.Response(404)
        return httpx.Response(200, content=b"alert x\n")

    def make_client(allow_private, headers, proxy=None, deadline=None):  # type: ignore[no-untyped-def]
        return httpx.Client(transport=httpx.MockTransport(handler), headers=headers, follow_redirects=False)

    monkeypatch.setattr(sync, "_make_client", make_client)
    entry = {"type": "http-file", "url": "https://feeds.example.org/ok"}
    assert catalog_check.health(entry, "7.0.3") == "ok"
    assert catalog_check.health({**entry, "url": "https://feeds.example.org/gone"}, "7.0.3") == "HTTP 404"
    assert "https to http" in catalog_check.health({**entry, "url": "https://feeds.example.org/down"}, "7.0.3")
    assert catalog_check.licence_fingerprint({"licence_url": "https://feeds.example.org/big"}, [5]) == {}


def test_bundled_catalog_check_is_clean_against_the_recorded_oisf_index():
    text = (Path(__file__).parent / "fixtures" / "oisf-index.yaml").read_text()
    res = catalog_check.check(index_text=text, do_health=False)
    assert (res.candidates, res.attention, res.exit_code) == ([], [], 0)


def test_unconfirmed_publishers_are_not_republished():
    """Etnetera (no written licence) and PT Open (pending legal review) stay out of the published
    builds and site: fetched by the user (recipes), never enabled by the core preset."""
    by = {s.name: s for s in catalog_sources()}
    for name in ("etnetera-aggressive", "ptrules-open"):
        assert by[name].redistribute == "unknown" and by[name].tier == "user-fetch", name
    assert not {"etnetera-aggressive", "ptrules-open"} & {s.name for s in preset_sources("core", "7.0.3") if s.enabled}
