# Web UI

<!-- doctest: skip long-running server -->
```bash
suriharvest serve                    # http://127.0.0.1:8077/ ; Ctrl+C stops it
suriharvest serve --port 8078        # another port
```

The same workspace as the CLI (current folder or `SURIHARVEST_HOME`). A workspace that was never updated opens on
a welcome page with a **Download new rules** button.

- [Pages](#pages)
- [Search syntax](#search-syntax)
- [suricata-update feed](#suricata-update-feed)
- [Exclusions file](#exclusions-file)
- [JSON API](#json-api)
- [Security](#security)

## Pages

The menu on the left, top to bottom:

| Page | Address | What you do there |
|---|---|---|
| **Overview** | `/` | Totals, the **Suricata check** (how many rules load on each engine), **Recent changes** of the last update, rules **By protocol**, **Your rulesets** (each profile's last build, **Build now**, "Copy suricata-update URL"), **Top sources**, **Common starting points** (one-click searches such as "Rules for a CVE" = `cve:*`, `remapped:yes`) and **Licences in your index**. **Download new rules** starts `suriharvest update` as a background job. |
| **Search** | `/search?q=...` | Every rule in the index, one row per family by default, with facets (protocol, source, classtype, severity, engine, licence ...) that add filters to the query. Tick rules to export them or to exclude them from a profile ("Exclude from default..."). The search box at the top of every page leads here. |
| rule pages | `/rule/<logic hash>` | Opened from a result. The rule in plain language, its text, **Dependencies** (flowbits it sets or needs, and who sets them), **Revision history**, **Related rules** (family, same logic elsewhere), **Suricata check** per engine with the engine's error, **In your rulesets** (in which profile builds it is, and an "Exclude from ..." form), **Where it comes from** (sources, files, licence, sid owner) and **Details** (score parts, metadata). |
| **Sources** | `/sources`, `/sources/<name>` | Every source with licence, redistribution, tier, status, last download and rule counts. A source page has its Suricata check, **Quarantine** (lines that could not be parsed), **Download log**, **Settings** and **Overlap with other sources**; **Download only this** syncs that one source. |
| **Builds & changes** | `/builds` | Per profile: the latest build compared with the one before (added, removed, changed rev / exported sid / source), the rules that would be new since the last build, **Build now**, and **Update runs** (each run's report, at `/runs/<id>`). |
| **Profiles & exclusions** | `/profiles`, `/profiles/<name>/exclusions` | One card per profile (query, engine, options, last build, **Rebuild now**) and the CLI command to create another. A profile's exclusions page: **Add by name** (message, category, sid, regex), **Search and select** (exclude a whole search or ticked rules), and **Current exclusions** with how many rules each matches, its reason and review date. |
| **Export** | `/export` | Download a profile's latest build, a search or ticked rules: `suricata.rules`, one file per source (zip), rules + datasets (zip), or the **suricata-update** feed. Options: engine (leave out rules that fail there), fix sid clashes, only rules you may share. Shows the licence mix of the download, the matching `suriharvest export` command and, for a profile, the `suricata-update add-source` command. |
| **About & licences** | `/about` | What suriharvest does, how licences and sids are handled, the search syntax, the CLI equivalents, and this installation (workspace, engines, remap base). |
| **Jobs & health** | `/jobs` | Background jobs started from the UI (update, one source, build) with their log, and **Health**: schema, failing sources, quarantine. |

Old addresses redirect: `/workflow` to `/`, `/runs` to `/builds`, `/help` to `/about`, `/doctor` to `/jobs`.

Keyboard (press `?` for the list): `/` search, `g` then `o` / `s` / `b` / `p` / `e` go to Overview, Sources,
Builds, Profiles, Export; `j` / `k` move through results, `Enter` opens, `x` ticks, `e` exports the ticked rules,
`y` copies, `t` switches the theme, `Esc` closes.

## Search syntax

The web search takes the CLI's query syntax ([cli.md](cli.md#filter-syntax): words, `app:`, `source:`, `ioc:`,
`loads:`, `mitre:`, `updated>`, ...); the CLI, the web and `GET /api/search` share one parser, so a query gives
the same rules everywhere. The filters most used from the web:

| Filter | Example | Meaning |
|---|---|---|
| `cve:` | `cve:CVE-2021-44228`, `cve:2024-3400`, `cve:*` | the rule names this CVE in its message, `reference:cve,...` or `metadata: cve ...`; a bare `CVE-2021-44228` is the same filter; `cve:*` (or `any`) any CVE |
| `licence:` / `license:` | `licence:permissive`, `licence:copyleft` | licence class of the rule: `permissive`, `copyleft`, `restricted` (own use only; also `nc`, `own`), `none` (unknown). ET Open counts per rule: BSD rules permissive, `GPL ...` rules copyleft |
| `remapped:` | `remapped:yes`, `remapped:no` | the sid was (not) remapped after a sid clash |
| `metadata:` / `meta:` | `metadata:malware_family=Lumma_Stealer`, `metadata:deprecation_reason` | a metadata key=value (exact, case-insensitive), or just the key |
| `flowbits:` / `flowbit:` | `flowbits:ET.cve.2024.6235` | sets or checks this flowbit (or xbit) |
| `severity:` | `severity:critical,major`, `severity:none` | one or several `signature_severity` values; `none` = no severity |
| `loads:` / `fails:` | `loads:8`, `fails:suricata-7` | also the short engine name, not only the name in `suriharvest.yaml` |

`CVE-2021-44228`, `cve:CVE-2021-44228` and `cve:2021-44228` give the same answer. Spelling variants are one
search too (`cobaltstrike` = `cobalt strike`). Counts are one rule per family (the same detection written several
ways) unless you tick **Show every variant**, like the CLI without `--per-logic`.
The buttons next to the sort switch between cards and a compact table (`view=table` in the address, the same
name as in sigharvest; `layout=table` is accepted too).

## suricata-update feed

`suriharvest serve` serves every profile's latest build as a suricata-update source:

```
http://127.0.0.1:8077/feed/<profile>/<engine>.tar.gz
```

- `<engine>`: an engine name from `suriharvest.yaml` (`local` after a plain `init`), `suricata-<major>` (`suricata-8`)
  or the major alone; `all` keeps rules even if they fail on an engine. Rules that fail on the chosen engine are
  left out.
- The archive holds `rules/suricata.rules`, the dataset files its rules load (`rules/datasets/...`) and `NOTICE.md`
  (sources and licences). The Export page and the Overview's "Copy suricata-update URL" show the exact URL.

On the same host:

<!-- doctest: skip needs a running suriharvest serve and root -->
```bash
sudo suricata-update add-source suriharvest-default http://127.0.0.1:8077/feed/default/local.tar.gz
sudo suricata-update disable-source et/open      # the feed already contains ET Open
sudo suricata-update
```

For sensors on other hosts, bind to an address they can reach with a token (see [Security](#security)) and pass
the token as a header: `suricata-update add-source --http-header "Authorization: Bearer $TOKEN" NAME URL`. Put
TLS in front. Without a web server, publish files instead: `suriharvest release build` writes an `index.yaml`
and tarballs ([releases.md](releases.md)), or see [export.md](export.md#feeding-suricata-update).

## Exclusions file

Exclusions live in the database and in `exclusions/<profile>.yaml` (`exclusions/all-profiles.yaml` for every
profile): `rule_exclusions: - msg:` (name substrings) and `exclusions:` (other kinds). A change in the web UI
rewrites the file; a hand edit of the file is applied at the next read, build or update. A broken file is
reported and left alone.

## JSON API

Read-only, same host/token rules as the pages (see Security); GET only.

| Endpoint | Parameters | Returns |
|---|---|---|
| `GET /api/search` | `q` (the web query syntax above), `offset` (from 0), `limit` (1-200, default 50), `all=1` (every logic, not one per family), `junk=1`; `page`/`per_page` are still read when `offset`/`limit` are absent | `{"query", "total", "offset", "limit", "results": [...]}` (the shape of `suriharvest search --json`, docs/conventions.md); each rule has the fields of `suriharvest search --json` (`logic_hash`, `rule_key`, `sid`, `rev`, `msg`, `score`, `sources`, `flags`, `loads_in`, `fails_in`, `verdict`, ...). Ordered by score, then id, so pages are stable between index runs |
| `GET /api/stats` | none | the corpus funnel of `suriharvest stats --json` plus `version` |
| `GET /api/jobs/{id}` | none | state and log of a background job started from the UI |
| `GET /feed/{profile}/{engine}.tar.gz` | none | the suricata-update feed above |

Errors are JSON `{"detail": "..."}` with the HTTP status, as in sigharvest: a query that cannot be read or an
out-of-range `offset`/`limit` gives `400`, an unknown `/api/` path `404`.

With `suriharvest serve` running:

<!-- doctest -->
```bash
curl -sf 'http://127.0.0.1:8077/api/search?q=cobalt+app:http&limit=100&offset=0' | jq '.results[].rule_key'
curl -sf 'http://127.0.0.1:8077/api/search?q=cve:CVE-2021-44228&all=1' | jq .total
curl -sf 'http://127.0.0.1:8077/api/stats' | jq '{version, logic_groups, families}'
curl -sf -o default-feed.tar.gz 'http://127.0.0.1:8077/feed/default/local.tar.gz' && tar -tzf default-feed.tar.gz
```

## Performance

- Requests read the database two at a time (`SURIHARVEST_WEB_READERS`, 1 to 64, default 2); the others wait (a
  503 after 20 s). Each row SQLite hands back passes Python's GIL between the request threads, so many requests
  reading at once in one process get less done in total than a few: on a 85,000-rule core workspace, 10 clients
  of the load mix went from 11.7 to 36.8 requests/s. Background jobs (update, build, source download) do not count.
- The totals and facets of a search are kept per query (256 queries) until the index, a verdict, a source's
  licence, the engines or the sid map change, so changing page or sort order reuses them. The one-line rule
  summaries are kept per rule version.
- List filters (`buffer:`, `source:`, `flag:`, `dialect:`, `loads:`, `fails:`, `mitre:`) and the list facets read
  the `logic_group_values` table (docs/architecture.md#database-schema) instead of parsing each rule's JSON.

## Security

- Binds 127.0.0.1 and accepts only local Host headers (DNS rebinding). `--allow-host NAME` adds a name, e.g. for
  a reverse proxy.
- Binding to another address requires `--token-env VAR`: the environment variable holds a token (16+ characters)
  sent as the HTTP Basic password (any user name) or as `Authorization: Bearer`. Put TLS in front.
- With `--host 0.0.0.0` (every interface) no Host name is known in advance: list the names or addresses clients
  use, e.g. `suriharvest serve --host 0.0.0.0 --token-env SURIHARVEST_WEB_TOKEN --allow-host 192.0.2.10
  --allow-host suri.example.org`. Other Host headers get 421 with a message naming the missing `--allow-host`.
- Every POST must come from the same origin and carry the per-process CSRF token; bodies are capped at 1 MB and
  must announce their size with `Content-Length` (a chunked body gets 411).
- Downloads, feeds and the JSON API (`/export...`, `/feed/...`, `/api/...`) refuse a request a browser marks as
  coming from another site (`Sec-Fetch-Site`, `Origin`), so a page elsewhere cannot start exports on your server;
  clients that send neither header (suricata-update, curl) are served.
- Ruleset downloads built on request run one at a time with two more waiting; beyond that the server answers 429
  with `Retry-After`. Each one is built by a short-lived child process on disk and streamed from there, so the
  server's memory stays flat and other pages stay fast while it runs.
  Finished downloads are sent four at a time (more get 429), and a client that does not accept the next chunk
  within 60 s is disconnected, which closes its temp file. At start the server removes its own download folders
  older than an hour from the temp folder; it never follows a link there and leaves other users' folders alone.
- `Content-Security-Policy: default-src 'self'` with no inline scripts or styles; rule text is always escaped.
- Writes take the workspace lock for a moment; during `suriharvest update` they answer 503.
- The server refuses to start on a database whose schema is behind the code (`suriharvest doctor`).
