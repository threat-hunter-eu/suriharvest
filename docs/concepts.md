# Concepts

This page is a short map of how suriharvest works: the pipeline, the workspace, the commands and the keys used to
find duplicates.

## Pipeline

`update` = sync (http with ETag/If-Modified-Since, git shallow clone + diff, local folders; size caps and safe
extraction) -> ingest (every rule version kept, unparsable lines quarantined) -> validate new rule texts with
`suricata -T` in each engine (cache keyed by content hash, engine and a config hash covering the version,
suricata.yaml, classification/reference/threshold files and overrides) -> index (logic groups, families, scores,
near-duplicates, full-text search) -> gates ([scheduling.md](scheduling.md)) -> report -> rebuild profiles.

## Workspace

| path | what |
|---|---|
| `sources.yaml` | sources ([sources.md](sources.md)) |
| `suriharvest.yaml` | `ruleset_version` for URLs (old name `suricata_version`), `remap_base`, engines used by `validate` (local binary or docker image) |
| `corpus/<source>/` | rule files of each source |
| `data/suriharvest.db` | SQLite (corpus, validation cache, index, verdicts, profiles, runs) |
| `exclusions/*.yaml` | exclusions per profile, editable by hand |
| `state/sid-map.tsv` | stable sid remapping ([sids.md](sids.md)) |
| `reports/runs/` | update run reports (`<stamp>.md` and `.json`) |

## Commands

| command | does |
|---|---|
| `init PATH [--preset/--tier T --catalog F --redistributable-only --engine NAME=IMAGE_OR_BINARY --refresh]`, `doctor` | create (or rewrite the settings of) a workspace; check it and create/upgrade the database |
| `sources list/add/import/enable/disable/check` | edit sources.yaml; `check` compares the catalog with the OISF index (exit 0/1/2) |
| `sync [names]`, `index`, `validate` | fetch + ingest, rebuild the index, load rules in each engine |
| `stats`, `search`, `show`, `deps`, `quarantine` | look at the corpus |
| `triage` | keep/review/drop on a logic, a rule key or a source (overlay, nothing deleted) |
| `export [--disabled comment\|omit\|enable / --include-disabled]` | suricata.rules + manifest.jsonl (+ by-source, suricata-update files, IOC datasets); rules disabled upstream (commented out by every publisher, or ET `DELETED`) are written commented out by default |
| `profile create/set/remove/list/exclude/unexclude/exclusions/import-conf/preview/suggest/new/build/builds/diff` | named rulesets ([profiles.md](profiles.md)) |
| `update [--no-validate --wait S --allow-failures --max-failed-sources PCT --report-file F]`, `runs list/show/accept` | unattended update with gates; history |
| `release build OUT --engine suricata-7 [--engine suricata-8] ...`, `site build OUT --release DIR` | flat, reproducible release files ([releases.md](releases.md)) and a static site ([site.md](site.md)) |
| `serve` | local web UI ([web.md](web.md)) |

## Dedup

| key | same key means |
|---|---|
| content_hash | identical rule text (the `#` of a disabled rule is not part of it) |
| rule_key | `namespace:gid:sid`: the same rule according to its publisher (docs/sids.md); newest rev wins |
| logic_hash | same header and detection options; metadata, action, threshold, fast_pattern ignored |
| semantic_hash | same detection written differently (legacy modifiers vs sticky buffers, buffer order, ...) |

Details in [identity.md](identity.md). Golden tests: `tests/test_identity.py`.

## Tests

<!-- doctest: skip the test suite itself -->
```bash
uv run pytest                 # offline
uv run pytest -m engine       # with a real Suricata binary
uv run pytest -m docs         # every <!-- doctest --> example in README.md and docs/ (needs suricata)
```

Every ```` ```bash ```` block in `README.md` and `docs/*.md` has a marker on the line above it: `<!-- doctest -->`
(run by `tests/test_docs.py` against an offline fixture workspace in which `~/suri` exists, with synthetic rules
under the catalog's source names; `sudo`, network tools and `suriharvest serve` are skipped) or
`<!-- doctest: skip REASON -->`. An unmarked block fails the plain test run.
