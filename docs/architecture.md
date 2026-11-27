# Architecture

A short map for contributors. suriharvest is one Python package with its own Suricata rule parser, a SQLite
database (SQLAlchemy + Alembic migrations), and a small FastAPI/Jinja web UI. Suricata itself is used only as a
validator (`suricata -T`).

## Pipeline

```
sources.yaml ─▶ sync ─▶ ingest ─▶ validate ─▶ index ─▶ profiles / export / release
              http, git   parse     suricata -T    identity, dedup,     exclusions, flowbits,
              (ETag)      rules     per engine     families, score      sid map, manifest
```

| Step | Module | What happens |
|---|---|---|
| sync | `sync.py` | Conditional HTTP GETs (ETag / Last-Modified), Git fetch, size caps, safe tar extraction into `corpus/` |
| majors | `majors.py` | One download per Suricata major for `${suricata_version}` URLs; per-engine views (validation, canonical text, build membership) |
| ingest | `ingest.py`, `parser.py` | Parse every rule (multi-line, `#`-disabled), record versions and occurrences; unparseable lines go to quarantine |
| validate | `validate.py` | Batches with unique gid:sid per engine; bisects on failure to find the bad rule; cache key = content hash + engine version + config hash |
| index | `index.py`, `identity.py`, `sidalloc.py` | Rule keys, logic groups, families, IOC detection, flowbit graph, scores, FTS |
| gates | `runs.py`, `pipeline.py` | Compare with the last passed run; stop on suspicious drops |
| profiles | `profiles.py` | Select, exclude, close flowbits, resolve collisions, write builds and diffs |
| export | `export.py`, `export_formats.py`, `sidmap.py` | Rules files, suricata-update files, datasets, stable sid map |
| web | `web/` | Read-mostly UI; only exclusions write |

## Identity and dedup

- **content_hash**: exact rule text (disabled marker stripped). Same text = same version.
- **rule key** `(namespace, gid, sid)`: namespace is the publisher. It comes from the sidallocation.org table
  (`sidalloc.py`) when the source matches the range owner, otherwise from the source's `sid_namespace` or name.
  `rev` is compared only inside a namespace.
- **logic_hash**: header + detection options in order; `msg`, `sid`, `rev`, `classtype`, `reference`,
  `metadata`, `priority` and the action are excluded; thresholds are hashed separately; `fast_pattern` /
  `prefilter` are ignored. Same logic under different sids is one rule in a build.
- **semantic normalisation**: legacy content modifiers vs sticky buffers, `uricontent` vs `http.uri`, etc., so
  equivalent rules written in old and new style group together.
- Near-duplicates (other ports, other pcre) are **never** merged.
- Flowbit/xbit setters are never deduplicated across publishers unless the whole bit graph is identical.

Details: `docs/identity.md`.

## sid collisions and the sid map

Two namespaces, one `gid:sid` = collision. The sidallocation.org owner of the range keeps it; otherwise the rule
that held it in an earlier build; otherwise the better `priority`. The others are remapped (profiles and releases)
or the export stops (plain `export` without `--remap-colliding-sids`). Every clash decision is recorded in
`state/sid-map.tsv` (`logic_hash, gid, original, sid, date, rule_key`; clash rows only), so a rule's exported sid
stays stable, also across new revisions. The nightly
workflow commits this file before publishing. Details: [sids.md](sids.md).

## Workspace layout

```
$SURIHARVEST_HOME/
  sources.yaml            sources to collect
  suriharvest.yaml        suricata_version, engines, remap_base
  corpus/                 downloaded and extracted source files (corpus/<source>/@<major>/: per-major copies)
  data/suriharvest.db     SQLite database
  data/cache/             HTTP and validation caches
  data/profiles/<name>/   builds
  reports/runs/           run reports (<stamp>.md and .json)
  state/sid-map.tsv       stable sid assignments
```

## Design rules

- **Never rewrite rule text silently.** The only changes are a remapped sid (recorded in `state/sid-map.tsv` and
  `collisions.json`, explained in `NOTICE.md`) and the publisher's enable state when a profile asks for it.
- **The engine is the judge.** A rule is "valid" for an engine only if that engine loaded it.
- **Untrusted input everywhere.** Downloads are size-capped, archives are extracted safely (no absolute paths, no
  `..`, no links outside), Suricata runs with `--network=none` in Docker and a minimal config, rule text is
  autoescaped in HTML.
- **Licence travels with the rule.** `redistribute` is checked on every path that publishes.
- **Last good wins.** Failed sources keep their last copy; failed gates publish nothing.
- **Migrations under the lock, by the commands that write.** `doctor`, `update` and `sync` upgrade the schema while
  they hold the workspace lock; read-only commands (and `serve`) refuse a database whose schema is behind.

## Database schema

Alembic migrations in `src/suriharvest/migrations/versions/`; `doctor`, `update` and `sync` apply them under the
workspace lock (`init` and `doctor` create the database), read-only commands refuse a database behind the code.

| Revision | Change |
|---|---|
| 0001 | baseline (0.1) |
| 0002 | `logic_group_values(group_id, kind, pos, value, lvalue)`: one row per element of the list columns of `logic_groups` (`buffers`, `sources`, `flags`, `loads_in`, `fails_in`, `mitre`), `lvalue` = SQLite `lower(value)`, index on `(kind, lvalue)`. Derived: `index` rebuilds it with `logic_groups`; the upgrade fills it from the existing `logic_groups`, so no reindex is needed |

Going back to an older version: the downgrade only drops derived data. With the newer version still installed,
`python -c "from pathlib import Path; from alembic import command; from suriharvest.db import alembic_config;
command.downgrade(alembic_config(Path('data/suriharvest.db')), '0001')"` in the workspace, then install the older
version (its search parses the JSON columns again). After an upgrade from that state, `doctor` refills the table;
`suriharvest index` rebuilds it from scratch at any time.

## Automation (GitHub Actions)

| Workflow | When | What |
|---|---|---|
| `ci.yml` | every push | ruff, actionlint, pytest (3.12), CLI contract, engine tests inside the pinned Suricata 7 container, privacy gate + gitleaks |
| `ci-full.yml`, `ci-docs.yml` | PR to main, daily (opt-in), manual | pytest (3.13, 3.15), Windows, engine tests on Suricata 8, wheel install + `init` in a clean venv, web UI at 390 px, offline acceptance harness, docs examples |
| `nightly.yml` | nightly | `update` with the redistributable core sources -> `release build` -> independent re-validation of the exact files in Suricata 7 and 8 containers -> commit sid map -> signed GitHub Release (only if content changed) |
| `catalog-health.yml` | weekly | checks every catalog URL and licence text, opens a PR touching only `health.yaml` |
| `pages.yml` | after a release | optional static site (`site build` not implemented yet: skipped with a warning) |

Scheduled workflows are opt-in (`SURIHARVEST_AUTOMATION_ENABLED=true`), so forks stay quiet. CI never downloads
sources that are not redistributable and needs no secrets.
