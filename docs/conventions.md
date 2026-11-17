# Conventions shared by sigharvest and suriharvest

sigharvest (Sigma) and suriharvest (Suricata) are sibling tools. This page lists what they keep identical, so that
someone who knows one can use the other. It is the same file in both repositories; change it in both or in neither.
Differences that follow from the rule format (presets, export formats, release files, domain pages) are listed at
the end.

## Command line

- One console script, `TOOL`, also runnable as `python -m TOOL`.
- Global options: `--version` (prints `TOOL X.Y.Z`), `-v/--verbose`, `--help`. `TOOL version` prints the tool version,
  the database schema revision and the main dependency versions.
- Shared verbs, same meaning: `init [PATH]`, `update`, `sync`, `index`, `search [QUERY]`, `show KEY`,
  `export [QUERY] --out PATH`, `stats`, `doctor`, `serve`, `sources list|add|remove|enable|disable`,
  `quarantine list|show`, `runs list|show|accept`, `release build`, `site build`.
- Shared options, same spelling: `--source/-s NAME` (repeatable), `--limit`, `--offset`, `--json`, `--include-junk`,
  `--allow-failures`, `--max-failed-sources PCT`, `--report-file PATH` (`.json` for JSON, otherwise Markdown),
  `--wait SECONDS`, `--redistributable-only/--include-private-sources`.
- Opt-in switches are plain flags (`--allow-failures`); a `--x/--no-x` pair is shown only when the default is on.
- Help text: sentences with a capital letter and a full stop; commands grouped as Start here, Rules, Sources,
  Publish, Admin; the first group shows an example.

## Output, errors and exit codes

- Results go to stdout, messages and errors to stderr. Errors start with `error: ` and say what to do next.
- `--json` prints one JSON document and nothing else. Lists use `{"total": N, "offset": N, "limit": N,
  "results": [...]}`; the web API returns the same objects. JSON is printed only when asked for.
- Exit codes:

  | Code | Meaning |
  |---|---|
  | 0 | OK |
  | 1 | The command ran but did not reach its goal: a source or a gate failed, doctor found a problem, nothing matched a key, an export selected nothing |
  | 2 | Bad option or argument, not a workspace, the workspace is busy, or an I/O error |

## Workspace

- Found from `TOOL_HOME`, else the current folder or the nearest parent with a `sources.yaml`.
- Layout: `sources.yaml`, `data/TOOL.db`, `data/TOOL.lock`, `data/cache/`, `reports/runs/<stamp>.md` and `.json`.
- Commands that write (`init`, `update`, `sync`) upgrade the database schema under the workspace lock; read-only
  commands refuse an old schema and say `run TOOL doctor`.
- Sources declare `licence` (SPDX) and `redistribute: yes|no|unknown`; nothing marked `no` or `unknown` goes into a
  file meant to be shared.

## Environment and repository variables

- Every variable starts with `SIGHARVEST_` or `SURIHARVEST_`: `TOOL_HOME`, `TOOL_ALLOWED_HOSTS`,
  `TOOL_PRIVACY_TERMS`, `TOOL_KEEP_RELEASES`.
- GitHub repository switches are named `TOOL_<FEATURE>_ENABLED` and are off unless set to `true`:
  `AUTOMATION_ENABLED` (master switch for scheduled jobs), `PAGES_ENABLED`, `SIGNING_ENABLED`, `PYPI_ENABLED`.

## Web UI

- `TOOL serve` binds 127.0.0.1. Default ports: sigharvest 8799, suriharvest 8077, so both can run at once.
- Binding to any other address requires `--token-env VAR` (HTTP Basic password or Bearer token); extra host names
  with `--allow-host` or `TOOL_ALLOWED_HOSTS`.
- Same shell: sidebar with Overview, Search, the tool's own pages, Sources, Export, About & licences; footer with
  JSON API, Shortcuts, Theme. One search box per page.
- Same keys: `/` search, `?` shortcuts, `g` + letter to go to a page, `j`/`k`, `Enter`, `x`, `e`, `y`, `t`, `Esc`.
- About & licences has, in this order: what TOOL does, licences, search syntax, command line, data and privacy,
  versions, credits.
- Search page layout: `/search?...&view=table` for the table, `view=cards` (or nothing) for the cards. sigharvest's
  old `layout=table` is still accepted.
- Unknown pages render the HTML error page; `/api/*` errors are JSON `{"detail": "..."}`.
- Styles: `harvest-base.css` is byte-identical in both tools (a test checks its SHA-256); each tool adds only its
  accent tokens and its domain components.

## Releases

- Rule releases are tagged `rules-YYYY-MM-DD` (`.N` for a second one that day) and published as drafts first.
- Every release has `RELEASE_NOTES.md`, `NOTICE.md`, the licence texts, a manifest, `changes.json`, `stats.json`,
  `SHA256SUMS` and, when signing is on, `SHA256SUMS.sigstore.json`. Archives of rules start with `TOOL-`. The
  licence and manifest file names follow the rule format (see the table below).
- The nightly workflow is `.github/workflows/nightly.yml`.

## Repository

- Docs: `getting-started.md`, `cli.md`, `web.md`, `export.md`, `sources.md`, `concepts.md`, `identity.md`,
  `releases.md`, `site.md`, `scheduling.md`, `automation.md`, `architecture.md`, `faq.md`, `conventions.md`.
- README sections, in order: centred hero (logo, name, pitch, three badges: CI, licence, Python), section links,
  the overview screenshot, Quickstart (install, init + update, serve), What you get (screenshots), How it works
  (Mermaid), Download the rules, Documentation, Licence and attribution. Comparisons with other tools live in
  `docs/faq.md`. Links are absolute; the repository's own images (logo, screenshots) are relative paths, so GitHub
  shows them even while the repository is private. `scripts/pypi_readme.py` (run by `publish.yml` before
  `uv build`) makes every relative link and image absolute for the PyPI page; `tests/` checks both forms.
- Screenshots: `uv run scripts/screenshots.py` against a running demo workspace writes `docs/screenshots/NAME-light.png`
  and `NAME-dark.png` (1440x900 at 2x, the README shows them with `<picture>`) and `docs/social-preview.png`.
- CHANGELOG follows Keep a Changelog with an `## [Unreleased]` section on top.
- SECURITY.md sections: Supported versions, Reporting a vulnerability, Threat model, Verifying a release,
  Dependency advisories. CODE_OF_CONDUCT.md is the same text in both.
- Issue templates: `bug.yml`, `source.yml`, `rule-feedback.yml`, `config.yml`.
- Local checks: `scripts/ci-full-local.sh [--quick]`; clean-install test: `tests/acceptance/accept.sh TOOL
  [REPO] --offline`. `tests/acceptance/`, `scripts/privacy_gate.py`, `scripts/pypi_readme.py` and
  `scripts/screenshots.py` are shared copies: change them in both.

## Intentional differences

| | sigharvest | suriharvest |
|---|---|---|
| Presets | curated, sigmahq, all | core, community, all |
| Export formats | Sigma YAML, zip, JSONL, CSV, SIEM queries | suricata.rules, suricata-update layout |
| Release index | `index.json.gz` | `index.yaml` (suricata-update) |
| Release manifest, licence texts | `manifest.json` + `rules.jsonl.gz`, `LICENSES.zip` | `manifest.jsonl.gz`, `LICENSES.tar.gz` |
| Own pages | ATT&CK coverage, Changes, collections | Builds & changes, Profiles & exclusions, Jobs & health |
| Accent colour | teal | cobalt |
