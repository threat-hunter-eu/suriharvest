# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

Nightly rulesets are versioned separately by date (`rules-YYYY-MM-DD`); their changes are in each release's
`RELEASE_NOTES.md`.

## [Unreleased]

Nothing yet: changes after the first public release are listed here.

## [0.1.0] - 2026-11-17

First public release.

### Added

- Per-major rulesets: with engines of several Suricata majors, a source whose URL holds `${suricata_version}`
  (ET Open) is downloaded once per major (`corpus/<source>/@<major>/`), each engine validates and publishes its
  own major's copy (`suricata-7.rules` from 7.0.3, `suricata-8.rules` from 8.0); identical texts stay one rule
  (same logic hash, same sid). docs/sources.md.
- Native Windows support: the workspace lock uses `msvcrt` byte locks on Windows (`fcntl` elsewhere), cached Git
  repos with read-only pack files are deleted, output redirected to a file or pipe is UTF-8, every written file
  (exports, releases, feeds, reports) uses LF so builds are byte-identical across operating systems, a missing
  Suricata/Docker names the fix, and the engine subprocess keeps the Windows variables it needs. CI runs the
  tests and a CLI smoke run on `windows-latest`.
- `publish.yml`: PyPI trusted publishing on a `vX.Y.Z` GitHub release, off until `SURIHARVEST_PYPI_ENABLED`
  is `true` (action pinned by SHA).
- docs/suricata-update.md: the nightly release as a suricata-update source.
- Catalog: `oisf_name` (the suricata-update index name, e.g. `et/open`, `oisf/trafficid`,
  `abuse.ch/sslbl-blacklist`) on every source that is in the OISF index, so `export --format suricata-update`
  leaves those sources to suricata-update and writes your exclusions to `disable.conf`.
- Doc tests: every shell example in README.md and docs/ is marked runnable or skipped with a reason, and the
  runnable ones run in CI against an offline fixture workspace (`pytest -m docs`).
- Docs: web.md rewritten for the current pages, the search filters (`cve:`, `licence:`, `remapped:`,
  `metadata:`, `flowbits:`) and the `/feed/<profile>/<engine>.tar.gz` suricata-update URL; CVE search recipe;
  working `show`/exclusion/`suricata -T` examples; `profile remove`, `import-conf` and override examples, the
  build `latest` link, `/api/search` + `/api/stats`, proxy settings (`SURIHARVEST_TRUST_PROXY`).
- `profile import-conf`: migrate a suricata-update configuration (enable/disable/drop/modify.conf: sid,
  gid:sid, `re:`, `group:`, `metadata:`) into a profile; unsupported lines are listed, never dropped.
- Profile overrides kept across updates (`exclusions/<profile>.yaml`): `enable`, `modify` (alert -> drop,
  or a regex rewrite; refused when it breaks the rule or its sid) and `thresholds` (`threshold.config` written
  with each rule's exported sid). New exclusion kinds `rule_regex`, `metadata`, `file`; sid and rule-key
  exclusions are dictionary lookups (thousands of entries stay fast).
- Read-only JSON API in `suriharvest serve`: `GET /api/search` (paginated, the CLI query syntax) and
  `GET /api/stats` (docs/web.md).
- `NOTICE`: project attribution and where the per-source rule licences are recorded.
- `site build`: static, CSP-safe GitHub Pages site from release files (downloads, sources, changes, Suricata check,
  notice, client-side search over rule metadata).
- Releases: merged `classification.config` / `reference.config` in `suriharvest-N.tar.gz`; `duplicate_of` rows
  and `msg` in the manifest.
- `init` with a bundled catalog of free Suricata sources and presets (`core`, `community`, `all`); workspaces via
  `SURIHARVEST_HOME`.
- `update`: conditional downloads, safe extraction, rule parsing (multi-line and disabled rules), validation with
  `suricata -T` on one or more engines (local binary or Docker image) with a result cache, indexing and update
  gates that keep the last good state.
- Identity and dedup: rule keys per publisher namespace (sidallocation.org aware), rev handling inside a
  namespace, logic hash and semantic normalisation, families, IOC detection.
- `search` with full-text and filters (`proto:`, `app:`, `buffer:`, `classtype:`, `source:`, `sid:`, `ioc:`,
  `loads:`/`fails:`, `mitre:`, `severity:`, `updated>`, `score>=`, ...), and `show`, `stats`, `deps`, `quarantine`.
- Profiles: named rulesets with query, engine and options; exclusions by message, sid, category, classtype,
  source, logic or query, with reasons and review dates; builds with `manifest.jsonl`, `excluded.jsonl` and
  `changes.json`; `profile diff`.
- `export`: merged `suricata.rules`, per-source files, suricata-update files (`local.rules`, `enable.conf`,
  `disable.conf`), IOC rules as datasets, flowbits closure, and stable sid remapping via `state/sid-map.tsv`.
- `sources` list / add / import / enable / disable, including local folders and sources that need a key.
- `runs` list / show / accept; `doctor`; `--version`.
- `serve`: local web UI (Overview, Search, Sources, Builds, Profiles & exclusions, Export, About & licences, Jobs &
  health), light and dark themes.
- Curated catalog of 30 free sources (10 core, 14 community, 4 experimental, 2 user-fetch) with SPDX licences, `stale` status,
  per-major URLs, sid namespaces of range owners and an `excluded:` list; `sources check` (OISF index, health,
  `--licences` fingerprints).
- `release build`: reproducible, checksummed release files per engine with `NOTICE.md`, `LICENSES.tar.gz`
  (publishers' licence files + SPDX texts), recipes for sources that are not redistributed, release gates.
- GitHub Actions: CI (lint, tests, CLI contract, wheel install, offline acceptance, engine tests, privacy gate),
  opt-in nightly release (Suricata 7 and 8, re-validated in clean containers, Sigstore-signed), weekly catalog
  health PR, optional Pages.
- `docs/conventions.md` (the same file in sigharvest); `serve` (the old name `web` is a hidden alias); `-v/--verbose`;
  `search --offset`; `profile build --json`; `--include-private-sources` (the opposite of `--redistributable-only`);
  `SURIHARVEST_ALLOWED_HOSTS` (extra Host names, as `--allow-host`); the `rule-feedback.yml` issue template.
- The web UI loads `harvest-base.css`, byte-identical in sigharvest (a test checks its SHA-256); `style.css` keeps
  the tokens and the Suricata components. The keyboard fixes of sigharvest's `app.js` (shortcuts on a focused
  checkbox, none while a dialog is open, select-all shows a partial state, list filters stay in their list).

### Security

- `profile import-conf` / overrides: drop.conf never turns a `noalert` flowbit setter into a drop
  rule (it blocked traffic without an alert), as suricata-update; enable.conf now wins over disable.conf
  (`beats_exclusions: true`), trailing ` # comments` are stripped, `group:x` matches `x.rules`, bare `x.rules`
  and `*` lines are read, prefixes are case-sensitive (golden tests against suricata-update 1.3.3).
- `modify`: a rewrite that adds a line break or control character, does not load in the profile's engine
  (`suricata -T`), or removes a flowbit setter other rules of the build need is refused per rule; the flowbit
  closure works on the rewritten rules. When the best flowbit setter cannot be used the next one is tried.
  Fail-safe: a rewrite the profile's engine did not validate (no engine, engine cannot run, rule loads files)
  is not applied; the rule ships as published.
- Sid map: two rules of the same sid owner keep their recorded sids across builds (the remapped one no
  longer moved at every build); a new revision takes over its rule's row; `release build --previous` retires rows
  of rules in neither manifest (never a row with a note); a `# floor=` header keeps retired sids used;
  `sidmap_check.py` checks every transition, takes retirement authority from the previous published release's
  manifest and binds the published rules files to the manifest.
- A copy from another source in an owner's rule key (`et:...`) is published only when the owner ever carried that
  text, also when the owner ships its rule disabled; the index notices rules a publisher only enabled or disabled.
- Rule options are split like Suricata: a `;` right after a backslash never ends an option, also after `\\`.
- Search: queries over 1 KiB or 32 terms and out-of-range `sid:` values are refused (400) instead of slow requests
  or HTTP 500s. `sources check` probes go through the same guarded HTTP client as sync.
- User regexes (`rule_regex`, `msg_regex`, `re:`) see the first 8 KiB of a rule and use RE2 when google-re2 is
  installed: a hostile long rule can no longer stall builds.
- A threshold `ip` list holding `$EXTERNAL_NET` with anything else is refused (Suricata keeps no address).
- Thresholds: `count`/`seconds`/`timeout` 1..2^32-1 in ASCII digits, no `!` and only default address variables
  in `ip`, lists written without spaces (Suricata refused the whole file before).
- Source URLs in published files are redacted (no credentials, query strings or local paths).
- `release build` / `export` / `profile build` apply the current `sources.yaml` (`redistribute`, `enabled`,
  `licence`) before building, without waiting for a sync.
- sid rewriting goes through the parser (a `sid:` inside another option is never touched); the range owner keeps
  its sid against squatters; malformed rules are quarantined or skipped, never abort a build.
- A source cannot replace a publisher's rule by reusing its sid and msg with a higher rev: rev only orders
  revisions of one lineage, across sources sid ownership then priority decide; the other copy is remapped and listed
  in `collisions.json`. A non-redistributable copy never displaces a redistributable rule in a shared build.
- Dataset rules: names that clash between rules are kept apart, files ship with profile builds, `export` and the
  web feed (or the rule is left out with a reason), dataset file contents are part of `content_id` and of the
  validation cache key, absolute/escaping dataset paths are never opened on the build host (`unsafe_path`).
- A source cannot redefine a higher-priority source's classtype in the merged `classification.config` (reported).
- Upstream notice lines cannot swallow a rule (no trailing backslash; loaded-rule counts are checked).
- Web UI: page numbers clamped, malformed `Content-Length` refused, non-ASCII credentials handled.
- Web UI under load: searches of three or more words (one of 8+ letters) and queries with control characters no
  longer answer 500 (the full-text query is always valid); an unexpected error is answered as a normal 500 instead
  of resetting the connection; ruleset downloads queue (1 running, 2 waiting, then 429), are built in a short-lived
  child process and stream from disk;
  downloads, feeds and the API refuse cross-site browser requests; POST bodies need a `Content-Length` (chunked
  bodies bypassed the 1 MB cap); the overview, Sources and export-page counts are cached per index; a busy connection pool
  answers 503; `testserver` is no longer an accepted Host outside the tests.
- Web downloads: a client that never read a finished download kept its (deleted) temp file open for as long as the
  connection lived, outside the download queue. Sends are now bounded (4 at once, then 429) and each chunk must be
  accepted within 60 s, or the client is disconnected and the file closed.
- The start-up sweep of old download folders in the shared temp folder followed a planted symbolic link, and
  removing it changed the mode of the link's target. The sweep now uses `lstat`, skips links and folders of other
  users, and `rmtree` never runs `chmod` through a link.

[0.1.0]: https://github.com/threat-hunter-eu/suriharvest/releases/tag/v0.1.0
