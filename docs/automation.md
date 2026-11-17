# GitHub Actions

Seven workflows live in `.github/workflows/` ([what runs when](#what-runs-when) has the CI split):

| Workflow | Trigger | What it does |
|---|---|---|
| `ci.yml` | push to any branch (not `state`/`data`), pull request to main, manual | ruff (lint + format), actionlint and an "all workflows pin the same images" check; pytest on Python 3.12 (`-n auto`) and a smoke test of every CLI command and flag the other workflows call; `pytest -m engine` inside the pinned Suricata 7 image; the privacy gate + gitleaks |
| `ci-full.yml` | pull request to main (not docs-only), daily 02:47 UTC when `SURIHARVEST_FULL_CI_ENABLED`, manual | pytest on Python 3.13, native Windows (pytest + `scripts/windows-smoke.ps1`), `pytest -m engine` inside the pinned Suricata 8 image, the wheel installed in a clean venv + `init`, the web UI at 390 px (Playwright), the offline acceptance harness (`tests/acceptance`) |
| `ci-docs.yml` | pull request to main, daily with `ci-full.yml`, manual | every `<!-- doctest -->` example of README.md and docs/ inside the Suricata 7 image |
| `nightly.yml` | daily 03:23 UTC + manual (`force_release`, `cold_start`, `ignore_gates`) | sync the redistributable core sources, validate on Suricata 7 and 8, `release build`, `suricata -T` on the exact files to publish, commit the sid map to the `state` branch, sign (opt-in, public only), publish a GitHub Release `rules-YYYY-MM-DD`, keep stats on a `data` branch, open an issue when a scheduled run fails |
| `catalog-health.yml` | Mondays 04:41 UTC + manual | `suriharvest sources check --licences` on the bundled catalog; opens or updates a PR that only touches `src/suriharvest/catalog/health.yaml` |
| `publish.yml` | release `v*` published (not prerelease) + `SURIHARVEST_PYPI_ENABLED` | tag commit must be on `main`; tests; `uv build --no-sources` without uv cache; trusted publishing (OIDC) from the protected `pypi` environment ([PyPI](#pypi)) |
| `pages.yml` | called by nightly, manual, push of `src/suriharvest/site/**` | `suriharvest site build` from the release's metadata files (no workspace): overview with downloads and checksums, sources, changes, Suricata check, notice, client-side search over rule metadata; static and CSP-safe (no inline script or style), deployed to GitHub Pages |

## What runs when

Actions minutes are billed for a private repository, each job rounded up to a whole minute and Windows at twice the
Linux rate, so the checks are split by cost. `tests/test_workflows.py` keeps the push set to the four jobs below.

| Event | Workflows | Jobs |
|---|---|---|
| push to any branch | `ci.yml` | `lint` (ruff, ruff format, actionlint, image pins), `test` (pytest, Python 3.12), `engine` (Suricata 7), `privacy` (about 5 billed minutes) |
| pull request to main | `ci.yml` `lint` + `privacy` (and `test` + `engine` for a fork's PR, whose branch had no push run here), `ci-full.yml`, `ci-docs.yml` | Python 3.13, Windows, Suricata 8, wheel, web UI at 390 px, acceptance, docs examples; a docs-only change (`*.md`, `docs/`) skips `ci-full.yml` but not the docs examples |
| daily 02:47 UTC | `ci-full.yml` + `ci-docs.yml` | as for a pull request, only when the repository variable `SURIHARVEST_FULL_CI_ENABLED` is `true` (default off: the jobs are skipped and nothing is billed) |
| manual (Actions -> Run workflow) | any of the three | everything in that workflow, on the branch you pick |

Make `ruff, actionlint, engine pins` and `privacy gate` required status checks on main (Settings -> Branches) once
the repository is public: then no pull request, from a fork or Dependabot included, merges without them.

Every check workflow cancels a superseded run of the same branch, and every job has a `timeout-minutes`. The whole
suite, minus native Windows and the second Suricata major, runs locally with one command (no Actions minutes):
`scripts/ci-full-local.sh` (`--quick` runs the push set only).

## Switching automation on

Nothing scheduled runs until you set repository variables (Settings -> Secrets and variables -> Actions ->
Variables). Forks do not inherit variables, so a fork never publishes by accident.

| Name | Kind | Default | Purpose |
|---|---|---|---|
| `SURIHARVEST_FULL_CI_ENABLED` | variable | unset (off) | `true` runs `ci-full.yml` and `ci-docs.yml` daily as well ([what runs when](#what-runs-when)) |
| `SURIHARVEST_AUTOMATION_ENABLED` | variable | unset (off) | `true` enables nightly, catalog-health and pages |
| `SURIHARVEST_PAGES_ENABLED` | variable | unset (off) | `true` additionally enables pages (Settings -> Pages -> Source: GitHub Actions) |
| `SURIHARVEST_SIGNING_ENABLED` | variable | unset (off) | keyless cosign signature of `SHA256SUMS` in the `sign` job; only honoured on a repository the API reports as **public** ([Signing](#signing)) |
| `SURIHARVEST_KEEP_RELEASES` | variable | `30` | `rules-*` releases kept by the prune step |
| `SURIHARVEST_RULES_REPO` | variable | this repository | `owner/name` of the data repository that receives the releases ([Rules repository](#rules-repository)) |
| `SURIHARVEST_RULES_APP_CLIENT_ID` | variable | unset | client id of the GitHub App that publishes into `SURIHARVEST_RULES_REPO` |
| `SURIHARVEST_RULES_APP_KEY` | secret (environment `rules-publish`) | unset | that App's private key (PEM) |
| `SURIHARVEST_KEEP_MONTHLY` | variable | `12` | months for which the first `rules-*` release of the month is kept beyond `SURIHARVEST_KEEP_RELEASES` |
| `SURIHARVEST_STATS_BRANCH` | variable | `data` | branch that receives `stats/latest.json` and `stats/history.jsonl` |
| `SURIHARVEST_MAX_DROP_PCT` | variable | `5` | release gate: largest allowed drop of rules per engine against the last release |
| `SURIHARVEST_PR_TOKEN` | secret | `GITHUB_TOKEN` | GitHub App token or PAT for the catalog-health PR, so CI runs on it |

Repository settings the workflows need: Actions may create pull requests (catalog-health). No workflow pushes to
`main`: the sid map goes to the `state` branch and stats to the `data` branch, so `main` can require pull requests
([sid map state branch](#sid-map-state-branch)).

### Signing

Signing is opt-in and public-only, and the gate fails closed: keyless cosign writes a **public** Sigstore
transparency-log (Rekor) entry whose certificate names the repository, workflow, ref, run and commit, and it cannot be
removed.

- A separate `sign` job (the only one with `id-token: write`; `publish` keeps `contents: write` without it) runs only
  when `SURIHARVEST_SIGNING_ENABLED` is `true`.
- Its first step asks the API, `gh api repos/$GITHUB_REPOSITORY --jq .private` with `GITHUB_TOKEN`, and sets
  `public=true` only when the answer is exactly `false`. An API error, an empty answer or `true` all give
  `public=false`; the cosign steps require `public == 'true'` **and** the variable.
- The event payload (`github.event.repository.private`) is not used: `schedule` payloads are not documented to carry
  `repository`, and `!null` would be `true` (fail-open). For the same reason the branch checks use
  `github.event.repository.default_branch || 'main'`.
- A private repository never signs, whatever the variable says; its releases have no `SHA256SUMS.sigstore.json`
  (verify them with `sha256sum --check SHA256SUMS`). If signing is on and `sign` fails, nothing is published that
  night. `pages.yml` uses the same visibility check and stops when the repository is not verified public (a Pages
  site is public even for a private repository).

### PyPI

`publish.yml` is off until `SURIHARVEST_PYPI_ENABLED=true`. Before turning it on:

1. Settings -> Environments -> New environment `pypi`: **Required reviewers** = the owner ("Prevent self-review" once
   there are other maintainers); **Deployment branches and tags** = "Selected branches and tags" with one **tag** rule
   `v*`; no secrets. Without it GitHub creates the environment on first use with no protection.
2. On PyPI, the trusted publisher names this repository, workflow `publish.yml` **and** environment `pypi`.
3. Optionally, a tag ruleset on `v*` so only admins can create, move or delete release tags.

The `build` job refuses a prerelease and a tag whose commit is not on `main` (`git merge-base --is-ancestor
"$GITHUB_SHA" origin/main`), restores no uv cache, makes the README's relative image paths absolute
(`scripts/maintainer/pypi_readme.py`, so they show on PyPI) and builds with `uv build --no-sources`; only `publish`, inside the
protected environment, has `id-token: write`.

### Sid map state branch

The persistent sid map (`state/sid-map.tsv`, append-only, docs/sids.md) lives on the orphan branch `state`, never on
`main`:

- `build` reads it through the API from the tip of `state` (it holds no git credentials) into its workspace. With no
  `state` branch it starts from an empty map, but only if no `rules-*` release exists yet; otherwise it stops.
- `state` (contents write) fetches the branch with a token passed to git for that command only (no persisted
  credentials), re-validates the new map (same base as the build read, allowed transitions only, well-formed) with
  `python3 -I src/suriharvest/sidmap_check.py` **from main's checkout**, and pushes one commit to `state` (never
  forced: if the branch moved, the push fails and nothing is published). The release is tagged on the built `main`
  commit; the job summary names the `state` commit.
- Trust model: the `state` branch is a working copy, not the authority. The previous **published** release is,
  downloaded from GitHub in the `state` job (not taken from the build artifact or from the branch): its manifest is
  the only thing that allows retiring a row, and the new map must also pass `sidmap_check.py` against the
  `sid-map.tsv` that release shipped (checked against its `SHA256SUMS`), so rows removed from the branch by hand are
  caught.
- Rulesets (public repository): `main` = pull request required, no force-push or deletion; `state` and `data` = no
  force-push, no deletion, pushes from Actions allowed.
- Recovery: if `state` is lost, recreate it from the latest release's `sid-map.tsv` (checked against its
  `SHA256SUMS`): `git switch --orphan state && mkdir state && cp <download>/sid-map.tsv state/ && git add state &&
  git commit -m "state: restore sid map from <tag>" && git push origin state`.

No workflow uses a source key. Sources that need a key, have a non-commercial licence or no licence are never
fetched by CI; they are listed in `recipes.tar.gz` so users can fetch them themselves.

## Rules repository

The packs are published in a separate public data repository, `threat-hunter-eu/suriharvest-rules`, named by the repo variable
`SURIHARVEST_RULES_REPO` (`owner/name`). Unset, everything is published in this repository as before. The data repository
holds only releases `rules-YYYY-MM-DD`, a README, `LICENSE-NOTE.md` and its own `pages.yml` (the search site); it
runs no build. Users download from `https://github.com/threat-hunter-eu/suriharvest-rules/releases/latest/download/<file>`.

- Reads (previous release, gates, the published manifest and sid map the `state` job checks against): `GITHUB_TOKEN`, read-only, on the public data repository.
- Writes: only the `publish` job, through a GitHub App installed on the data repository alone (repository
  permission Contents: read and write, nothing else). `actions/create-github-app-token` mints a one-hour token for
  that one repository after every gate passed. The App's client id is the variable `SURIHARVEST_RULES_APP_CLIENT_ID`; its
  private key is the secret `SURIHARVEST_RULES_APP_KEY` of the environment `rules-publish` (deployment branches: `main`
  only), so no other job, branch or pull request can read it.
- Signing: the `sign` job signs only when **both** repositories are verified public (same fail-closed API check).
  The Sigstore identity stays this repository's `nightly.yml` on `main` (see .github/SECURITY.md).
- `publish` adds `build-info.json` (tool repository, commit, run URL; not in `SHA256SUMS`). The data repository's
  `pages.yml` runs on `release: published` (App-token releases fire it), checks that the commit is on this
  repository's `main` and builds the site with that commit. This repository's `pages` job and `pages.yml` are skipped
  while `SURIHARVEST_RULES_REPO` names another repository.
- Retention: the newest `SURIHARVEST_KEEP_RELEASES` (30) releases plus the first release of each of the newest
  `SURIHARVEST_KEEP_MONTHLY` (12) months; only `rules-YYYY-MM-DD[.N]` tags are ever deleted.
- Rulesets on the data repository: `main` requires a pull request (the App has no bypass, so it cannot push code);
  `rules-*` tags can be created and deleted only by the App and admins, and never moved; other tags only by admins.

The sid map (`state` branch), stats (`data` branch) and the failure issue stay in this repository; `index.yaml`
points at the data repository (`--download-base`), and `publish` refuses an `index.yaml` built for another one.

## Principles

- `permissions: {}` at workflow level; each job asks for the minimum. Jobs that download and parse third-party data
  (`nightly/build`, `catalog-health/check`) hold a read-only token, `persist-credentials: false` and no secrets.
  Write tokens live in small jobs that only move artifacts (`state`, `publish`, `pr`, `keepalive`), never persist
  credentials (the token is given to `git` for the fetch/push only), and re-validate the artifact first (sid map: same base, only the allowed transitions (`sidmap_check.py` with the release manifest), well-formed; health.yaml: known fields and source names).
- Release only on change: `summary.json` `content_id` against the previous release (or `force_release`).
- Draft, then publish: `gh release create --draft` with every asset, then `--draft=false --latest`.
- Last good wins: a failed night saves no cache, commits nothing and publishes nothing.
- Only the check workflows (`ci.yml`, `ci-full.yml`, `ci-docs.yml`; read-only token) use the setup-uv cache; every other `setup-uv` step has `enable-cache: false`, uv
  itself is pinned (`version:`), and no `run:` script contains a `${{ }}` expression. `tests/test_workflows.py`
  enforces all three plus the SHA pins. Dependabot (`.github/dependabot.yml`) proposes weekly grouped updates for
  actions and `uv.lock`; bump the uv pin by hand with setup-uv.
- Supply chain: actions pinned by commit SHA (the comment names the exact tag); Suricata images pinned by digest (`jasonish/suricata:7.0.17@sha256:...`,
  `jasonish/suricata:8.0.8@sha256:...`) in the `ci*.yml` workflows and `nightly.yml`; the `lint` job of `ci.yml` fails if the pins differ
  or lose their digest. gitleaks and actionlint are pinned too.
- Privacy: `scripts/maintainer/privacy_gate.py` scans the tree and the whole history with generic rules (secrets, e-mail
  addresses, home/user paths, databases, binaries, large files); exceptions go to `.github/privacy-allowlist.txt`
  (path glob, rule id, optional line regex, justification). Project-specific sensitive terms are not in the
  repository: the gate loads them from the file named by `SURIHARVEST_PRIVACY_TERMS` (format in `load_terms`); CI
  writes that file from the `PRIVACY_TERMS` repository secret and shows a notice (generic rules only) when the
  secret is missing. Run it locally before pushing:
  `SURIHARVEST_PRIVACY_TERMS=/path/to/terms.txt python3 -I scripts/maintainer/privacy_gate.py . --allowlist .github/privacy-allowlist.txt --history`.

## Nightly, step by step

1. **build** (read-only): restore the workspace cache (`.ws/corpus`, `.ws/data`, one key per day);
   `suriharvest init .ws --refresh --catalog src/suriharvest/catalog/sources.yaml --tier core --redistributable-only
   --engine suricata-7=<image> --engine suricata-8=<image>`; copy the sid map from the `state` branch into the workspace; a Python
   guard checks that every enabled source is `redistribute: yes`, not experimental/user-fetch, has no `auth` and is
   `active` or `stale`; `suriharvest doctor`; `suriharvest update --allow-failures --max-failed-sources 10`;
   download `summary.json` and `manifest.jsonl.gz` of the last `rules-*` release; `suriharvest release build`
   with `--previous` (gates) and `--recipes-from` the catalog; check `SHA256SUMS` and `index.yaml`; save the cache
   only when everything passed.
2. **verify** (matrix 7/8, inside the pinned image, without suriharvest): checksums, engine version equals
   `summary.json`, tarball copies equal the flat files, per-source files partition the merged file, and
   `suricata -T` on every published rules file loads exactly the number of rules `summary.json` announces.
3. **state** (contents write): commits the sid map to the `state` branch before anything is published (sids are
   only reserved, so a committed map followed by a failed publish is harmless).
4. **sign** (id-token; only with `SURIHARVEST_SIGNING_ENABLED=true`, cosign only on a verified-public repository):
   keyless cosign bundle `SHA256SUMS.sigstore.json`, handed to `publish` as an artifact.
5. **publish** (contents write): checksums, the signature when `sign` made one, tag
   `rules-YYYY-MM-DD` (`.2`, `.3` on reruns), draft then public, prune old releases.
6. **pages**, **keepalive** (stats branch, heartbeat commit so scheduled workflows are not disabled after 60 days
   without activity), **notify** (one `nightly-failure` issue).

## Known gaps

The workflows are written for the complete design. These parts are not finished yet and are guarded so the
workflows do not fail:

| Item | Effect today | Where it is guarded |
|---|---|---|
| dataset sources in the nightly build | `release build` ships `suricata-N.datasets.tar.gz` (files under `datasets/<source>/`, unpack next to the `.rules` files; also inside `suriharvest-N.tar.gz` under `rules/datasets/`, next to `rules/suricata.rules`); nightly still enables the **core** tier only | `nightly.yml` init step (`--tier core`) |
| health fields `final_url`, `since`, `rules_seen` | not written; `sources check` writes `status`, `check`, `oisf`, `licence_url`, `licence_sha256`, `licence_changed` | the PR job accepts both sets |
| licence texts for git sources | `LICENSES.tar.gz` holds the files publishers ship inside tarballs; for git sources (only rule files are kept) `LICENSES/INDEX.md` links the SPDX text | `release.py` `_licence_files` |
| manifest `content_hash` and rows for rules excluded for other reasons than duplicates (`duplicate_of` rows are written); rules shipped disabled upstream kept commented in the release | not in the manifest; the release ships enabled rules only | - |

## Failure modes

| Failure | Effect | Recovery |
|---|---|---|
| a source fails (timeout, 410, rename) | `--allow-failures` keeps its last copy; more than 10% failed fails the gate | fix the catalog; the weekly health PR shows it |
| corpus or release gate (drop > 5% per engine, a source drops > 50% or vanishes) | build red, nothing saved or published, issue opened | inspect the diagnostics artifact; if the drop is real and reviewed, rerun with `ignore_gates` |
| verify fails | no sid map commit, no release | reproduce with the `release-files` artifact in the same image |
| sid map changed on `state` during the run | `state` fails, nothing published | rerun |
| `state` branch missing while releases exist | `build` fails | restore it from the latest release's `sid-map.tsv` ([sid map state branch](#sid-map-state-branch)) |
| a ruleset rejects the push to `state` | `state` fails, nothing published | allow pushes from Actions on `state` (no force-push, no deletion) |
| signing on and `sign` fails (cosign, Rekor) | nothing published | rerun the failed jobs; to release unsigned, unset `SURIHARVEST_SIGNING_ENABLED` |
| publish fails half way | the release stays a draft | delete the draft, rerun the failed jobs (artifacts are kept 7 days) |
| bad release | users get bad data | `gh release delete <tag> --cleanup-tag`; the previous one becomes latest |
| privacy gate hit | CI red | remove it, or allowlist it with a justification; leaked secrets must be rotated and purged |
