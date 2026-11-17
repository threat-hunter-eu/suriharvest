# Contributing to suriharvest

Thanks for helping! Bug reports, source suggestions, docs fixes and code are all welcome.

## Quick ways to help

- **Suggest a source**: open an issue with the URL, the licence (link to the publisher's own text), the sid range,
  and whether the rules load on Suricata 7 and/or 8.
- **Report a broken build**: include `suriharvest version`, `suricata -V`, the `suriharvest runs show latest`
  output and the failing rule's sid.
- **Report a dedup or collision problem**: include both rule keys (`namespace:gid:sid`) from `suriharvest search`.
- **Rule content problems** (false positives, wrong msg): report them to the publisher of the rule.

## Development setup

You need Python 3.12+, [uv](https://docs.astral.sh/uv/), and Suricata (or Docker) for the engine tests.

```bash
git clone https://github.com/threat-hunter-eu/suriharvest
cd suriharvest
uv sync
uv run suriharvest --help
```

## Before you open a pull request

```bash
uv run ruff check .
uv run ruff format --check .
uv run pytest -n auto              # unit tests: no network, no Suricata needed
uv run pytest -m engine            # needs `suricata` on PATH
uv run --group ui playwright install chromium-headless-shell && uv run --group ui pytest tests/test_web_layout.py  # every page at 390 px
SURIHARVEST_TEST_PROXY=http://127.0.0.1:8899 uv run pytest -m proxy   # through a real forward proxy (network)
python3 -I scripts/maintainer/privacy_gate.py . --allowlist .github/privacy-allowlist.txt --history
tests/acceptance/accept.sh suriharvest --offline   # clean-install test of this checkout (suricata optional)
```

Or all of it in one command, the same checks as the full CI without spending Actions minutes (only native Windows
and the second Suricata major are left to `ci-full.yml`):

```bash
scripts/ci-full-local.sh            # --quick: only what runs on every push
```

**What runs when** ([docs/automation.md](../docs/automation.md#what-runs-when)): every push runs `ci.yml` only (ruff,
actionlint, pytest on 3.12, engine tests on Suricata 7, privacy gate). Python 3.13, Windows, Suricata 8, the wheel,
the web UI, the acceptance harness and the docs examples run on pull requests to main, daily when
`SURIHARVEST_FULL_CI_ENABLED` is `true`, and from Actions -> Run workflow.

- **Tests never use the network** by default. Tests that download real sources are marked `network`; tests that
  need a Suricata binary are marked `engine`. CI runs the engine tests inside pinned Suricata 7 (every push) and 8
  (pull requests) containers. Tests run in parallel (pytest-xdist): keep them independent of each other, writing
  only under `tmp_path`.
- **Fixtures are synthetic.** Do not commit rule text from ET or any other publisher; write minimal rules that
  show the case. CI rejects `.rules` files outside `tests/fixtures/` and `tests/acceptance/fixtures/`.
- **New behaviour comes with a test**; bug fixes with a test that fails before the fix.
- **Schema changes** go through an Alembic migration in `src/suriharvest/migrations/`.
- **Identity changes** (content hash, logic hash, rule key) must be called out in the PR: they change dedup
  results and can affect sid stability. Update `docs/identity.md`.
- **Never edit existing rows of the sid map** (`state/sid-map.tsv` in a workspace; the published project's map
  lives on the `state` branch and only the nightly `state` job writes it); it is append-only by design.
- Update the docs and add a line to `CHANGELOG.md` under *Unreleased*.

## Catalog changes

Editing `src/suriharvest/catalog/sources.yaml`:

- `licence` must reflect the publisher's own licence text, not only the OISF index label; say where you checked.
- `redistribute: yes` only when the licence clearly allows republishing.
- Set `min_suricata` from a real `suricata -T` run, and `priority` so the original publisher wins collisions.
- Sources that need a key or are non-commercial go in tier `user-fetch` with `redistribute: no`.

## Privacy rules for this repository

This is a public project. Never commit commercial or private rules, API keys, tokens, internal hostnames, internal
paths or e-mail addresses. CI runs gitleaks and `scripts/maintainer/privacy_gate.py` (tree and history) on every push and every pull request to main; a
justified exception goes into `.github/privacy-allowlist.txt`. The gate in the repository holds generic rules only;
maintainers keep a list of project-specific sensitive terms outside the repository and point the gate at it with
`SURIHARVEST_PRIVACY_TERMS=/path/to/terms.txt` (CI reads it from the `PRIVACY_TERMS` secret and prints a notice
when the secret is not set). Findings from that list are reported as `sensitive-term`.

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).

## Licence

By contributing you agree that your contribution is released under the project's [MIT licence](../LICENSE).
