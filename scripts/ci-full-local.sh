#!/usr/bin/env bash
# Runs on this machine what ci.yml, ci-full.yml and ci-docs.yml run on GitHub (docs/automation.md#what-runs-when),
# without spending Actions minutes: ruff, actionlint (when installed), pytest on Python 3.12 and 3.13, the engine
# tests and the docs examples against the local `suricata`, the web UI at 390 px (Playwright), the offline acceptance
# harness (clean wheel) and the privacy gate. Native Windows and the second Suricata major have no local equivalent:
# run the engine tests again with the other `suricata` on PATH, or dispatch ci-full.yml.
#
#   scripts/ci-full-local.sh            # everything; a failed step does not stop the others
#   scripts/ci-full-local.sh --quick    # only what runs on every push (ci.yml)
#
# The 3.12/3.13 environments live in ${SURIHARVEST_CI_ENVS:-~/.cache/suriharvest-ci}, outside the checkout.
# Exit: 0 when every step passed, 1 otherwise (the failed steps are listed at the end).
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2
ENVS=${SURIHARVEST_CI_ENVS:-${XDG_CACHE_HOME:-$HOME/.cache}/suriharvest-ci}
QUICK=0
[ "${1:-}" = --quick ] && QUICK=1
failed=()
step() { # step NAME COMMAND...
    local name=$1; shift
    printf '\n\033[1m== %s\033[0m\n' "$name"
    "$@" || failed+=("$name")
}
on() { # on PYTHON COMMAND...: run in a uv-managed CPython env of that version (as CI does)
    local py=$1; shift
    UV_PYTHON_PREFERENCE=only-managed UV_PROJECT_ENVIRONMENT="$ENVS/py$py" uv run --locked --python "$py" "$@"
}

uv sync --locked || exit 2
step "ruff" uv run --no-sync ruff check .
step "ruff format" uv run --no-sync ruff format --check .
if command -v actionlint >/dev/null; then step "actionlint" actionlint; else echo "actionlint not installed: skipped"; fi
step "pytest (py3.12)" on 3.12 pytest -q -n auto -m "not engine and not network"
step "engine tests (local suricata)" uv run --no-sync pytest -q -rs -m engine
step "privacy gate" python3 -I scripts/maintainer/privacy_gate.py . --allowlist .github/privacy-allowlist.txt --history

if [ "$QUICK" = 0 ]; then
    step "pytest (py3.13)" on 3.13 pytest -q -n auto -m "not engine and not network"
    step "docs examples" uv run --no-sync pytest -q -rs -m docs tests/test_docs.py
    step "web UI at 390 px (Playwright)" bash -c 'uv run --locked --group ui playwright install chromium-headless-shell &&
        SURIHARVEST_REQUIRE_PLAYWRIGHT=1 uv run --locked --group ui pytest -q -rs tests/test_web_layout.py'
    step "acceptance (offline, clean wheel)" tests/acceptance/accept.sh suriharvest "$PWD" --offline --locked
fi

if [ "${#failed[@]}" -gt 0 ]; then
    printf '\nFAILED: %s\n' "${failed[@]}"
    exit 1
fi
printf '\nall steps passed\n'
