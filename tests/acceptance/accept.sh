#!/usr/bin/env bash
# Acceptance harness: install TOOL from a clean wheel into a fresh, isolated environment and walk through what a
# brand-new user does (init, update, search, show, every export, web UI). See README.md.
#
#   accept.sh TOOL [REPO_PATH|GIT_URL] [options]
#     TOOL                sigharvest | suriharvest
#     REPO_PATH|GIT_URL   working tree or git URL (default: the repository containing this folder)
#   options
#     --offline           local fixture git repos instead of network sources (CI mode; PyPI still needed unless --uv-offline)
#     --uv-offline        install dependencies from the uv cache only (no network at all)
#     --cli NAME          console script to call (default TOOL)
#     --home-var NAME     workspace env var the tool honours (default TOOL_HOME in upper case)
#     --python VER        Python for the tool env (default 3.12)
#     --fail-fast         stop at the first failed step (default: keep going and report every failure)
#     --runs-dir DIR      parent of the run folder (default $ACCEPT_RUNS or ${TMPDIR:-/tmp}/acceptance-runs)
#     --keep-server       leave the web server running at the end (prints its URL)
#     --locked            install with the versions pinned in the repo's uv.lock (what CI tests); default resolves the
#                         newest allowed versions, like `uv tool install git+URL` does for a real user
#     --raw-copy          copy the whole working tree, ignoring .gitignore (default copies what a clone would get)
# Exit: 0 all checks passed (warnings allowed), 1 at least one failed step, 2 harness/usage error.

set -uo pipefail

HARNESS=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

usage() { sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 2; }

TOOL="" SOURCE="" MODE=online UV_OFFLINE=0 CLI="" HOME_VAR="" PYVER=3.12 KEEP_SERVER=0 RAW_COPY=0 LOCKED=0
RUNS_DIR=${ACCEPT_RUNS:-${TMPDIR:-/tmp}/acceptance-runs}
ORIG_ARGS=("$@")
while [[ $# -gt 0 ]]; do
    case $1 in
        --offline) MODE=offline ;;
        --uv-offline) UV_OFFLINE=1 ;;
        --cli) CLI=$2; shift ;;
        --home-var) HOME_VAR=$2; shift ;;
        --python) PYVER=$2; shift ;;
        --fail-fast) export FAIL_FAST=1 ;;
        --runs-dir) RUNS_DIR=$2; shift ;;
        --keep-server) KEEP_SERVER=1 ;;
        --raw-copy) RAW_COPY=1 ;;
        --locked) LOCKED=1 ;;
        -h|--help) usage ;;
        -*) echo "unknown option $1" >&2; usage ;;
        *) if [[ -z $TOOL ]]; then TOOL=$1; elif [[ -z $SOURCE ]]; then SOURCE=$1; else usage; fi ;;
    esac
    shift
done
case $TOOL in sigharvest|suriharvest) ;; *) echo "TOOL must be sigharvest or suriharvest" >&2; usage ;; esac
CLI=${CLI:-$TOOL}
HOME_VAR=${HOME_VAR:-$(tr '[:lower:]' '[:upper:]' <<<"$TOOL")_HOME}
# default: the repository that contains this harness (tests/acceptance/ -> ../..); else a TOOL folder next to it
if [[ -z $SOURCE ]]; then
    if [[ -f $HARNESS/../../pyproject.toml ]]; then SOURCE=$(cd "$HARNESS/../.." && pwd); else SOURCE=$(cd "$HARNESS/../.." && pwd)/$TOOL; fi
fi

# --------------------------------------------------------------------------------------------- clean environment
# Re-run under `env -i` with a throw-away HOME: no user config, keys, venvs, *_HOME variables or ~/.local/bin tools
# leak in. The uv cache and uv-managed Pythons are shared (speed only; they are content-addressed).
# TMPDIR is left unset (system default, like most users); ACCEPT_TMPDIR=DIR sets it, e.g. to test a long path.
if [[ ${ACCEPT_CLEAN_ENV:-0} != 1 ]]; then
    UV_BIN=$(command -v uv) || { echo "uv not found: install it from https://docs.astral.sh/uv/" >&2; exit 2; }
    command -v git >/dev/null || { echo "git not found" >&2; exit 2; }
    mkdir -p "$RUNS_DIR"
    RUN="$(cd "$RUNS_DIR" && pwd)/$TOOL-$MODE-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$RUN"/{home,logs,tmp,bin}
    uv_cache=$("$UV_BIN" cache dir 2>/dev/null)
    uv_py=$("$UV_BIN" python dir 2>/dev/null)
    exec env -i \
        ACCEPT_CLEAN_ENV=1 RUN="$RUN" UV_BIN="$UV_BIN" HARNESS="$HARNESS" \
        HOME="$RUN/home" USER="${USER:-user}" LOGNAME="${LOGNAME:-user}" ${ACCEPT_TMPDIR:+TMPDIR=$ACCEPT_TMPDIR} \
        PATH="$RUN/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin" \
        LANG=C.UTF-8 LC_ALL=C.UTF-8 TERM=dumb COLUMNS=200 NO_COLOR="${NO_COLOR:-}" FAIL_FAST="${FAIL_FAST:-0}" \
        UV_CACHE_DIR="$uv_cache" UV_PYTHON_INSTALL_DIR="$uv_py" UV_NO_CONFIG=1 \
        ${http_proxy:+http_proxy=$http_proxy} ${https_proxy:+https_proxy=$https_proxy} ${no_proxy:+no_proxy=$no_proxy} \
        ${SURICATA:+SURICATA=$SURICATA} ${SURICATA_CONFIG:+SURICATA_CONFIG=$SURICATA_CONFIG} \
        ${STEP_TIMEOUT:+STEP_TIMEOUT=$STEP_TIMEOUT} ${ACCEPT_FIXTURE_SKIP:+ACCEPT_FIXTURE_SKIP=$ACCEPT_FIXTURE_SKIP} \
        bash "${BASH_SOURCE[0]}" "${ORIG_ARGS[@]}"
fi

# shellcheck source=lib/common.sh
source "$HARNESS/lib/common.sh"
# shellcheck source=/dev/null
source "$HARNESS/lib/$TOOL.sh"

export UV_TOOL_DIR="$RUN/uv-tools" UV_TOOL_BIN_DIR="$RUN/bin"
[[ $UV_OFFLINE == 1 ]] && export UV_OFFLINE=1
export GIT_TERMINAL_PROMPT=0 GIT_CONFIG_NOSYSTEM=1
CAPTURE="$HARNESS/lib/capture.sh"
WS="$RUN/workspace"
SERVER_PID=""
EXTRA_PIDS=""   # helper processes a walkthrough starts (fixture HTTP server); killed on exit

{
    echo "TOOL=$TOOL"; echo "MODE=$MODE"; echo "RAW_COPY=$RAW_COPY"; echo "LOCKED=$LOCKED"; echo "SOURCE=$SOURCE"; echo "CLI=$CLI"; echo "HOME_VAR=$HOME_VAR"
    echo "STARTED=$(date -u +%Y-%m-%dT%H:%M:%SZ)"; echo "UV=$("$UV_BIN" --version)"; echo "GIT=$(git --version)"
    command -v suricata >/dev/null && echo "SURICATA=$(suricata -V 2>&1 | head -1)"
} >"$RUN/meta.env"
: >"$RUN/steps.tsv"

cleanup() {
    if [[ -n $SERVER_PID && $KEEP_SERVER != 1 ]]; then kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null; fi
    local p
    for p in $EXTRA_PIDS; do kill "$p" 2>/dev/null; wait "$p" 2>/dev/null; done
}
trap cleanup EXIT

printf '%s acceptance (%s) from %s\nrun folder: %s\n\n' "$TOOL" "$MODE" "$SOURCE" "$RUN"

# --------------------------------------------------------------------------------------------- 1. get the code
SRC="$RUN/src"
if [[ $SOURCE =~ ^(https?://|git@|ssh://|file://) || $SOURCE == *.git ]]; then
    run_step "git clone (as a new user would)" -- git clone --depth 1 "$SOURCE" "$SRC" || die "cannot clone $SOURCE"
elif [[ -d $SOURCE ]]; then
    # Copy what a clone would contain: tracked + untracked-but-not-ignored files (works before the first commit).
    # Never builds inside the repo itself, so the repo under test is not touched.
    copy_tree() {
        mkdir -p "$SRC"
        if [[ $RAW_COPY != 1 ]] && git -C "$SOURCE" rev-parse --git-dir >/dev/null 2>&1; then
            (cd "$SOURCE" && git ls-files -z --cached --others --exclude-standard) |
                (cd "$SOURCE" && xargs -0 -r cp --parents -t "$SRC" 2>/dev/null) || true
            (cd "$SOURCE" && git ls-files -z --cached --others --exclude-standard | tr '\0' '\n' | wc -l)
        else
            tar -C "$SOURCE" --exclude=.venv --exclude=dist --exclude=__pycache__ --exclude=.git -cf - . | tar -C "$SRC" -xf -
        fi
    }
    run_step "copy working tree (clone-equivalent)" -- bash -c "$(declare -f copy_tree); RAW_COPY=$RAW_COPY SOURCE='$SOURCE' SRC='$SRC' copy_tree" ||
        die "cannot copy $SOURCE"
else
    die "no such repo path or URL: $SOURCE"
fi
check "pyproject.toml present" test -f "$SRC/pyproject.toml" || die "no pyproject.toml in $SOURCE"
want "README has a quickstart (Quickstart/Use/Usage section)" grep -qiE '^#+ *(quick ?start|use|usage|getting started)\b' "$SRC/README.md"
want "README quickstart uses '$CLI'" grep -q "$CLI init" "$SRC/README.md"
check "no workspace data or secrets in the tree" bash -c "! find '$SRC' \( -name '*.db' -o -name '*.sqlite' -o -name 'api.env' -o -name '.env' -o -name 'sources.private.yaml' \) -print | grep ."

# --------------------------------------------------------------------------------------------- 2. build + install
run_step "uv build --wheel" -- "$UV_BIN" build --wheel --out-dir "$RUN/dist" "$SRC" || die "wheel build failed (see $LAST_LOG)"
WHEEL=$(ls "$RUN"/dist/*.whl 2>/dev/null | head -1)
[[ -n $WHEEL ]] || die "no wheel in $RUN/dist"
check "wheel is named $TOOL-*" bash -c "[[ '$(basename "$WHEEL")' == $TOOL-* ]] || { echo 'wheel is $(basename "$WHEEL")'; exit 1; }"
want "uv.lock committed" test -f "$SRC/uv.lock"
check "wheel ships no rule corpus or database" bash -c "! python3 -I -m zipfile -l '$WHEEL' | grep -E '\.(db|sqlite|evtx)\b|corpus/'"
INSTALL_ARGS=()
if [[ $LOCKED == 1 ]]; then
    run_step "uv export lock constraints" -- "$UV_BIN" export --project "$SRC" --frozen --no-dev --no-hashes --no-emit-project -o "$RUN/constraints.txt" ||
        die "cannot export uv.lock"
    INSTALL_ARGS=(--constraints "$RUN/constraints.txt")
fi
run_step "uv tool install (fresh env, Python $PYVER$([[ $LOCKED == 1 ]] && echo ', uv.lock pins'))" -- "$UV_BIN" tool install --python "$PYVER" "${INSTALL_ARGS[@]}" "$WHEEL" ||
    die "install failed (see $LAST_LOG)"
TOOL_ENV=$(find "$UV_TOOL_DIR" -mindepth 1 -maxdepth 1 -type d | head -1)
TOOL_PY="$TOOL_ENV/bin/python"
[[ -x $TOOL_PY ]] || die "no tool environment under $UV_TOOL_DIR"
if ! check "console script '$CLI' on PATH" test -x "$RUN/bin/$CLI"; then
    log "installed scripts: $(ls "$RUN/bin" | tr '\n' ' ')"
    die "the wheel does not provide '$CLI' (re-run with --cli NAME to test the rest anyway)"
fi
BIN="$RUN/bin/$CLI"
tool_version
run_step "$CLI --help" -- "$BIN" --help
# The marker list is not kept in this repository (scripts/privacy_gate.py scans the whole tree,
# --help text included, in CI). Set ACCEPT_INTERNAL_RE to a regex to run this check here too.
INTERNAL_RE=${ACCEPT_INTERNAL_RE:-}
if [[ -n $INTERNAL_RE ]]; then
    check "--help names no internal/private product" bash -c "! grep -iE '$INTERNAL_RE' '$LAST_LOG'"
fi

# --------------------------------------------------------------------------------------------- 3. tool walkthrough
tool_contract_help        # every documented command/flag exists in --help (warnings)
tool_flow                 # init, sources, update, search, show, export, validate exports
tool_web                  # serve/web on a free port, every page + JSON API, CSP, no tracebacks

finish
[[ $FAILS -eq 0 ]]
