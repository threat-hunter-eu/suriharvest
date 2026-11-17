# shellcheck shell=bash
# Shared helpers for accept.sh: timed steps, checks, result files.
# Every step writes its full output to $RUN/logs/NN-<slug>.log and one row to $RUN/steps.tsv:
#   n  status(OK|FAIL|WARN|SKIP)  seconds  name  log  message

STEP_N=0
FAILS=0
WARNS=0
FAIL_FAST=${FAIL_FAST:-0}
C_OK=$'\e[32m' C_FAIL=$'\e[31m' C_WARN=$'\e[33m' C_DIM=$'\e[2m' C_OFF=$'\e[0m'
if [[ ! -t 1 || -n "${NO_COLOR:-}" ]]; then C_OK='' C_FAIL='' C_WARN='' C_DIM='' C_OFF=''; fi

log() { printf '%s\n' "$*" >&2; }
die() { printf '%sFATAL%s %s\n' "$C_FAIL" "$C_OFF" "$*" >&2; finish; exit 2; }

_slug() { printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '-' | cut -c1-60; }

_now() { printf '%s' "${EPOCHREALTIME:-$(date +%s.%N)}"; }

_record() { # status seconds name logfile message
    local status=$1 secs=$2 name=$3 logf=$4 msg=${5:-}
    msg=${msg//$'\t'/ }
    msg=${msg//$'\n'/ | }
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$STEP_N" "$status" "$secs" "$name" "${logf#"$RUN"/}" "${msg:0:600}" >>"$RUN/steps.tsv"
    local colour=$C_OK
    case $status in FAIL) colour=$C_FAIL; FAILS=$((FAILS + 1)) ;; WARN) colour=$C_WARN; WARNS=$((WARNS + 1)) ;; SKIP) colour=$C_DIM ;; esac
    printf '%s[%-4s]%s %3d %-58s %7ss %s\n' "$colour" "$status" "$C_OFF" "$STEP_N" "${name:0:58}" "$secs" "${msg:0:160}"
    if [[ $status == FAIL && $FAIL_FAST == 1 ]]; then finish; exit 1; fi
}

# Problems we look for in the output of every command, even when it exits 0.
BAD_OUTPUT_RE='Traceback \(most recent call last\)|UnicodeEncodeError|UnicodeDecodeError|sqlite3\.OperationalError|Internal Server Error|RuntimeWarning: coroutine'

# run_step [--expect "0 1"] [--soft] [--cwd DIR] NAME -- CMD...
#   Runs CMD with a timer. FAIL when the exit code is not in --expect (default 0) or the output shows a traceback.
#   --soft turns a failure into WARN (contract items not settled yet). Sets LAST_LOG, LAST_RC.
run_step() {
    local expect="0" soft=0 cwd="" name=""
    # options may come before or after NAME; `--` ends them
    while [[ $# -gt 0 && $1 != -- ]]; do
        case $1 in
            --expect) expect=$2; shift 2 ;;
            --soft) soft=1; shift ;;
            --cwd) cwd=$2; shift 2 ;;
            --*) die "run_step: bad option $1" ;;
            *) name=$1; shift ;;
        esac
    done
    [[ ${1:-} == -- ]] && shift
    STEP_N=$((STEP_N + 1))
    LAST_LOG="$RUN/logs/$(printf '%02d' "$STEP_N")-$(_slug "$name").log"
    local t0 t1 rc msg status
    t0=$(_now)
    {
        printf '$'; printf ' %q' "$@"; printf '\n'
        [[ -n $cwd ]] && printf '# cwd: %s\n' "$cwd"
    } >"$LAST_LOG"
    if [[ -n $cwd ]]; then
        (cd "$cwd" && timeout "${STEP_TIMEOUT:-1800}" "$@") >>"$LAST_LOG" 2>&1 </dev/null
    else
        timeout "${STEP_TIMEOUT:-1800}" "$@" >>"$LAST_LOG" 2>&1 </dev/null
    fi
    rc=$?
    t1=$(_now)
    LAST_RC=$rc
    local secs
    secs=$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.1f", b-a}')
    printf '# exit %s after %ss\n' "$rc" "$secs" >>"$LAST_LOG"
    status=OK msg=""
    if [[ " $expect " != *" $rc "* ]]; then
        status=FAIL
        [[ $rc == 124 ]] && msg="timed out after ${STEP_TIMEOUT:-1800}s; " || msg="exit $rc (expected $expect); "
        msg+=$(grep -v '^# \|^\$ ' "$LAST_LOG" | grep -v '^\s*$' | tail -n 4 | cut -c1-200 | tr '\n' ' ')
    elif grep -Eq "$BAD_OUTPUT_RE" "$LAST_LOG"; then
        status=FAIL
        msg="exit $rc but output shows: $(grep -Eo "$BAD_OUTPUT_RE" "$LAST_LOG" | head -1); $(grep -E 'Error|error' "$LAST_LOG" | tail -n 1 | cut -c1-200)"
    fi
    [[ $status == FAIL && $soft == 1 ]] && status=WARN
    _record "$status" "$secs" "$name" "$LAST_LOG" "$msg"
    [[ $status != FAIL ]]
}

# check NAME CMD... : an assertion (no timing of interest). OK when CMD exits 0; its stdout/stderr is the message.
check() {
    local name=$1; shift
    STEP_N=$((STEP_N + 1))
    LAST_LOG="$RUN/logs/$(printf '%02d' "$STEP_N")-check-$(_slug "$name").log"
    local t0 out rc secs
    t0=$(_now)
    out=$("$@" 2>&1); rc=$?
    secs=$(awk -v a="$t0" -v b="$(_now)" 'BEGIN{printf "%.1f", b-a}')
    { printf '$'; printf ' %q' "$@"; printf '\n%s\n# exit %s\n' "$out" "$rc"; } >"$LAST_LOG"
    if [[ $rc == 0 ]]; then _record OK "$secs" "$name" "$LAST_LOG" "$(tail -n 1 <<<"$out")"; return 0; fi
    _record FAIL "$secs" "$name" "$LAST_LOG" "$(tail -n 3 <<<"$out")"
    return 1
}

# want NAME CMD... : like check, but a failure is a WARN (nice to have / contract not final).
want() {
    local saved=$FAIL_FAST name=$1; shift
    FAIL_FAST=0
    STEP_N=$((STEP_N + 1))
    LAST_LOG="$RUN/logs/$(printf '%02d' "$STEP_N")-want-$(_slug "$name").log"
    local out rc
    out=$("$@" 2>&1); rc=$?
    { printf '$'; printf ' %q' "$@"; printf '\n%s\n# exit %s\n' "$out" "$rc"; } >"$LAST_LOG"
    if [[ $rc == 0 ]]; then _record OK 0.0 "$name" "$LAST_LOG" "$(tail -n 1 <<<"$out")"; else _record WARN 0.0 "$name" "$LAST_LOG" "$(tail -n 3 <<<"$out")"; fi
    FAIL_FAST=$saved
    return 0
}

skip() { STEP_N=$((STEP_N + 1)); _record SKIP 0.0 "$1" "" "${2:-}"; }

# Python with PyYAML for the validators: the installed tool's own interpreter (isolated mode, -I).
pycheck() { "$TOOL_PY" -I "$HARNESS/lib/checks.py" "$@"; }

free_port() { python3 -I -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }

# http_get NAME URL [json|html|any] : 200, no traceback in body, CSP header present, content type as expected.
http_get() {
    local name=$1 url=$2 kind=${3:-html}
    check "$name" "$TOOL_PY" -I "$HARNESS/lib/checks.py" http "$url" --kind "$kind"
}

finish() {
    [[ -n "${RUN:-}" && -f "$RUN/steps.tsv" ]] || return 0
    local total ok
    total=$(wc -l <"$RUN/steps.tsv")
    ok=$(awk -F'\t' '$2=="OK"' "$RUN/steps.tsv" | wc -l)
    python3 -I "$HARNESS/lib/summarize.py" "$RUN" >/dev/null 2>&1 || true
    printf '\n%s: %d steps, %d ok, %s%d failed%s, %d warnings. Logs: %s\n' "${TOOL:-?}" "$total" "$ok" \
        "$([[ $FAILS -gt 0 ]] && printf '%s' "$C_FAIL")" "$FAILS" "$C_OFF" "$WARNS" "$RUN"
    [[ -f "$RUN/summary.md" ]] && printf 'Report: %s\n' "$RUN/summary.md"
}

# disable_others KEEP_CSV : disable every enabled source except KEEP_CSV through the CLI (`sources disable`).
# Tries one call with all names (convenient for users); falls back to one call per name and records a WARN.
# Offline mode refuses to continue if anything else is still enabled (the run must never hit the network).
disable_others() {
    local keep=$1 others n
    others=$(pycheck sources "$WS/sources.yaml" --enabled --keep "$keep")
    if [[ -n $others ]]; then
        # shellcheck disable=SC2086
        run_step --soft "sources disable NAME... ($(wc -w <<<"$others") names in one call)" --cwd "$WS" -- "$BIN" sources disable $others
        if [[ $LAST_RC != 0 ]]; then
            for n in $others; do
                run_step "sources disable $n" --cwd "$WS" -- "$BIN" sources disable "$n"
            done
        fi
    fi
    if ! check "only $keep enabled" bash -c "left=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' sources '$WS/sources.yaml' --enabled --keep '$keep'); [[ -z \$left ]] || { echo \"still enabled: \$left\"; exit 1; }"; then
        [[ $MODE == offline ]] && die "offline mode: other sources are still enabled; refusing to run update against the network"
    fi
}
