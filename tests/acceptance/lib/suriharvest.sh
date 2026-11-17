# shellcheck shell=bash
# suriharvest walkthrough: the documented CLI contract
# (init, doctor, sources, update, search, show, deps, quarantine, export, profile build/diff, web, version).

tool_version() {
    run_step "$CLI version" -- "$BIN" version
    check "version names the tool" grep -q "suriharvest" "$LAST_LOG"
    run_step "$CLI --version (common convention)" --soft -- "$BIN" --version
}

tool_contract_help() {
    local spec cmd flags f out
    local -a contract=(
        "init|--refresh --catalog --tier --redistributable-only --engine --suricata-version --preset"
        "doctor|"
        "update|--allow-failures --max-failed-sources --report-file"
        "release build|--engine --redistributable-only --recipes-from --download-base --build-epoch --previous --max-drop-pct --max-source-drop-pct --no-gates --report-file"
        "sources check|--catalog --health --oisf-index --licences --max-http-requests --report-file"
        "sources list|"
        "sources add|--type --licence --redistribute --tier --path --copyright"
        "sources enable|"
        "sources disable|"
        "search|--per-logic --json --limit"
        "show|"
        "export|--out --unit --redistributable-only --include-private-sources --profile --by-source --format --remap-colliding-sids"
        "deps|"
        "quarantine|"
        "profile build|"
        "profile diff|--json"
        "serve|--host --port"
        "site build|--release --tag --download-base --base-url --site-url --build-epoch"
    )
    local missing=() t0
    t0=$(_now)
    for spec in "${contract[@]}"; do
        cmd=${spec%%|*}; flags=${spec#*|}
        # shellcheck disable=SC2086
        if ! out=$("$BIN" $cmd --help 2>&1); then missing+=("'$cmd' (no such command)"); continue; fi
        for f in $flags; do grep -q -- "$f" <<<"$out" || missing+=("$cmd $f"); done
    done
    STEP_N=$((STEP_N + 1))
    if ((${#missing[@]})); then
        _record WARN "$(awk -v a="$t0" -v b="$(_now)" 'BEGIN{printf "%.1f", b-a}')" "CLI contract: commands/flags in --help" "" "missing: ${missing[*]}"
    else
        _record OK "$(awk -v a="$t0" -v b="$(_now)" 'BEGIN{printf "%.1f", b-a}')" "CLI contract: commands/flags in --help" "" "all ${#contract[@]} commands present"
    fi
}

suricheck() { # like check, but SKIP when there is no Suricata to run (NO_SURICATA=1)
    if ((${NO_SURICATA:-0})); then skip "$1" "no suricata on PATH"; return 0; fi
    check "$@"
}

tool_flow() {
    local fx="$RUN/fixture-repos" keep others key q ex="$RUN/exports"
    mkdir -p "$ex"
    NO_SURICATA=0
    if ! command -v "${SURICATA:-suricata}" >/dev/null; then
        # e.g. Windows or a laptop without Suricata: validation and every `suricata -T` check are skipped (SKIP lines)
        NO_SURICATA=1
        skip "engine steps" "suricata not on PATH: update runs with --no-validate, suricata -T checks are skipped"
    fi

    # ---- init
    run_step "init workspace (default preset)" --cwd "$HOME" -- "$BIN" init "$WS" || die "init failed"
    check "workspace layout (sources.yaml, suriharvest.yaml, data/suriharvest.db)" bash -c "cd '$WS' && test -f sources.yaml && test -f suriharvest.yaml && ls data/*.db"
    want "database is data/suriharvest.db (renamed)" test -f "$WS/data/suriharvest.db"
    run_step "init again refuses to clobber" --expect "1 2" --cwd "$HOME" -- "$BIN" init "$WS"
    check "catalog enables only redistributable sources without keys" "$TOOL_PY" -I -c "import sys, yaml; s = yaml.safe_load(open(sys.argv[1]))['sources']; sys.exit(any(x.get('enabled', True) and (x.get('auth') or x.get('redistribute') != 'yes' or '\${secret}' in x['url']) for x in s))" "$WS/sources.yaml"

    # ---- source set
    if [[ $MODE == offline ]]; then
        # shellcheck source=../expected/suriharvest-offline.env
        source "$HARNESS/expected/suriharvest-offline.env"
        run_step "build fixture git repos" -- python3 -I "$HARNESS/lib/make_fixtures.py" suricata "$fx" || die "fixtures"
        run_step "sources add fixture-suri-alpha (file://)" --cwd "$WS" -- "$BIN" sources add fixture-suri-alpha "file://$fx/fixture-suri-alpha" \
            --type git --licence MIT --redistribute yes --tier core
        run_step "sources add fixture-suri-beta (file://)" --cwd "$WS" -- "$BIN" sources add fixture-suri-beta "file://$fx/fixture-suri-beta" \
            --type git --licence BSD-2-Clause --redistribute yes --tier core --copyright "Copyright (c) 2026 Acceptance Fixture"
        keep="fixture-suri-alpha,fixture-suri-beta"
    else
        keep="et-open,oisf-trafficid"
        check "default preset has et-open and oisf-trafficid" bash -c "grep -q 'name: et-open' '$WS/sources.yaml' && grep -q 'name: oisf-trafficid' '$WS/sources.yaml'"
    fi
    disable_others "$keep"
    if [[ $MODE == online ]]; then
        # make sure both wanted sources are on even if the preset left one off
        run_step "sources enable et-open oisf-trafficid" --cwd "$WS" -- "$BIN" sources enable et-open oisf-trafficid
    fi
    run_step "sources list" --cwd "$WS" -- "$BIN" sources list

    # ---- doctor + update
    run_step "doctor (fresh workspace)" --cwd "$WS" -- "$BIN" doctor
    STEP_TIMEOUT=${STEP_TIMEOUT:-3600} run_step "update (sync + validate + index)" --cwd "$WS" -- "$BIN" update $( ((NO_SURICATA)) && echo --no-validate)
    run_step "doctor (after update)" --cwd "$WS" -- "$BIN" doctor
    # README "Use": `ls data/profiles/default/*/` -> suricata.rules, by-source/, manifest.jsonl, excluded.jsonl
    local build_dir
    build_dir=$(ls -d "$WS"/data/profiles/default/*/ 2>/dev/null | sort | tail -1)
    if check "update wrote a default profile build (README: data/profiles/default/*/)" test -n "$build_dir"; then
        check "build has suricata.rules, by-source/, manifest.jsonl, excluded.jsonl" bash -c "cd '$build_dir' && ls -d suricata.rules by-source manifest.jsonl excluded.jsonl"
        suricheck "build suricata.rules loads in suricata -T with 0 errors" pycheck suricata-test "$build_dir/suricata.rules"
        [[ $MODE == offline ]] && suricheck "build has $SURI_EXPORT_RULES rules, unique sids" pycheck rules-count "$build_dir/suricata.rules" --expect "$SURI_EXPORT_RULES" --unique-sids --no-sid 9000006
    fi
    [[ $MODE == offline ]] && suri_latest_link default
    run_step "profile diff default (README, after the first build)" --expect "0 2" --cwd "$WS" -- "$BIN" profile diff default
    want "first diff is a clean message, not an error" test "$LAST_RC" = 0
    want "doctor reports no failed sync" bash -c "! grep -q 'last sync of' '$LAST_LOG'"
    run_step "stats --json" --cwd "$WS" -- "$CAPTURE" "$RUN/stats.json" "$BIN" stats --json

    # ---- search
    if [[ $MODE == offline ]]; then q=FIXTURE; else q=trojan; fi
    run_step "search $q (table)" --cwd "$WS" -- "$BIN" search "$q"
    run_step "search $q --per-logic --json" --cwd "$WS" -- "$CAPTURE" "$RUN/search.json" "$BIN" search "$q" --per-logic --json --limit 100000
    key=$(pycheck json "$RUN/search.json" "rules|results.0.logic_hash" 2>/dev/null) || key=""
    check "search finds rules" test -n "$key"
    run_step "search via $HOME_VAR from another folder" --cwd "$HOME" -- env "$HOME_VAR=$WS" "$BIN" search "$q" --limit 3
    run_step "search with a bad filter is a clear error" --expect "0 2" --cwd "$WS" -- "$BIN" search 'app:'
    if [[ $MODE == offline ]]; then
        check "unique logic count == $SURI_UNIQUE_LOGIC" bash -c "n=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' json '$RUN/search.json' total); echo \"total \$n\"; [[ \$n == $SURI_UNIQUE_LOGIC ]]"
        suricheck "rules failing suricata -T == $SURI_LOAD_FAILS" bash -c "n=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' json-count '$RUN/search.json' 'rules|results' fails_in); echo \"failing \$n\"; [[ \$n == $SURI_LOAD_FAILS ]]"
        run_step "search 'shared dns' --json" --cwd "$WS" -- "$CAPTURE" "$RUN/search-shared.json" "$BIN" search "shared" --per-logic --json
        check "shared rule: one logic listing $SURI_SHARED_SOURCES sources" bash -c "t=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' json '$RUN/search-shared.json' total); n=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' json '$RUN/search-shared.json' 'rules|results.0.sources' --len); echo \"logics \$t, sources \$n\"; [[ \$t == 1 && \$n == $SURI_SHARED_SOURCES ]]"
        run_step "quarantine" --cwd "$WS" -- "$BIN" quarantine
        check "broken rule quarantined ($SURI_QUARANTINE line)" bash -c "grep -q '^$SURI_QUARANTINE quarantined' '$LAST_LOG' && grep -q 9000005 '$LAST_LOG'"
        run_step "deps" --cwd "$WS" -- "$BIN" deps
        check "deps lists the orphan flowbit $SURI_ORPHAN_BIT" grep -q "$SURI_ORPHAN_BIT" "$LAST_LOG"
        check "deps does not list fx.login (it has a setter)" bash -c "! grep -A50 'checked but never set' '$LAST_LOG' | grep -q 'fx.login '"
    else
        check "ET Open + trafficid give >= 20000 logics" bash -c "n=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' json '$RUN/stats.json' 'logic_groups|unique_logic' 2>/dev/null || '$TOOL_PY' -I '$HARNESS/lib/checks.py' json '$RUN/search.json' total); echo \"logics \$n\"; [[ \$n -ge 20000 ]]"
    fi

    # ---- show
    if [[ -n $key ]]; then
        run_step "show ${key:0:10}" --cwd "$WS" -- "$BIN" show "${key:0:10}"
        check "show prints the rule text" grep -qE '(alert|drop|pass) [a-z0-9-]+ ' "$LAST_LOG"
    fi
    if [[ $MODE == offline ]]; then
        run_step "show 9000002 (by sid)" --cwd "$WS" -- "$BIN" show 9000002
        run_step "show fixture-suri-alpha:1:9000004 (namespace:gid:sid)" --cwd "$WS" -- "$BIN" show fixture-suri-alpha:1:9000004
        check "show of a flowbit checker names its setter dependency" grep -q "fx.login" "$LAST_LOG"
    fi
    run_step "show unknown is a clear error" --expect "1 2" --cwd "$WS" -- "$BIN" show 999999999

    # ---- exports
    run_step "export (defaults)" --expect "0 2" --cwd "$WS" -- "$BIN" export --out "$ex/plain"
    if [[ $LAST_RC == 0 ]]; then
        check "default export: no duplicate sids" pycheck rules-count "$ex/plain/suricata.rules" --min 1 --unique-sids
        suricheck "default export loads in suricata -T with 0 errors" pycheck suricata-test "$ex/plain/suricata.rules"
    else
        check "default export refusal explains the sid collision and the fix" grep -qiE 'remap|collid|collision' "$LAST_LOG"
    fi
    run_step "export --unit logic --remap-colliding-sids --by-source" --cwd "$WS" -- \
        "$BIN" export --out "$ex/merged" --unit logic --remap-colliding-sids --by-source
    local export_log=$LAST_LOG
    if [[ $MODE == offline ]]; then
        suricheck "merged file has $SURI_EXPORT_RULES rules, unique sids, no broken/failing rule" \
            pycheck rules-count "$ex/merged/suricata.rules" --expect "$SURI_EXPORT_RULES" --unique-sids --no-sid 9000005 --no-sid 9000006 --has-sid 9000003
        suricheck "merged file loads: $SURI_EXPORT_RULES rules, 0 failed (suricata -T)" pycheck suricata-test "$ex/merged/suricata.rules" --expect-loaded "$SURI_EXPORT_RULES"
        check "manifest.jsonl records $SURI_REMAPPED remapped sid" bash -c "n=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' jsonl-differ '$ex/merged/manifest.jsonl' exported_sid sid); echo \"remapped \$n\"; [[ \$n == $SURI_REMAPPED ]]"
        check "export warns about the bit without setter" grep -q "$SURI_ORPHAN_BIT" "$export_log"
        want "sid map persisted in state/sid-map.tsv" test -s "$WS/state/sid-map.tsv"
    else
        suricheck "merged file loads in suricata -T with 0 errors" pycheck suricata-test "$ex/merged/suricata.rules"
    fi
    check "manifest.jsonl parses" pycheck jsonl "$ex/merged/manifest.jsonl" --min 1 --keys "sid,logic_hash"
    local f total=0 n
    for f in "$ex"/merged/by-source/*.rules; do
        [[ -e $f ]] || { check "by-source files written" false; break; }
        suricheck "by-source $(basename "$f") loads in suricata -T" pycheck suricata-test "$f" --allow-empty
        n=$(pycheck rules-count "$f" | awk '{print $2}')
        total=$((total + n))
    done
    check "by-source files partition the merged file" bash -c "m=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' rules-count '$ex/merged/suricata.rules' | awk '{print \$2}'); echo \"merged \$m, by-source sum $total\"; [[ \$m == $total ]]"
    run_step "export --redistributable-only" --cwd "$WS" -- "$BIN" export --out "$ex/redistributable" --unit logic --remap-colliding-sids --redistributable-only
    suricheck "redistributable export loads in suricata -T" pycheck suricata-test "$ex/redistributable/suricata.rules"
    run_step "export --format suricata-update" --cwd "$WS" -- "$BIN" export --out "$ex/suricata-update" --format suricata-update --remap-colliding-sids
    check "suricata-update files written" bash -c "ls '$ex/suricata-update' && test -n \"\$(ls '$ex/suricata-update')\""
    for f in "$ex"/suricata-update/*.rules; do
        [[ -e $f ]] && suricheck "suricata-update $(basename "$f") loads in suricata -T" pycheck suricata-test "$f" --allow-empty
    done
    run_step "export --profile default" --cwd "$WS" -- "$BIN" export --out "$ex/profile-default" --profile default --remap-colliding-sids
    suricheck "profile export loads in suricata -T" pycheck suricata-test "$ex/profile-default/suricata.rules"
    run_step "export --format bogus is a clear error" --expect "1 2" --cwd "$WS" -- "$BIN" export --out "$ex/bad" --format bogus

    # ---- builds + diff (the 'diff' export)
    run_step "profile build default (#1)" --cwd "$WS" -- "$BIN" profile build default
    local build1
    build1=$(sed -nE 's/^build ([^ ]+ #)?([0-9]+).*/\2/p' "$LAST_LOG" | head -1)  # "build default #3" (older: "build 3")
    if [[ $MODE == offline ]]; then
        run_step "fixture: upstream bumps sid 9000002 to rev 3" -- python3 -I "$HARNESS/lib/make_fixtures.py" suricata-bump "$fx"
        run_step "update (picks up the new rev)" --cwd "$WS" -- "$BIN" update
    fi
    run_step "profile build default (#2)" --cwd "$WS" -- "$BIN" profile build default
    run_step "profile builds default" --cwd "$WS" -- "$BIN" profile builds default
    # `update` also writes a build of every profile, so compare against the build made before the upstream change.
    run_step "profile diff default ${build1:-previous} latest --json" --cwd "$WS" -- "$CAPTURE" "$RUN/diff.json" "$BIN" profile diff default "${build1:-previous}" latest --json
    if [[ $MODE == offline ]]; then
        check "diff shows $SURI_DIFF_CHANGED changed rule (9000002 rev 2 -> 3)" bash -c "n=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' json '$RUN/diff.json' changed --len); echo \"changed \$n\"; [[ \$n == $SURI_DIFF_CHANGED ]] && grep -q 9000002 '$RUN/diff.json'"
        suricheck "diff: nothing added or removed" bash -c "a=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' json '$RUN/diff.json' added --len); r=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' json '$RUN/diff.json' removed --len); echo \"added \$a removed \$r\"; [[ \$a == 0 && \$r == 0 ]]"
        run_step "show 9000002 lists the rev history" --cwd "$WS" -- "$BIN" show 9000002
        want "rev history shows rev 2 and rev 3" bash -c "grep -qE 'rev[: ]*2' '$LAST_LOG' && grep -qE 'rev[: ]*3' '$LAST_LOG'"
    else
        check "diff of two builds with no change is empty" bash -c "n=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' json '$RUN/diff.json' changed --len); echo \"changed \$n\"; [[ \$n == 0 ]]"
    fi
    if [[ $MODE == offline ]]; then
        suri_latest_link default
        suri_import_conf
        run_step "release build --engine local" --cwd "$WS" -- "$BIN" release build "$ex/release" --engine local --build-epoch 1767225600 --no-gates
        suri_release_checks "$ex/release"
        suri_majors
    else
        run_step "release build (DESIGN.md contract)" --soft --cwd "$WS" -- "$BIN" release build "$ex/release" --engine local --build-epoch 1767225600 --no-gates
    fi
    KEY=$key
}

# ------------------------------------------------------------------------------------------------ v3 additions
# Features added after the first harness (CHANGELOG 0.1.0): the build `latest` link, profile import-conf and
# overrides (enable / modify / thresholds), release build with LICENSES/ and licence headers, per-major rulesets,
# the JSON API. Offline mode only (exact numbers from expected/suriharvest-offline.env).

suri_latest_link() { # PROFILE : latest (symlink or LATEST file) names the newest build folder
    local prof=$1 dir="$WS/data/profiles/$1"
    check "profile $prof: 'latest' points at the newest build" bash -c "
        cd '$dir' || exit 1
        newest=\$(ls -d [0-9]*Z/ [0-9]*Z-*/ 2>/dev/null | sed 's:/\$::' | sort -V | tail -1)  # two builds in one second: <stamp>-2 (slash dropped first: '-' sorts before '/')
        [[ -n \$newest ]] || { echo 'no build folder'; exit 1; }
        if [[ -L latest ]]; then t=\$(readlink latest); t=\${t%/}; t=\${t##*/}; else t=''; fi
        f=\$(tr -d '[:space:]' < LATEST 2>/dev/null); f=\${f%/}; f=\${f##*/}
        echo \"newest \$newest, latest -> \${t:-none}, LATEST \${f:-none}\"
        [[ \$t == \"\$newest\" || \$f == \"\$newest\" ]] || exit 1
        [[ -z \$t || -z \$f || \$t == \"\$f\" ]] || { echo 'latest and LATEST disagree'; exit 1; }
        cmp -s latest/suricata.rules \"\$newest/suricata.rules\" || { echo 'latest/suricata.rules is not the newest build'; exit 1; }"
}

suri_write_confs() { # DIR : sample suricata-update configuration
    local conf=$1
    mkdir -p "$conf"
    {
        echo '# disable.conf (suricata-update syntax)'
        echo '9000002            # by sid (trailing comment is stripped)'
        echo '1:9000003          # gid:sid: the flowbit setter; enable.conf turns it back on'
        echo 're:collide\.fixture'
        echo 'filename:fixture-beta.rules'
    } >"$conf/disable.conf"
    printf '9000003\n' >"$conf/enable.conf"
    printf '9000003\n9000004\n' >"$conf/drop.conf"
    {
        echo '9000008 "shared\.fixture\.invalid" "shared.fixture.example"'
        echo '9000001 "flow:established,to_server;" "flow:established,to_server; zzbogus:1;"'
    } >"$conf/modify.conf"
}

suri_import_conf() {
    local conf="$RUN/suricata-update-conf" b="$WS/data/profiles/imported/latest" ov="$WS/exclusions/imported.yaml" log
    suri_write_confs "$conf"
    run_step "profile create imported --engine local" --cwd "$WS" -- "$BIN" profile create imported --engine local --description "migrated from suricata-update"
    run_step "profile import-conf imported DIR --dry-run" --cwd "$WS" -- "$BIN" profile import-conf imported "$conf" --dry-run
    check "dry run changes nothing" bash -c "grep -q 'dry run' '$LAST_LOG' && ! grep -q 'value:' '$ov' 2>/dev/null"
    run_step "profile import-conf imported DIR" --cwd "$WS" -- "$BIN" profile import-conf imported "$conf"
    check "import: $SURI_IMPORT_EXCLUSIONS exclusions, 1 enable; the filename: line listed as not imported (file:line)" bash -c "grep -Eq '$SURI_IMPORT_EXCLUSIONS exclusions?(\(s\))?, 1 enable' '$LAST_LOG' && grep -q 'not imported: disable.conf:5' '$LAST_LOG'"
    check "enable.conf line beats disable.conf (beats_exclusions: true)" grep -q 'beats_exclusions: true' "$ov"
    run_step "profile import-conf again (idempotent)" --cwd "$WS" -- "$BIN" profile import-conf imported "$conf"
    check "second import reports nothing added (docs: importing twice adds nothing new)" grep -q ': 0 new entries (0 exclusions, 0 enable, 0 modify)' "$LAST_LOG"
    check "second import did not duplicate entries" bash -c "n=\$(grep -c 'reason: imported from disable.conf' '$ov'); echo \"\$n exclusions in the file\"; [[ \$n == $SURI_IMPORT_EXCLUSIONS ]]"
    # overrides by hand: a modify that removes a flowbit setter others need (must be refused), thresholds
    check "add overrides to exclusions/imported.yaml (modify + thresholds)" bash -c "
        '$TOOL_PY' -I '$HARNESS/lib/checks.py' yaml-add '$ov' modify '[{\"kind\":\"sid\",\"value\":\"9000003\",\"from\":\"flowbits:set,fx.login; \",\"to\":\"\",\"reason\":\"acceptance: removes a needed setter, must be refused\"}]' &&
        '$TOOL_PY' -I '$HARNESS/lib/checks.py' yaml-add '$ov' thresholds '[{\"kind\":\"sid\",\"value\":\"9000004\",\"filter\":\"suppress\",\"track\":\"by_src\",\"ip\":\"\$HOME_NET\"},{\"kind\":\"sid\",\"value\":\"9000001\",\"filter\":\"threshold\",\"type\":\"limit\",\"track\":\"by_src\",\"count\":1,\"seconds\":60},{\"kind\":\"source\",\"value\":\"fixture-suri-beta\",\"filter\":\"event_filter\",\"type\":\"both\",\"track\":\"by_dst\",\"count\":5,\"seconds\":300}]'"
    run_step "profile exclusions imported (reads the edited file)" --cwd "$WS" -- "$BIN" profile exclusions imported
    check "no override reported as 'not applied'" bash -c "! grep -qi 'not applied' '$LAST_LOG'"
    run_step "profile build imported" --cwd "$WS" -- "$BIN" profile build imported
    log=$LAST_LOG
    check "build reports: noalert setter not dropped, 2 modify refusals, $SURI_THRESHOLD_LINES threshold lines" bash -c "
        grep -q 'noalert rule(s)' '$log' && grep -q 'modify refused: .*9000001: the modified rule does not load' '$log' &&
        grep -q 'modify refused: .*9000003: it removes the setter of flowbits:fx.login' '$log' && grep -q '$SURI_THRESHOLD_LINES threshold.config lines' '$log'"
    check "imported build has $SURI_IMPORTED_RULES rules, unique sids" pycheck rules-count "$b/suricata.rules" --expect "$SURI_IMPORTED_RULES" --unique-sids
    check "disable.conf: 9000002 left out" pycheck rule-line "$b/suricata.rules" 9000002 --absent
    check "disable.conf re: beta's colliding rule left out" bash -c "! grep -q 'collide.fixture.invalid' '$b/suricata.rules'"
    check "enable.conf re-enables the flowbit setter 9000003, still alert + noalert (drop.conf skips it)" pycheck rule-line "$b/suricata.rules" 9000003 --action alert --contains 'flowbits:set,fx.login;' --contains 'flowbits:noalert;'
    check "drop.conf: 9000004 is drop, marked modified" pycheck rule-line "$b/suricata.rules" 9000004 --action drop --contains 'suriharvest_modified'
    check "modify.conf: 9000008 rewritten, marked modified" pycheck rule-line "$b/suricata.rules" 9000008 --contains 'shared.fixture.example' --contains 'suriharvest_modified' --lacks 'shared.fixture.invalid'
    check "refused modify: 9000001 written unmodified" pycheck rule-line "$b/suricata.rules" 9000001 --lacks zzbogus --lacks suriharvest_modified
    check "excluded.jsonl gives the disable.conf reason" grep -q 'imported from disable.conf' "$b/excluded.jsonl"
    check "manifest.jsonl marks the 2 modified rules" bash -c "n=\$(grep -cE '\"modified\": *true' '$b/manifest.jsonl'); echo \"modified \$n\"; [[ \$n == 2 ]]"
    check "threshold.config: $SURI_THRESHOLD_LINES lines with the build's sids" bash -c "
        f='$b/threshold.config'; n=\$(grep -cvE '^[[:space:]]*(#|\$)' \"\$f\"); echo \"\$n lines\"; [[ \$n == $SURI_THRESHOLD_LINES ]] &&
        grep -qF 'suppress gen_id 1, sig_id 9000004, track by_src, ip \$HOME_NET' \"\$f\" && grep -q 'sig_id 9100001' \"\$f\""
    suricheck "imported build + threshold.config load in suricata -T" pycheck suricata-test "$b/suricata.rules" --expect-loaded "$SURI_IMPORTED_RULES" --threshold-file "$b/threshold.config"
    # a broken entry is reported and left out; the other entries still apply
    cp "$b/threshold.config" "$RUN/threshold.before"
    check "add a broken threshold (count 0)" pycheck yaml-add "$ov" thresholds '[{"kind":"sid","value":"9000008","filter":"threshold","type":"limit","track":"by_src","count":0,"seconds":60}]'
    run_step "profile build imported (broken threshold entry)" --expect "0 1" --cwd "$WS" -- "$BIN" profile build imported
    check "broken entry reported as not applied" grep -qi 'not applied' "$LAST_LOG"
    check "the valid thresholds still apply" bash -c "d='$WS/data/profiles/imported'; f=\$(tr -d '[:space:]' < \"\$d/LATEST\"); grep -v '^#' \"\$d/\$f/threshold.config\" | cmp -s - <(grep -v '^#' '$RUN/threshold.before')"
    suricheck "build with the broken entry still loads in suricata -T" pycheck suricata-test "$b/suricata.rules" --threshold-file "$b/threshold.config"
    suri_latest_link imported
}

suri_release_checks() { # DIR
    local rel=$1 f merged loose=() total=0 n before tgz
    [[ -d $rel ]] || { check "release folder written" false; return; }
    check "release SHA256SUMS verify" bash -c "cd '$rel' && sha256sum --check --quiet SHA256SUMS"
    merged=$(ls "$rel"/suricata-*.rules 2>/dev/null | grep -v '\.by-source\.' | head -1)
    check "release has a merged suricata-N.rules" test -n "$merged" || return
    for f in "$rel"/suricata-*.rules; do loose+=("$f"); done
    # enabled rules before the headers (the default profile build: same selection, no licence header) and after
    before=$(pycheck rules-count "$WS/data/profiles/default/latest/suricata.rules" | awk '{print $2}')
    check "release merged file: $SURI_RELEASE_RULES active rules (profile build without headers: $before)" \
        bash -c "n=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' rules-count '$merged' | awk '{print \$2}'); echo \"release \$n, profile build $before\"; [[ \$n == $SURI_RELEASE_RULES && \$n == $before ]]"
    for f in "${loose[@]}"; do
        suricheck "$(basename "$f"): every active rule loads (headers swallow none)" pycheck suricata-test "$f"
    done
    for f in "$rel"/suricata-*.by-source.*.rules; do
        [[ -e $f ]] || continue
        n=$(pycheck rules-count "$f" | awk '{print $2}'); total=$((total + n))
    done
    check "by-source release files partition the merged file" bash -c "m=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' rules-count '$merged' | awk '{print \$2}'); echo \"merged \$m, by-source sum $total\"; [[ \$m == $total ]]"
    check "no comment line in a release rules file ends in a backslash" pycheck comment-continuations "${loose[@]}"
    check "beta's notice kept on top of its by-source file" bash -c "f=\$(ls '$rel'/suricata-*.by-source.fixture-suri-beta.rules); grep -qF '$SURI_COPYRIGHT_BETA' \"\$f\" && grep -q 'C:.fixture.notes' \"\$f\""
    check "merged header: SPDX ids with licence text links, both copyright lines" bash -c "
        h=\$(grep '^#' '$merged'); grep -q 'BSD-2-Clause: full text LICENSES.BSD-2-Clause.txt' <<<\"\$h\" && grep -q 'MIT: full text LICENSES.MIT.txt' <<<\"\$h\" &&
        grep -qF '$SURI_COPYRIGHT_ALPHA' <<<\"\$h\" && grep -qF '$SURI_COPYRIGHT_BETA' <<<\"\$h\""
    check "licence texts as loose assets" bash -c "test -s '$rel/LICENSES.MIT.txt' && test -s '$rel/LICENSES.BSD-2-Clause.txt'"
    check "NOTICE.md lists both publishers' copyright lines" bash -c "grep -qF '$SURI_COPYRIGHT_ALPHA' '$rel/NOTICE.md' && grep -qF '$SURI_COPYRIGHT_BETA' '$rel/NOTICE.md'"
    check "LICENSES.tar.gz: each source's LICENSE + SPDX texts + INDEX.md" pycheck archive "$rel/LICENSES.tar.gz" --has LICENSES/fixture-suri-alpha/LICENSE --has LICENSES/fixture-suri-beta/LICENSE --has LICENSES/INDEX.md --has LICENSES/texts/ --grep "LICENSES/fixture-suri-beta/LICENSE=$SURI_COPYRIGHT_BETA"
    tgz=$(ls "$rel"/suriharvest-*.tar.gz 2>/dev/null | head -1)
    if check "suricata-update tarball written" test -n "$tgz"; then
        check "tarball: rules/suricata.rules, NOTICE.md, LICENSES/" pycheck archive "$tgz" --has rules/suricata.rules --has NOTICE.md --has LICENSES/
        rm -rf "$RUN/release-tgz"; mkdir -p "$RUN/release-tgz"; tar -xzf "$tgz" -C "$RUN/release-tgz"
        f=$(find "$RUN/release-tgz" -path '*rules/suricata.rules' | head -1)
        [[ -n $f ]] && suricheck "tarball rules/suricata.rules loads: $SURI_RELEASE_RULES rules (suricata -T)" pycheck suricata-test "$f" --expect-loaded "$SURI_RELEASE_RULES"
        [[ -n $f ]] && check "tarball rules file: no comment line ends in a backslash" pycheck comment-continuations "$f"
    fi
}

suri_majors() {
    local ws="$RUN/ws-majors" fx="$RUN/fixture-majors" rel="$RUN/exports/release-majors" fake="$RUN/fake-engines/suricata-8" real port url others up=0
    real=$(command -v suricata)
    mkdir -p "$(dirname "$fake")"
    {
        echo '#!/bin/sh'
        echo '# Fake Suricata 8 for the acceptance harness: answers -V with version 8.0.0, validates with the real binary.'
        echo "if [ \"\$1\" = \"-V\" ]; then echo \"This is Suricata version 8.0.0 RELEASE (acceptance fake over $real)\"; exit 0; fi"
        echo "exec \"$real\" \"\$@\""
    } >"$fake"
    chmod +x "$fake"
    run_step "majors: per-major fixture files" -- python3 -I "$HARNESS/lib/make_fixtures.py" suricata-major "$fx"
    port=$(free_port)
    (cd "$fx/fixture-major" && exec python3 -I -m http.server --bind 127.0.0.1 "$port") >"$RUN/logs/http-fixture.log" 2>&1 </dev/null &
    EXTRA_PIDS+=" $!"
    for _ in $(seq 1 50); do curl -fsS -o /dev/null "http://127.0.0.1:$port/suricata-7/fixture-major.rules" 2>/dev/null && { up=1; break; }; sleep 0.1; done
    check "majors: fixture HTTP server on 127.0.0.1:$port" test $up = 1 || return
    url="http://127.0.0.1:$port/suricata-\${suricata_version}/fixture-major.rules"
    run_step "majors: init --engine suricata-7=BIN --engine suricata-8=FAKE" --cwd "$HOME" -- "$BIN" init "$ws" --engine "suricata-7=$real" --engine "suricata-8=$fake"
    run_step "majors: sources add http-file URL with \${suricata_version} (+ --copyright)" --cwd "$ws" -- "$BIN" sources add fixture-major "$url" \
        --type http-file --licence MIT --redistribute yes --tier core --copyright "Copyright (c) 2026 Major Fixture Publisher"
    others=$(pycheck sources "$ws/sources.yaml" --enabled --keep fixture-major)
    # shellcheck disable=SC2086
    [[ -n $others ]] && run_step "majors: disable the other sources" --cwd "$ws" -- "$BIN" sources disable $others
    check "majors: only fixture-major enabled" bash -c "[[ -z \$('$TOOL_PY' -I '$HARNESS/lib/checks.py' sources '$ws/sources.yaml' --enabled --keep fixture-major) ]]" || return
    run_step "majors: update (one download per major, validate on both engines)" --cwd "$ws" -- "$BIN" update
    check "majors: one copy per major (corpus/fixture-major/@7, @8)" bash -c "test -s '$ws/corpus/fixture-major/@7/fixture-major.rules' && test -s '$ws/corpus/fixture-major/@8/fixture-major.rules'"
    run_step "majors: search --per-logic --json" --cwd "$ws" -- "$CAPTURE" "$RUN/majors.json" "$BIN" search FIXTURE --per-logic --json
    check "majors: $SURI_MAJOR_LOGICS logics (shared rule is one logic)" bash -c "n=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' json '$RUN/majors.json' total); echo \"total \$n\"; [[ \$n == $SURI_MAJOR_LOGICS ]]"
    check "majors: default profile (engine suricata-7) builds the 7 copy" bash -c "f='$ws/data/profiles/default/latest/suricata.rules'; grep -q 'major-v7' \"\$f\" && ! grep -q 'major-v8' \"\$f\" && ! grep -q 'sid:9200003;' \"\$f\""
    run_step "majors: release build --engine suricata-7 --engine suricata-8" --cwd "$ws" -- "$BIN" release build "$rel" --engine suricata-7 --engine suricata-8 --build-epoch 1767225600
    [[ -f $rel/suricata-7.rules && -f $rel/suricata-8.rules ]] || { check "majors: suricata-7.rules and suricata-8.rules written" false; return; }
    check "majors: suricata-7.rules = $SURI_MAJOR_7 rules (no 8-only rule)" pycheck rules-count "$rel/suricata-7.rules" --expect "$SURI_MAJOR_7" --has-sid 9200001 --has-sid 9200002 --no-sid 9200003 --unique-sids
    check "majors: suricata-7.rules has the v7 text of 9200002" pycheck rule-line "$rel/suricata-7.rules" 9200002 --contains major-v7 --lacks major-v8
    check "majors: suricata-8.rules = $SURI_MAJOR_8 rules (+ 8-only rule)" pycheck rules-count "$rel/suricata-8.rules" --expect "$SURI_MAJOR_8" --has-sid 9200001 --has-sid 9200003 --unique-sids
    check "majors: suricata-8.rules has the v8 text of 9200002" pycheck rule-line "$rel/suricata-8.rules" 9200002 --contains major-v8 --lacks major-v7
    check "majors: the shared rule keeps its sid in both files" bash -c "grep -q 'major-shared.*sid:9200001;' '$rel/suricata-7.rules' && grep -q 'major-shared.*sid:9200001;' '$rel/suricata-8.rules'"
    suricheck "majors: suricata-7.rules loads" pycheck suricata-test "$rel/suricata-7.rules" --expect-loaded "$SURI_MAJOR_7"
    suricheck "majors: suricata-8.rules loads" pycheck suricata-test "$rel/suricata-8.rules" --expect-loaded "$SURI_MAJOR_8"
    check "majors: the --copyright line is in the merged header" grep -q 'fixture-major: Copyright (c) 2026 Major Fixture Publisher' "$rel/suricata-8.rules"
}

suri_api() { # URL
    local url=$1 c="$TOOL_PY -I $HARNESS/lib/checks.py"
    check "GET /api/search?q=FIXTURE&all=1 total == CLI search --per-logic ($SURI_UNIQUE_LOGIC)" bash -c "
        '$TOOL_PY' -I '$HARNESS/lib/checks.py' http '$url/api/search?q=FIXTURE&all=1&limit=200' --kind json --save '$RUN/api-search.json' >/dev/null || exit 1
        a=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' json '$RUN/api-search.json' total); c=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' json '$RUN/search.json' total)
        r=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' json '$RUN/api-search.json' 'results|rules' --len)
        echo \"api \$a (\$r rows), cli \$c\"; [[ \$a == \$c && \$a == $SURI_UNIQUE_LOGIC && \$r == \$a ]]"
    check "GET /api/search limit=3&offset=3: 3 rows, offset and limit echoed" bash -c "
        '$TOOL_PY' -I '$HARNESS/lib/checks.py' http '$url/api/search?q=FIXTURE&all=1&limit=3&offset=3' --kind json --save '$RUN/api-page2.json' >/dev/null || exit 1
        r=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' json '$RUN/api-page2.json' 'results|rules' --len); o=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' json '$RUN/api-page2.json' offset); l=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' json '$RUN/api-page2.json' limit)
        echo \"rows \$r offset \$o limit \$l\"; [[ \$r == 3 && \$o == 3 && \$l == 3 ]]"
    check "GET /api/search?q=sid:9000004 finds 1 logic" bash -c "
        '$TOOL_PY' -I '$HARNESS/lib/checks.py' http '$url/api/search?q=sid:9000004&all=1' --kind json --save '$RUN/api-sid.json' >/dev/null || exit 1
        n=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' json '$RUN/api-sid.json' total); echo \"total \$n\"; [[ \$n == 1 ]]"
    check "GET /api/search with an out-of-range sid is 400" "$TOOL_PY" -I "$HARNESS/lib/checks.py" http "$url/api/search?q=sid:99999999999999999999" --kind any --status 400
    check "GET /api/search?limit=0 is 400" "$TOOL_PY" -I "$HARNESS/lib/checks.py" http "$url/api/search?q=FIXTURE&limit=0" --kind any --status 400
    check "GET /api/stats matches stats --json and has version" bash -c "
        a=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' json '$RUN/api-stats.json' 'logic_groups|unique_logic'); c=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' json '$RUN/stats.json' 'logic_groups|unique_logic')
        v=\$('$TOOL_PY' -I '$HARNESS/lib/checks.py' json '$RUN/api-stats.json' version); echo \"api \$a cli \$c version \$v\"; [[ -n \$a && \$a == \$c && -n \$v ]]"
    check "GET /feed/default/local.tar.gz is a suricata-update tarball" bash -c "
        curl -fsS -o '$RUN/feed.tar.gz' '$url/feed/default/local.tar.gz' && tar -tzf '$RUN/feed.tar.gz' | grep -q 'suricata.rules'"
}

tool_web() {
    local port url k
    port=$(free_port)
    url="http://127.0.0.1:$port"
    STEP_N=$((STEP_N + 1))
    local t0; t0=$(_now)
    (cd "$WS" && exec "$BIN" serve --host 127.0.0.1 --port "$port") >"$RUN/logs/server.log" 2>&1 </dev/null &
    SERVER_PID=$!
    local up=0
    for _ in $(seq 1 120); do
        if curl -fsS -o /dev/null "$url/" 2>/dev/null; then up=1; break; fi
        kill -0 "$SERVER_PID" 2>/dev/null || break
        sleep 0.5
    done
    local secs; secs=$(awk -v a="$t0" -v b="$(_now)" 'BEGIN{printf "%.1f", b-a}')
    if [[ $up != 1 ]]; then
        _record FAIL "$secs" "web: start on $url" "$RUN/logs/server.log" "not answering; $(tail -n 3 "$RUN/logs/server.log" | tr '\n' ' ')"
        return
    fi
    _record OK "$secs" "web: start on $url" "$RUN/logs/server.log" "up"
    k=${KEY:-0000000000}
    local q=FIXTURE; [[ $MODE == online ]] && q=trojan
    http_get "GET /" "$url/"
    http_get "GET /workflow" "$url/workflow"
    http_get "GET /search?q=$q" "$url/search?q=$q"
    http_get "GET /search?q=$q&all=1&page=2" "$url/search?q=$q&all=1&page=2"
    http_get "GET /search (empty)" "$url/search"
    if [[ -n ${KEY:-} ]]; then http_get "GET /rule/<logic_hash>" "$url/rule/$k"; else skip "GET /rule/<logic_hash>" "no rule key"; fi
    http_get "GET /sources" "$url/sources"
    http_get "GET /runs" "$url/runs"
    http_get "GET /runs/1" "$url/runs/1"
    http_get "GET /doctor" "$url/doctor"
    http_get "GET /help" "$url/help"
    http_get "GET /profiles/default/exclusions" "$url/profiles/default/exclusions"
    http_get "GET /profiles/default/new" "$url/profiles/default/new"
    http_get "GET /profiles/default/diff" "$url/profiles/default/diff"
    http_get "GET /static/app.js" "$url/static/app.js" any
    check "GET /api/search (JSON API)" "$TOOL_PY" -I "$HARNESS/lib/checks.py" http "$url/api/search?q=$q" --kind json
    check "GET /api/stats (JSON API)" "$TOOL_PY" -I "$HARNESS/lib/checks.py" http "$url/api/stats" --kind json --save "$RUN/api-stats.json"
    [[ $MODE == offline ]] && suri_api "$url"
    check "GET /rule/<unknown> is 404, not 500" "$TOOL_PY" -I "$HARNESS/lib/checks.py" http "$url/rule/deadbeefdeadbeef" --kind any --status 404
    check "GET /search?q=<script> does not reflect raw HTML" bash -c "! curl -fsS '$url/search?q=%3Cscript%3Ealert(1)%3C/script%3E' | grep -q '<script>alert(1)'"
    check "cross-site POST refused" bash -c "code=\$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Origin: http://evil.invalid' '$url/jobs/update'); echo \"HTTP \$code\"; [[ \$code == 403 ]]"
    check "Host header check (DNS rebinding)" bash -c "code=\$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: evil.invalid' '$url/'); echo \"HTTP \$code\"; [[ \$code == 400 || \$code == 403 || \$code == 421 ]]"
    run_step "serve refuses a non-loopback bind without a token" --expect "1 2" --cwd "$WS" -- "$BIN" serve --host 0.0.0.0 --port "$(free_port)"
    if [[ $KEEP_SERVER == 1 ]]; then log "server left running: $url (pid $SERVER_PID)"; SERVER_PID=""; return; fi
    kill "$SERVER_PID" 2>/dev/null; wait "$SERVER_PID" 2>/dev/null; SERVER_PID=""
    check "server log has no traceback" bash -c "! grep -E '$BAD_OUTPUT_RE' '$RUN/logs/server.log'"
    check "port released after stop" bash -c "! curl -s -o /dev/null '$url/'"
}
