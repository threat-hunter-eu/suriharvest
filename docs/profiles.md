# Profiles, exclusions, builds and diffs

A **profile** is a named ruleset to build, e.g. `default` (made by `init`), `ioc-only`, `no-info`,
`suricata8`. Its candidate rules are a search query; exclusions remove what you do not want, each with a reason.

<!-- doctest -->
```bash
suriharvest profile create no-info --query 'ioc:no' --engine local --description 'behaviour rules only'
suriharvest profile suggest no-info                          # what is usually left out, with counts and examples
suriharvest profile preview 'ET INFO' --kind category        # what an exclusion would hit
suriharvest profile exclude no-info 'ET INFO' --kind category --reason 'policy noise' --review 2027-05-01
suriharvest profile new no-info                              # rules not in the last build yet
suriharvest profile build no-info                            # data/profiles/no-info/<UTC time>Z/ and .../latest
suriharvest profile builds no-info
suriharvest profile diff no-info                             # previous -> latest (or: diff no-info 3 7 --json)
suriharvest profile set no-info --redistributable-only       # only sources with redistribute: yes
suriharvest profile remove no-info --yes                     # delete it: exclusions, overrides, build records and folders
```

`profile remove` keeps the exclusions file as `exclusions/<name>.yaml.removed` and, with `--keep-files`, the
build folders. `--engine` must be an engine named in `suriharvest.yaml` (`local` after a plain `init`).

## Candidates

The query (search syntax) picks the candidates; `unit` is `logic` (every unique logic) or `family` (the best of
each family). By default only rules their publisher ships enabled are candidates (`--include-disabled` changes
that). With `--engine NAME`, rules that do not load in that engine are left out. When the same rule (same
publisher rule key) is present in several revisions, only the newest is kept; on equal revisions the better
source priority wins, then the higher score, then the logic hash, so the choice never depends on query order.

## Exclusion kinds

| kind | matches |
|---|---|
| `msg_contains` | part of the rule name, case-sensitive (default) |
| `msg_exact` | the whole name |
| `msg_regex` | Python regular expression on the name, case-insensitive |
| `rule_regex` | Python regular expression on the whole rule text, case-insensitive |
| `file` | rule file name (shell pattern), with or without `.rules`, or its path in the source |
| `sid` | a sid, any gid, any namespace |
| `rule_key` | `namespace:gid:sid` |
| `logic` | a logic hash (prefix) |
| `category` | name category: "ET INFO", "GPL NETBIOS", or the first word of the name |
| `classtype` | a classtype |
| `source` | rules only that source carries |
| `query` | any search query; future matching rules are excluded too |

Regular expressions (`msg_regex`, `rule_regex`, suricata-update `re:` lines) see the first 8 KiB of the text:
Suricata does not load a longer rule, and Python's backtracking `re` would otherwise let one hostile 256 KiB
rule stall every build. With [google-re2](https://pypi.org/project/google-re2/) installed next to suriharvest
(`uv tool install git+https://github.com/threat-hunter-eu/suriharvest --with google-re2`), patterns RE2 supports run in linear time; the others
(back-references, look-arounds) keep using `re`. The selected rules are the same either way.

An exclusion only changes a build when the rule is a candidate: a rule its publisher ships disabled (most
deprecated ET rules, e.g. sid 2013028) is already out unless the profile has `--include-disabled`, so excluding it
changes nothing; `profile exclude` says so when it happens. `profile build` reports what each exclusion removed (`excluded by: sid 1`; `--json` for the whole summary) and
`profile diff` shows the rule leaving.

`profile exclude all ...` adds an exclusion for every profile. The rule keys an exclusion matched are remembered,
so a rule the publisher renames stays excluded.

## Build output

`profile build` writes `suricata.rules`, `by-source/<source>.rules`, `manifest.jsonl` (source, licence,
redistribute, original and exported sid), `excluded.jsonl` (every rule left out, with the reason),
`logic_hashes.txt` and `changes.json`. Flowbit setters a selected rule needs are added automatically unless you
excluded them. Rules of different publishers that share a gid:sid get stable new sids (see [sids.md](sids.md)).

## Overrides: enable, modify, thresholds

Local changes that must survive every update live in the profile, never in the rule files. They are kept in
`exclusions/<profile>.yaml` next to the exclusions (edit the file; the next build, update or `profile exclusions`
reads it) and applied at every build, so a new upstream revision gets the same treatment. Each entry selects
rules with the same `kind` / `value` pairs as exclusions (`sid`, `rule_key`, `msg_regex`, `rule_regex`,
`category`, `classtype`, `source`, `file`, `metadata`, `query`, ...). Exclusions win: an excluded rule is not
enabled, modified or thresholded (the build lists an enable entry an exclusion wins over under `exclusion wins
over`), except for enable entries with `beats_exclusions: true`, which `import-conf` writes for enable.conf
because suricata-update re-enables what disable.conf disables. For example, appended to `exclusions/default.yaml`:

<!-- doctest: write exclusions/default.yaml -->
```yaml
enable:          # rules their publisher ships commented out become candidates
- {kind: sid, value: '2013028', reason: we run this policy}
modify:          # in file order; each entry is checked alone
- {kind: category, value: ET MALWARE, action: drop, reason: IPS}         # alert -> drop (alert rules, not noalert)
- {kind: sid, value: '2019401', from: 'seconds \d+', to: 'seconds 3600'} # Python regex, \1 back-references
thresholds:      # written to threshold.config next to suricata.rules
- {kind: sid, value: '2013028', filter: suppress, track: by_src, ip: '$HOME_NET'}
- {kind: sid, value: '2210000', filter: threshold, type: limit, track: by_src, count: 1, seconds: 60}
- {kind: sid, value: '2210001', filter: event_filter, type: both, track: by_dst, count: 5, seconds: 300}
- {kind: category, value: ET SCAN, filter: rate_filter, track: by_src, count: 50, seconds: 60, new_action: drop, timeout: 600}
```

<!-- doctest -->
```bash
suriharvest profile exclusions default                 # reads the file; reports entries it cannot apply
suriharvest profile build default                      # applies enable / modify / thresholds
cat data/profiles/default/latest/threshold.config
```

- A modified rule gets `metadata:suriharvest_modified true;` and `"modified": true` in `manifest.jsonl`.
- `action` changes only `alert` rules, and never a rule with `noalert` (a flowbit setter): a dropping setter
  would block traffic without ever logging an alert. suricata-update's drop.conf skips them the same way; the
  build counts them (`noalert rule(s) ... not changed`).
- A rewrite that makes the rule unreadable, splits it over two lines (a newline or other control character,
  also from a `\n` in `to`), changes its gid:sid, or removes a flowbit setter that other rules of the build
  check is refused and reported (`modify refused`); the rule is written without that entry. Rewritten rules are
  also run through the profile's engine (`suricata -T`, cached per text in `data/modified-rules-validation.json`)
  and a rule that does not load is written unmodified, so one bad rewrite never breaks the whole file. Fail-safe:
  a rewrite that could not be validated is not applied (the rule ships as published and the build lists it under
  `modify refused`): the profile has no engine (`profile set NAME --engine ...`), the engine cannot run, or the
  rewritten rule loads files (datasets). The flowbit closure uses the rewritten
  rules. Entries that match no rule are reported too (`matched no rule`).
- `threshold.config` uses the gid:sid each rule has **in that build**, so remapped sids are right. Point
  Suricata at it with `threshold-file:` in `suricata.yaml` (or `--set threshold-file=...`). `suppress` without
  `track`/`ip` suppresses the rule entirely; `ip` takes an address, a network, one of Suricata's default
  address variables (`$HOME_NET`, `$EXTERNAL_NET`, `$DNS_SERVERS`, ...) or a flat `[list]` of these, without
  `!` (Suricata 7 refuses the whole file on a negation or an undefined variable). `count`, `seconds` and
  `timeout` are whole numbers from 1 to 4294967295.
- A rule that carries its own `threshold:` or `detection_filter:` gets no threshold.config line except
  `suppress` (Suricata would ignore it, with one warning per rule); the build names these rules.
- `suriharvest profile exclusions NAME` lists the overrides after the exclusions, with how many rules each entry
  matched at the last build; the web page of the profile's exclusions shows them too.
- A broken entry is reported (`not applied ... thresholds #4 skipped: ...`, with the entry number) and left out;
  the other entries of the file apply, and the file is left as written until the entry is fixed.
- Overrides apply to `profile build` (and to the builds `update` makes). `export --profile` applies `enable`
  and `modify` too, not thresholds.

## Coming from suricata-update

`profile import-conf` turns an existing suricata-update configuration into profile entries:

<!-- doctest: skip reads the sensor's /etc/suricata -->
```bash
suriharvest profile import-conf default /etc/suricata            # reads enable/disable/drop/modify.conf there
```

Or name the files. With a `disable.conf` and a `modify.conf` like these in the current folder:

<!-- doctest: write disable.conf -->
```
# disable.conf
2052813
1:2013028
re:curl User-Agent
```

<!-- doctest: write modify.conf -->
```
# modify.conf
2019401 "seconds \d+" "seconds 3600"
```

<!-- doctest -->
```bash
suriharvest profile import-conf default --disable disable.conf --modify modify.conf --dry-run   # show, change nothing
suriharvest profile import-conf default --disable disable.conf --modify modify.conf
suriharvest profile exclusions default
```

| suricata-update file | becomes |
|---|---|
| `disable.conf` | exclusions (reason `imported from <file>:<line>`, with the real file name: `--disable sensor1-disable.conf` gives `imported from sensor1-disable.conf:4`) |
| `enable.conf` | `enable` entries with `beats_exclusions: true`: an enable.conf line keeps a rule disable.conf excludes, as in suricata-update |
| `drop.conf` | `modify` entries with `action: drop`; like suricata-update, `noalert` rules (flowbit setters) are never dropped. Unlike suricata-update, only `alert` rules change (a `pass` rule stays `pass`) |
| `modify.conf` | `modify` entries with `from` / `to` (`${1}` becomes `\1`; the oinkmaster `modifysid ... \| ...` form works too) |

Lines are read the way suricata-update reads them: ` #` and everything after it is a comment (also after a
matcher or a modify line), matchers are tried in its order and their prefixes are case-sensitive.
Matchers: `2019401`, `1:2019401`, comma lists of these, `*` (every rule), `re:` (whole rule text,
case-insensitive, kind `rule_regex`), `group:` or a bare `name.rules` (rule file name in any source, shell
patterns, with or without `.rules`, kind `file`), `metadata: key value` (kind `metadata`).

Flowbit setters work as in suricata-update: when an enabled rule checks a flowbit, every rule that sets it and
that disable.conf (or any exclusion) turned off ships anyway, with `noalert` added, and the build names them
(`excluded flowbit setter(s) kept, with noalert`). import-conf sets the profile option for this
(`flowbit_setters: suricata-update`); `suriharvest profile set NAME --flowbit-setters strict` keeps excluded rules
out, and the build then names each bit under `flowbits have no setter`.

One difference remains on purpose: suricata-update applies modify.conf to a rule drop.conf turned into `drop` as a
re-parsed rule without its file, so a `group:` / `*.rules` modify line never matches it and a `re:` line sees the
`drop` text (`re:^drop` matches, `re:^alert` does not). A profile matches every entry on the rule as published,
so such modify lines apply (and `re:^drop` is reported as "matched no rule"). Every line that cannot be converted (another gid, `filename:`, a bad regex, a back-reference
to a missing group, a malformed modify line) is listed with its file and line number and left out; nothing is
dropped silently. Importing twice adds nothing new. `--dry-run` shows the result without changing the profile.
