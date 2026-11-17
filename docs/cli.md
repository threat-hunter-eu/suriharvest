# CLI recipes

Task-oriented examples. Every command has `--help`.

- [The commands at a glance](#the-commands-at-a-glance)
- [Search](#search)
- [Filter syntax](#filter-syntax)
- [Rules for a CVE](#rules-for-a-cve)
- [Read a rule](#read-a-rule)
- [Profiles: your named rulesets](#profiles-your-named-rulesets)
- [Exclusions](#exclusions)
- [Build and diff](#build-and-diff)
- [Export](#export)
- [Sources](#sources)
- [Runs, health and scripting](#runs-health-and-scripting)

## The commands at a glance

| Command | What it does |
|---|---|
| `suriharvest init [PATH]` | Create a workspace (`--preset core\|community\|all`) |
| `suriharvest doctor` | Check the workspace, migrate the database, probe engines |
| `suriharvest update` | Sync, ingest, validate, index, check gates, rebuild profiles |
| `suriharvest sync [NAMES]` | Download sources only (all enabled, or the ones named) |
| `suriharvest validate` | Validate rules on engines (`--engine NAME`) |
| `suriharvest search [QUERY]` | Find rules |
| `suriharvest show REF` | One rule: text, copies, rev history, validation, family |
| `suriharvest stats` | Corpus totals |
| `suriharvest deps` | Flowbits / xbits dependencies |
| `suriharvest quarantine` | Lines that could not be parsed |
| `suriharvest profile ...` | Named rulesets: create, set, exclude, build, diff, remove, import-conf |
| `suriharvest export [QUERY] --out OUT` | Write a ruleset to a folder |
| `suriharvest sources ...` | List, add, import, enable, disable, check sources |
| `suriharvest release build OUT` | Publishable, reproducible release files ([releases.md](releases.md)) |
| `suriharvest site build OUT --release DIR` | Static, read-only site (GitHub Pages) from release files only ([site.md](site.md)) |
| `suriharvest runs ...` | Update runs: list, show, accept |
| `suriharvest serve` | Local web UI on http://127.0.0.1:8077 |
| `suriharvest version` | Print the version, the database schema revision, Python, the main libraries, `suricata` (its version) and suricata-update on PATH, and the workspace's engines by name (not run: `suriharvest doctor` probes them); `suriharvest --version` prints only the version |

## Search

<!-- doctest -->
```bash
suriharvest search 'cobalt strike'
suriharvest search 'cobalt strike app:http ioc:no'
suriharvest search 'source:et-open classtype:trojan-activity severity:major' --limit 100
suriharvest search 'fails:local' --per-logic          # every logic that does not load on the local engine
suriharvest search 'mitre:T1071' --json > t1071.json
```

The query is **one argument**: quote it when it has spaces. Words are matched in the rule message, content,
metadata and references (all words must match, case-insensitive, each word also matches as a prefix). Spelling
variants are the same search: `cobaltstrike`, `cobalt strike` and "CobaltStrike" all find each other (a long
word also matches itself split in two; two words also match their joined form). By default you get one row per
**family** (the same detection written several ways); `--per-logic` lists every unique logic. `--include-junk` includes rules
flagged as junk. Most users want `ioc:no` next to a malware name: without it, single-domain and single-IP
indicator rules make up much of the list.

## Filter syntax

Filters are `key:value` tokens inside the query.

| Filter | Example | Meaning |
|---|---|---|
| `proto:` | `proto:tcp` | rule header protocol |
| `app:` | `app:dns`, `app:tls`, `app:http` | app layer protocol |
| `buffer:` | `buffer:http.uri` | uses this sticky buffer |
| `classtype:` | `classtype:trojan-activity` | classtype |
| `cat:` / `category:` | `cat:malware` | publisher category (e.g. ET file name) |
| `source:` | `source:et-open`, `source:a,b` | carried by this source (comma = OR) |
| `sid:` | `sid:2027865` | exact sid |
| `key:` | `key:et:1:2052813` | exact rule key `namespace:gid:sid`; the namespace is the sid owner (`et` for ET Open, see `show`), not always the source name |
| `ioc:` | `ioc:no`, `ioc:yes`, `ioc:domain` | single-indicator rules (domain, IP, JA3, cert...) vs behaviour rules |
| `enabled:` | `enabled:yes` | enabled by its publisher in at least one source |
| `loads:` / `fails:` | `loads:8.0`, `fails:local` | validation result on an engine (name from `suriharvest.yaml`) |
| `dialect:` | `dialect:snort` | rules written in Snort syntax |
| `redistributable:` | `redistributable:yes` | source allows republishing |
| `severity:` | `severity:major` | publisher `signature_severity` metadata (exact value, case-insensitive) |
| `mitre:` | `mitre:T1071`, `mitre:TA0011` | `mitre_technique_id` / `mitre_tactic_id` metadata (exact id) |
| `perf:` | `perf:low` | publisher `performance_impact` |
| `flag:` | `flag:does_not_load` | quality flag: `does_not_load`, `missing_setter`, `needs_files`, `no_prefilter_content`, `foreign_syntax`, `deleted`, `deprecated`, `retired`, `no_msg`, `no_rev` |
| `verdict:` | `verdict:none` | triage verdict (`keep`, `review`, `drop`, or `none`) |
| `updated>` / `updated<` | `updated>2026-10-01` | last update date |
| `score>=` | `score>=60` | quality score at least N |
| `cve:` | `cve:CVE-2021-44228`, `cve:2021-44228`, `cve:*` | the rule names this CVE (message, `reference:cve,...` or `metadata: cve ...`); a bare `CVE-2021-44228` is the same filter; `cve:*` any CVE |
| `licence:` / `license:` | `licence:permissive` | licence class of the rule: `permissive`, `copyleft`, `restricted` (own use only; also `nc`, `own`), `none` (unknown); ET Open counts per rule (BSD rules permissive, `GPL ...` rules copyleft) |
| `remapped:` | `remapped:yes` | the rule's sid was remapped after a sid clash |
| `metadata:` / `meta:` | `metadata:malware_family=Cobalt_Strike` | a metadata key=value (exact, case-insensitive), or just the key |
| `flowbits:` / `flowbit:` | `flowbits:ET.http.binary` | sets or checks this flowbit or xbit |

Filters combine with AND; a comma means OR only where the table says so (`source:a,b`, `severity:critical,major`;
`severity:none` = no severity). Engine names in `loads:`/`fails:` are the ones in `suriharvest.yaml`
(`suriharvest doctor` lists them; `init` names the local binary `local`); the major alone also works (`loads:8`
for an engine `suricata-8.0.8`). The CLI, the web search and `GET /api/search` accept exactly the same syntax and
give the same counts. A key that is no filter (`protocol:http`: the key is `proto:`) or an engine that is not configured
(`loads:9`) is refused with a message (the API answers 400) instead of matching nothing; a search that finds
nothing names filter values no rule has, with the closest ones (`no rule has app:htp (closest: http)`; the API
adds them as `warnings`). URLs and rule keys (`et:1:2052813`) are not taken for filters.

<!-- doctest -->
```bash
suriharvest search 'licence:copyleft' --limit 5
suriharvest search 'metadata:malware_family=Cobalt_Strike ioc:no'
suriharvest search 'flowbits:ET.http.binary' --per-logic
suriharvest search 'remapped:yes'
suriharvest search 'severity:critical,major loads:local'
```

## Rules for a CVE

<!-- doctest -->
```bash
suriharvest search CVE-2021-44228                    # = cve:CVE-2021-44228
suriharvest search 'cve:CVE-2021-44228' --per-logic        # every unique logic, not one per family
suriharvest search 'cve:CVE-2021-44228' --per-logic --json > log4shell.json
suriharvest search 'cve:*' --limit 20                # rules that name any CVE
suriharvest search 'log4j'                           # rules that name the product but not the CVE id
```

A CVE id typed as words (`CVE-2021-44228`), the filter (`cve:CVE-2021-44228`, `cve:2021-44228`), the web search and
`GET /api/search?q=cve:CVE-2021-44228` are one search with one answer: rules that name the CVE in their message,
in `reference:cve,2021-44228` or in `metadata: cve CVE_2021_44228`. Counts are one rule per family (the same
detection written several ways); `--per-logic` (web: "Show every variant") counts every unique logic, and `--json`
lists exactly which rules are behind a number. Product names (`log4j`) also find rules that do not carry the CVE
id at all.

## Read a rule

<!-- doctest -->
```bash
suriharvest show 2052813                      # by sid
suriharvest show et:1:2052813                 # by rule key namespace:gid:sid (ET Open's namespace is `et`)
# or by a logic hash prefix (8+ characters), as `search --json` and the web rule page print it
```

The rule key's namespace is the publisher that owns the sid range (from [sidallocation.org](https://sidallocation.org/),
`sid_namespace` in `sources.yaml`), so the same rule shipped by two sources has one key. `show` prints the key on
its first line.

You see the current text, every copy (source, file, rev, enabled or not), the rev history, the family, the
validation result per engine with the engine's error message if it failed, and the flowbits it sets or needs.

## Profiles: your named rulesets

A **profile** is a recipe for a ruleset: which rules (a search query), which engine they must load on, and which
options. `init` creates `default`. Make more for different sensors:

<!-- doctest -->
```bash
# Behaviour rules only, no IOC lists, must load on the engine named `local` in suriharvest.yaml
suriharvest profile create dmz --query 'ioc:no' --engine local --description "DMZ sensors"

# Change options later
suriharvest profile set dmz --redistributable-only --include-disabled
suriharvest profile set dmz --iocs-as-datasets

suriharvest profile list
suriharvest profile create lab --query 'source:et-open'
suriharvest profile remove lab --yes        # delete it with its exclusions and builds (--keep-files keeps the folders)
```

`--engine` must name an engine from `suriharvest.yaml`; an unknown name is refused (it would filter nothing).

| Option (`create` / `set`) | Effect |
|---|---|
| `--query` | candidate rules (search syntax); default: every rule |
| `--unit logic\|family` | every unique logic, or the best rule of each family |
| `--engine NAME` | rules must load on this engine: a name from `engines:` in `suriharvest.yaml` (e.g. `local`, or `8.0` after `init --engine 8.0=jasonish/suricata:8.0.8`) |
| `--include-disabled` | also rules their publisher ships commented out |
| `--remap-sids` | give colliding sids a stable new number instead of failing (`set` only) |
| `--iocs-as-datasets` | turn single-indicator rules into dataset files + one rule per buffer |
| `--redistributable-only` | only sources with `redistribute: yes` |
| `--auto-build` / `--no-auto-build` | rebuild after every update (default on) |
| `--flowbit-setters suricata-update\|strict` | keep excluded flowbit setters with `noalert` (as suricata-update does), or never (`set` only; [profiles.md](profiles.md#coming-from-suricata-update)) |

## Exclusions

Exclude rules from one profile, or from every profile with the name `all`. Each exclusion says how many rules it matches right away.
An exclusion only changes a build when the rule would be in it: a rule its publisher ships disabled (the `on` column of
`show`'s copies says `no`) is already left out, unless the profile has `--include-disabled`. `exclude` warns when
that is the case ("every matching rule is shipped disabled upstream") and when nothing matches at all ("a no-op
until such a rule appears").

<!-- doctest -->
```bash
# Preview before you exclude
suriharvest profile preview "ET POLICY" --kind msg_contains

# By sid: ET INFO Dropbox paper Document Request Observed (enabled in ET Open)
suriharvest profile exclude default 2052813 --kind sid --reason "noisy on our network" --review 2027-05-01
suriharvest profile build default
suriharvest profile diff default            # shows "- 2052813 ..."

# By message text (default kind: msg_contains), exact message, classtype, source or a full search query
suriharvest profile exclude default "ET INFO"
suriharvest profile exclude default "ET INFO Observed DNS Query to .cloud TLD" --kind msg_exact --reason "too noisy here"
suriharvest profile exclude dmz policy-violation --kind classtype
suriharvest profile exclude all etnetera-aggressive --kind source
suriharvest profile exclude dmz 'app:smb ioc:yes' --kind query --review 2027-03-01

# List (the first column is the id) and undo
suriharvest profile exclusions default
suriharvest profile unexclude 2
```

Kinds: `msg_contains`, `msg_exact`, `msg_regex`, `rule_regex`, `sid`, `rule_key`, `logic`, `category`, `classtype`,
`source`, `query`, `metadata`, `file` ([profiles.md](profiles.md#exclusion-kinds)). `--review YYYY-MM-DD` reminds you to revisit an exclusion.

Exclusions are stored in the database and mirrored to `exclusions/<profile>.yaml` (and
`exclusions/all-profiles.yaml` for `all`), so you can review them in Git; hand edits are applied on the next
command. The names `all` and `all-profiles` are reserved.

Need ideas? `suriharvest profile suggest default` lists groups of rules people usually leave out, with counts and
examples (it changes nothing), and `suriharvest profile new default` lists the rules the profile would get now
that are not in its last build (what to review before the next build).

## Build and diff

<!-- doctest -->
```bash
suriharvest profile build default         # writes data/profiles/default/<UTC time>Z/, moves latest/ to it
suriharvest profile builds default        # list builds, newest first
suriharvest profile diff default                       # previous vs latest (first build: nothing to compare)
suriharvest profile diff default 1 2 --json            # two specific builds (numbers from `profile builds`)
```

A build contains `suricata.rules`, `manifest.jsonl`, `excluded.jsonl` and `changes.json`;
`data/profiles/<name>/latest` points at the newest build. A profile whose `--engine` is no longer in
`suriharvest.yaml` is not built (the message says how to fix it). The diff lists rules
added, removed and changed; a new revision of the same rule (same `namespace:gid:sid`) is one "changed" entry
(`rev 2 -> 3; new logic`), not a removal plus an addition. `excluded.jsonl` of the build says why a rule was left
out.

## Export

`export` writes a ruleset to a folder in one go, from a query or a profile:

<!-- doctest -->
```bash
suriharvest export --out out/                                         # everything, one rule per family
suriharvest export --out out/ --profile default                       # what the profile selects, exclusions applied
suriharvest export 'source:et-open app:tls' --out out/ --unit logic
suriharvest export --out out/ --by-source                             # also out/by-source/<source>.rules
suriharvest export --out out/ --format suricata-update                # local.rules + enable.conf + disable.conf
suriharvest export --out share/ --redistributable-only                # a file you may share
```

Rules that fail to load in an engine are left out (`--include-failing` keeps them), so `suricata -T` on the
result passes. Rules disabled upstream are written commented out (`--disabled comment`, the default for a query),
left out (`omit`) or enabled (`enable`, also `--include-disabled`; the default with `--profile`).

All formats and options: [export.md](export.md).

## Sources

<!-- doctest -->
```bash
suriharvest sources list
suriharvest sources disable etnetera-aggressive
suriharvest sources enable opnsense-rules
suriharvest sources add my-rules ~/rules --type local --licence MIT --redistribute no --priority 5
suriharvest sources import extra-catalog.yaml            # added disabled, review first
suriharvest sources check --no-http                      # catalog vs the OISF index (downloads the index; --licences hashes licence texts)
suriharvest sync my-rules                                # download just one source
suriharvest sources remove my-rules                      # out of sources.yaml; its rules leave the index at the next update
```

More in [sources.md](sources.md).

## Runs, health and scripting

<!-- doctest -->
```bash
suriharvest runs list
suriharvest runs show latest
suriharvest runs accept latest     # accept a run that failed a gate as the new baseline (after you checked it)
suriharvest quarantine             # lines that could not be parsed
suriharvest doctor
suriharvest stats --json           # corpus totals as JSON (also GET /api/stats from `suriharvest serve`)
```

Scripts that prefer HTTP can use the read-only JSON API of `suriharvest serve`: `GET /api/search?q=...` (same query
syntax and counts as `search --json`) and `GET /api/stats` ([web.md](web.md#json-api)).

`--json` prints one JSON document on stdout and nothing else; lists are `{"total", "offset", "limit", "results"}`
(`search --json` and `GET /api/search`, which adds `query`). Errors go to stderr and start with `error: `.

| Exit code | Meaning |
|---|---|
| 0 | OK |
| 1 | The command ran but did not reach its goal: a source or a gate failed, doctor found a problem, nothing matched a key (`show`) |
| 2 | Bad option or argument, not a workspace, the workspace is busy, or an I/O error |

`update --allow-failures` returns 0 when only some sources failed (gates still apply; `--max-failed-sources PCT`,
default 10, is the share of enabled sources allowed to fail; when every enabled source failed, or the corpus has no
rules, the run fails and exits 1 anyway), `--report-file PATH` also copies the Markdown report
there, and `--wait SECONDS` waits for a busy workspace instead of failing. `sources check` exits 0 (fine),
1 (something needs review) or 2 (the check itself failed).
