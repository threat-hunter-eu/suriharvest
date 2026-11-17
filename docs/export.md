# Export

Three ways to get a ruleset out of suriharvest, from simplest to most flexible:

1. **Nightly release**: no install, see [below](#nightly-release-files).
2. **`suriharvest profile build NAME`**: a named, repeatable ruleset with exclusions and history.
3. **`suriharvest export [QUERY] --out OUT`**: a one-off export of any query or profile, with format options.

- [Formats at a glance](#formats-at-a-glance)
- [suricata.rules](#suricatarules)
- [Per-source files](#per-source-files)
- [Feeding suricata-update](#feeding-suricata-update)
- [IOC rules as datasets](#ioc-rules-as-datasets)
- [sid collisions and remapping](#sid-collisions-and-remapping)
- [The manifest](#the-manifest)
- [Sharing a ruleset (licences)](#sharing-a-ruleset-licences)
- [Nightly release files](#nightly-release-files)
- [Search results as JSON](#search-results-as-json)

## Formats at a glance

| Command | You get |
|---|---|
| `suriharvest export [QUERY] --out OUT` | `OUT/suricata.rules` + `OUT/manifest.jsonl` |
| `... --by-source` | also `OUT/by-source/<source>.rules` |
| `... --format suricata-update` | `suriharvest-local.rules`, `enable.conf`, `disable.conf`, `README.txt`, `manifest.jsonl` |
| `... --iocs-as-datasets` | `datasets.rules` + `datasets/*.lst` + `datasets/iocs.jsonl` instead of thousands of IOC rules |
| `suriharvest profile build NAME` | `data/profiles/NAME/<YYYYMMDD-HHMMSS>Z/` (UTC; `latest` points at the newest): `suricata.rules`, `manifest.jsonl`, `excluded.jsonl`, `changes.json` |
| `suriharvest release build OUT` | the flat, checksummed release set ([releases.md](releases.md)) |
| `suriharvest search ... --json` | search results as JSON |

## suricata.rules

<!-- doctest -->
```bash
suriharvest export --out out/                                  # every rule, best of each family
suriharvest export --out out/ --unit logic                     # every unique logic
suriharvest export --out out/ --profile default                # what the profile selects, exclusions applied
suriharvest export 'app:tls ioc:no loads:local' --out out/   # engine names: suriharvest.yaml
```

The old form `suriharvest export OUT --query Q` (and a lone `export OUT`) still works in this release and prints the
new form to use; it will be removed before 1.0.

What the export does for you:

- **Only rules that load**: rules that failed `suricata -T` in an engine are left out and counted;
  `--include-failing` keeps them.
- **Flowbits closure**: if a rule checks a flowbit, a rule that sets it is added (the best-priority setter in the
  corpus) even if it was not in your selection. The summary says how many setters were added and lists bits that
  have no setter at all.
- **Publisher enable state**: for a query, rules every publisher ships commented out (or flags as deleted) are
  written commented out (`--disabled comment`); `--disabled omit` leaves them out, `--disabled enable` (or
  `--include-disabled`) enables them. With `--profile` the profile's own `include_disabled` option decides.
- **sid collisions are refused** unless you allow remapping (see [below](#sid-collisions-and-remapping)).
- **Malformed rules never stop an export**: a rule whose sid cannot be rewritten is left out and counted.
- **Dataset files** that rules `load` are written next to the rules under `datasets/<source>/...` (and next to
  `by-source/`), with the rule paths rewritten to match, as in a release. A dataset name that two rules define with
  a different type or file gets its own name (`<name>-<hash>`, reported) so the merged file loads. Rules whose file
  path is absolute or outside the source, that `save` a file, or whose file the source does not ship are left out
  with the reason (profile builds: `excluded.jsonl`). The web feed tarball carries the files under
  `rules/datasets/`; a single `.rules` download leaves dataset rules out.
- **Other external files** that rules need (Lua scripts, iprep lists) are listed in the summary.

Test the result before you deploy it (`-l`: a writable log folder, the default needs root):

<!-- doctest -->
```bash
suricata -T -c /etc/suricata/suricata.yaml -S out/suricata.rules -l /tmp
```

## Per-source files

<!-- doctest -->
```bash
suriharvest export --out out/ --by-source
```

writes `out/by-source/<source>.rules` next to the merged file. Concatenated, they equal the merged file. Useful when
you want to enable sources separately on a sensor, or when you must keep licences apart (GPL and CC-BY-SA rules
stay in their own files).

## Feeding suricata-update

If your sensors already use `suricata-update`, you have three options.

**A. Use the nightly release as a suricata-update source** (no suriharvest on the sensor; step by step in
[suricata-update.md](suricata-update.md)):

<!-- doctest: skip root and network (suricata-update on a sensor) -->
```bash
sudo suricata-update add-source suriharvest-8 \
  https://github.com/threat-hunter-eu/suriharvest-rules/releases/latest/download/suriharvest-8.tar.gz
sudo suricata-update disable-source et/open     # suriharvest already contains ET Open
sudo suricata-update
```

**B. Let suricata-update keep fetching the sources it knows, and add the rest from suriharvest:**

<!-- doctest -->
```bash
suriharvest export --out su/ --profile default --format suricata-update
cat su/README.txt                                  # the sources suricata-update must fetch itself
grep -E '^- name:|oisf_name:' sources.yaml         # their suricata-update names (oisf_name)
sudo suricata-update list-enabled-sources          # et/open is on by default; enable the others:
sudo suricata-update enable-source oisf/trafficid  # ... one per oisf_name
sudo suricata-update --local su/suriharvest-local.rules --enable-conf su/enable.conf --disable-conf su/disable.conf
```

- A source is **managed by suricata-update** when its `oisf_name` in `sources.yaml` is a name from the
  [OISF index](https://www.openinfosecfoundation.org/rules/index.yaml) (`et/open`, `oisf/trafficid`,
  `abuse.ch/sslbl-blacklist`, `abuse.ch/sslbl-ja3`, `abuse.ch/feodotracker`, `ptrules/open`, `stamus/lateral`,
  `tgreen/hunting`, `etnetera/aggressive`, `the-hunters-ledger/open`, `echap/stalkerware`, `aleksibovellan/nmap`,
  ...; see `sources.yaml`). The bundled catalog sets it for every source that is in that index. The export summary
  and `README.txt` name the managed sources (suriharvest names). suricata-update fetches only the sources you
  enabled there (`et/open` by default), so `enable-source` the `oisf_name` of each, or its rules are missing on
  the sensor.
- `suriharvest-local.rules` holds the selected rules from sources suricata-update does **not** fetch itself (your
  own folders, GitHub collections).
- `disable.conf` gets **every** rule your profile leaves out (exclusions, with `--profile`) and the rules you
  triaged as `drop` (`suriharvest triage`), whichever source suricata-update gets them from, by `gid:sid` with the
  message as a comment; a gid:sid that another selected rule still uses is not disabled (the summary lists it).
  `enable.conf` gets rules you triaged as `keep` that their publisher ships disabled. Without these two files
  suricata-update would turn your excluded rules back on.
- The summary warns about sources that have no `oisf_name` (their rules are in `suriharvest-local.rules`; disable
  the same source in suricata-update if it fetches it too) and, when ET Open ended up in
  `suriharvest-local.rules`, tells you to run `suricata-update disable-source et/open` (enabled by default) so it
  is not loaded twice.
- Workspaces created before the catalog had `oisf_name` lack it in `sources.yaml`: add `oisf_name: et/open` to
  the `et-open` entry (and the other names above to their entries) by hand, or, if you never edited
  `sources.yaml` and `suriharvest.yaml`, run `suriharvest init ~/suri --refresh` (rewrites both from the catalog
  and your `init` options; the database and builds are kept). Until then ET Open goes into
  `suriharvest-local.rules` and you must `disable-source et/open` as the warning says.

**C. Point suricata-update at `suriharvest serve`**: the Export page (and the Overview's "Copy suricata-update URL")
gives a feed URL per profile and engine, the profile's latest build as a suricata-update source:

```
http://127.0.0.1:8077/feed/<profile>/<engine>.tar.gz      e.g. /feed/default/local.tar.gz, /feed/dmz/suricata-8.tar.gz
```

`<engine>` is an engine name from `suriharvest.yaml`, `suricata-<major>` or the major alone (`8`); `all` keeps
rules that fail on some engine. The archive holds `rules/suricata.rules`, the dataset files its rules load and
`NOTICE.md`. On the same host:

<!-- doctest: skip needs a running suriharvest serve and root -->
```bash
sudo suricata-update add-source suriharvest-default http://127.0.0.1:8077/feed/default/local.tar.gz
sudo suricata-update disable-source et/open      # the feed already contains ET Open
sudo suricata-update
```

For sensors on other hosts, serve it on an address they reach, with a token and TLS in front
([web.md](web.md#security)), and give suricata-update the token as a header:

<!-- doctest: skip needs a running suriharvest serve and a sensor -->
```bash
export SURIHARVEST_WEB_TOKEN=...                                     # 16+ characters, never commit it
suriharvest serve --host 0.0.0.0 --token-env SURIHARVEST_WEB_TOKEN --allow-host suri.example.org
sudo suricata-update add-source --http-header "Authorization: Bearer $SURIHARVEST_WEB_TOKEN" \
  suriharvest-default https://suri.example.org/feed/default/suricata-8.tar.gz
```

You can also host your own build for suricata-update: put a `suricata.rules` (or a tarball) behind HTTPS and
`suricata-update add-source mybuild https://.../suricata.rules`.

## IOC rules as datasets

Many free feeds are single-indicator rules: one rule per domain, JA3 hash or certificate. Tens of thousands of
these slow down rule loading. Turn them into Suricata datasets:

<!-- doctest -->
```bash
suriharvest export --out out/ --profile default --iocs-as-datasets
```

You get:

```
out/suricata.rules            behaviour rules (IOC rules removed)
out/datasets.rules            one rule per buffer, e.g. dns.query, tls.sni, ja3.hash
out/datasets/suriharvest-dns-query.lst
out/datasets/iocs.jsonl       which original rules (sid, msg, source) each indicator came from
```

Load both rule files and put `datasets/` in Suricata's rule directory (Suricata 7+ resolves dataset paths relative
to it and refuses absolute paths). Notes:

- only domain, JA3 and JA3S indicators are converted; everything else stays a rule;
- the dataset matches the exact name; original rules that also matched subdomains are counted in the summary;
- generated rules use sids from `--sid-base` (default 1,990,000,000, outside every sidallocation.org range; a
  base that overlaps an allocated range is refused). Pick a range you own if you have one.

A profile can do this on every build: `suriharvest profile set NAME --iocs-as-datasets`.

## sid collisions and remapping

When two **different publishers** use the same `gid:sid`, only one can be loaded. By default the export **stops
with an error** listing the collisions, so you decide. Options:

<!-- doctest -->
```bash
# Give the losers new sids, stable across builds
suriharvest export --out out/ --remap-colliding-sids
suriharvest export --out out/ --remap-colliding-sids --remap-base 1900000000

# For a profile
suriharvest profile set default --remap-sids
```

- Who keeps the original sid: the publisher the [sidallocation.org](https://sidallocation.org/) table assigns the
  range to; otherwise the rule that held the sid in an earlier build; otherwise the better `priority` (then
  score). Details: [sids.md](sids.md).
- New sids start at `remap_base` in `suriharvest.yaml` (default 1,900,000,000) unless you pass `--remap-base`.
- Every assignment is written to `state/sid-map.tsv` (`logic_hash  gid  original_sid  exported_sid  since  rule_key  source  note`) and reused
  forever, so a remapped rule keeps the same sid in every later export and build: your alerts, suppressions and
  dashboards keep working.
- The manifest has `exported_sid` next to the original `sid`.
- Keep `state/sid-map.tsv` in version control or a backup.

Before remapping into a range, check [sidallocation.org](https://sidallocation.org/) that nobody owns it, or
request your own range. Never remap into another publisher's range.

Alternatively, avoid collisions at the source: disable one of the two sources, or exclude one rule
(`suriharvest profile exclude NAME SID --kind sid`).

## The manifest

`manifest.jsonl` has one JSON object per rule in the export: `logic_hash`, `rule_key` (namespace:gid:sid), `gid`,
`sid`, `exported_sid`, `rev`, `source`, `licence`, `url` (redacted: no credentials or query string; empty for local
folders), `redistribute`, `flags`, `is_ioc`, `enabled` and `msg`. Rules left out of a profile build are in its
`excluded.jsonl` with the reason.

<!-- doctest -->
```bash
# Which sources ended up in my build?
jq -r .source out/manifest.jsonl | sort | uniq -c | sort -rn

# Which rules were remapped?
jq -c 'select(.exported_sid != .sid) | {source, sid, exported_sid}' out/manifest.jsonl
```

## Sharing a ruleset (licences)

If the file leaves your organisation (a public repo, a customer, a product), export only redistributable sources:

<!-- doctest -->
```bash
suriharvest export --out share/ --redistributable-only --by-source
```

Then ship `NOTICE.md` and the licence texts with it (the nightly release has them in `NOTICE.md` and
`LICENSES.tar.gz`). See [sources.md](sources.md#licences).

## Nightly release files

Download from `https://github.com/threat-hunter-eu/suriharvest-rules/releases/latest/download/<file>`:

| File | Content |
|---|---|
| `suricata-7.rules`, `suricata-8.rules` | merged build: enabled rules that load on that engine, flowbit setters closed, collisions resolved, publishers' copyright lines on top |
| `suricata-N.by-source.<source>.rules` | the same, split by source, with the publisher's own notice on top |
| `suriharvest-7.tar.gz`, `suriharvest-8.tar.gz` | suricata-update source: `rules/suricata.rules` (one rules file; per-source copies are the flat `suricata-N.by-source.*` assets), `rules/classification.config`, `rules/reference.config`, `LICENSES/`, `NOTICE.md` |
| `index.yaml` | a suricata-update index (`version: 1`) describing the two sources |
| `manifest.jsonl.gz` | every published rule: engine, gid, sid, exported sid, rev, rule key, source, licence, logic hash, flags |
| `summary.json` | engine versions, counts per engine and source, gate results |
| `changes.json`, `RELEASE_NOTES.md` | added / modified / removed since the previous release |
| `validation.json`, `collisions.json` | load results per source and engine; colliding sids with winner and losers |
| `recipes.tar.gz` | suricata-update snippets for free sources that cannot be redistributed (you fetch them with your own key) |
| `suricata-overrides.txt` | the `--set` options the build was validated with |
| `sid-map.tsv` | the sid map used for the build |
| `NOTICE.md`, `LICENSES.tar.gz`, `LICENSES.<id>.txt` | attribution, copyright notices, the publishers' licence files and the full SPDX texts (also one asset per licence, linked from the header of every `.rules` file) |
| `stats.json` | small summary for the stats branch |
| `SHA256SUMS`, `SHA256SUMS.sigstore.json` | checksums and Sigstore signature (the signature is added by the nightly workflow when signing is enabled on a public repository) |

`suricata-N.datasets.tar.gz` holds the dataset files the rules `load` (under `datasets/<source>/`, unpack next to
the `.rules` file); `suriharvest-N.tar.gz` also carries them and a merged `classification.config` /
`reference.config`. The nightly build still ships the core tier only ([automation.md](automation.md#known-gaps)).

Every file in the release is checked in a clean Suricata 7 and 8 container before publishing: the merged file and
every per-source file must load with zero failed rules, and exactly as many as `summary.json` announces.

## Search results as JSON

<!-- doctest -->
```bash
suriharvest search 'source:et-open app:dns' --per-logic --limit 5000 --json > dns.json
```
