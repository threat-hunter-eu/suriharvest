# Sources

Where the rules come from, how licences are handled, and how to add your own.

- [The catalog and sources.yaml](#the-catalog-and-sourcesyaml)
- [Tiers and presets](#tiers-and-presets)
- [What ships in the catalog](#what-ships-in-the-catalog)
- [Add your own rules](#add-your-own-rules)
- [Sources that need a key or forbid redistribution](#sources-that-need-a-key-or-forbid-redistribution)
- [Priority, namespaces and sid collisions](#priority-namespaces-and-sid-collisions)
- [Licences](#licences)
- [Discovering more sources](#discovering-more-sources)

## The catalog and sources.yaml

suriharvest ships a **catalog** of free sources. `suriharvest init` copies it into your workspace as
`sources.yaml`, enabling the sources of the preset you chose. After that, `sources.yaml` is yours: edit it by hand
or with `suriharvest sources ...`.

```yaml
sources:
- name: et-open
  type: http-tarball
  url: https://rules.emergingthreats.net/open/suricata-${suricata_version}/emerging.rules.tar.gz
  paths: ['**/*.rules']
  licence: BSD-3-Clause AND GPL-2.0-only
  redistribute: yes
  status: active
  tier: core
  priority: 10
  min_suricata: '7'
  sid_namespace: et
  url_versions: {'7': 7.0.3, '8': '8.0'}
  licence_files: [rules/LICENSE, rules/BSD-License.txt, rules/gpl-2.0.txt]
  enabled: true
```

| Field | Meaning |
|---|---|
| `name` | unique short name, used in filters (`source:et-open`) |
| `type` | `http-tarball`, `http-file`, `git` or `local` |
| `url` | URL, Git remote or folder; `${suricata_version}` is filled from `suriharvest.yaml` (once per Suricata major when the engines span several: [per-major rulesets](#per-major-rulesets)) |
| `paths` | globs of rule files inside an archive, repo or folder (default `**/*.rules`) |
| `ref` | Git branch or tag |
| `licence` | SPDX expression, as the publisher's own text states it |
| `redistribute` | `yes`, `no` or `unknown`: may the rule text be republished? |
| `status` | `active`, `stale` (no upstream update for a year but still served), `dead`, `deprecated`; active and stale sources are synced |
| `tier` | `core`, `community`, `experimental`, `user-fetch` |
| `priority` | lower wins on sid and logic collisions (default 50) |
| `sid_namespace` | publisher namespace for sids (default: the source name); set it to the sidallocation.org namespace of a range owner (`et`, `stamus`, ...) so the owner keeps its sids in a collision |
| `min_suricata` | oldest Suricata version the rules load on (`7`, `8`, or a full version) |
| `url_versions` | Suricata major -> value of `${suricata_version}` in the URL (ET: `7` -> `7.0.3`, `8` -> `8.0`) |
| `auth` | name of an environment variable holding a key or token (sent only to the URL's own host, never after a redirect to another host) |
| `allow_private` | `true` for an internal mirror: downloads may connect to private/loopback addresses (refused otherwise, also after redirects) |
| `licence_files` | licence texts to publish in `LICENSES/`, relative to the source (a `local` folder contributes nothing else) |
| `copyright` | the copyright line(s) of the publisher (a string or a list), copied from its LICENSE file or feed header; goes into `NOTICE.md`, the rules file headers and the filled-in `LICENSES/<source>/LICENSE.<id>.txt` (MIT / BSD template text with this line, when the source ships no licence file). `release build` fails when a source whose licence asks for the notice to be kept (anything but CC0-1.0, 0BSD, Unlicense, MIT-0, PDDL-1.0) has neither this field nor a copyright line in its own rules header. A publisher that states no holder: name it and say so |
| `rule_licences` | per-rule licence of a source whose licence splits by sid: a list of `{licence, sids, msg_prefix}`, first match wins, an entry with neither `sids` nor `msg_prefix` matches every rule. It labels each rule's `licence` in the manifest (ET Open: `GPL-2.0-only` for sids 1-3464, 100000000-100000908, 2100000-2103999 and `GPL ...` rules, `BSD-3-Clause` otherwise) |
| `homepage`, `notes`, `oisf_name`, `licence_source`, `sid_range` | information (`homepage` replaces the fetch URL in `NOTICE.md`); `oisf_name` links the source to its suricata-update name |

`index.yaml` in a release names the combined SPDX expression of the sources in each build (`Various` only when a
source has no SPDX licence). Licences known only from a publisher's OISF index entry (`etnetera-aggressive`) say so
in `licence_source`, with the index URL and the date it was read; `sources check` re-reads the entry into
`health.yaml` so a change shows up in review. A written confirmation from the publisher is still the better evidence.

The bundled catalog also carries `rules` and `measured` (a measurement snapshot); they stay in the catalog and are
not copied into `sources.yaml`. Its `excluded:` list names sources left out on purpose, with the reason.

### Per-major rulesets

Some publishers ship one ruleset per Suricata major (ET Open: `suricata-7.0.3/` and `suricata-8.0/`). When the
engines in `suriharvest.yaml` span more than one major (say `suricata-7` and `suricata-8`), an `http-tarball` or
`http-file` source whose `url` contains `${suricata_version}` is downloaded **once per major**:

| What | How |
|---|---|
| version requested | per major: `ruleset_version` for its own major, otherwise the newest engine of that major; `url_versions` maps it to the publisher's folder |
| storage | `corpus/<source>/@7/`, `corpus/<source>/@8/`; rule paths in the database carry the `@<major>/` prefix; HTTP validators are kept per major |
| sources without the placeholder, `git`, `local` | downloaded once and shared by every engine |
| `min_suricata` | a major older than it gets no copy |
| validation | an engine checks the shared rules plus its own major's copy, never another major's |
| builds | a release (`suricata-7.rules`, `suricata-8.rules`) or a profile with an engine takes only the rules its major's copy ships, with that copy's text, revision, enabled state, notices, `classification.config` and licence files; without an engine (plain `export`, web downloads) the newest major's copy is used |

Identity is shared: a rule with the same text in both copies is one rule version, the same logic is one logic group
(same logic hash), so exclusions, verdicts and the sid map treat it as one rule and its sid never moves between
engines. A rule whose detection differs between the copies (ET rewrites some rules for Suricata 8) is two logic
groups under one rule key; each engine publishes its own. An engine whose major has no copy uses the nearest older
copy (else the oldest). With engines of one major, nothing changes: one download, no `@<major>` folders.

## Tiers and presets

| Tier | Meaning | Enabled by preset |
|---|---|---|
| `core` | main free sources: maintained, licensed, redistributable, load cleanly | `core`, `community`, `all` |
| `community` | licensed GitHub collections and larger IOC feeds; smaller, some need Suricata 8 or ship datasets | `community`, `all` |
| `experimental` | generated rules, Snort-dialect collections, local-range sids, unclear licences | `all` |
| `user-fetch` | free but not redistributable (non-commercial licence, personal key) | never automatically |

`init --tier core --tier community` picks tiers exactly; `--redistributable-only` keeps only `redistribute: yes`.

## What ships in the catalog

Measured 2026-11-14; counts change daily.

| Source | Tier | Licence | Rules (approx.) | Notes |
|---|---|---|---:|---|
| ET Open | core | BSD-3-Clause AND GPL-2.0-only | 72,000 (53,000 enabled) | per-version tarball |
| abuse.ch SSLBL | core | CC0-1.0 | 11,000 | TLS certificate blacklist |
| abuse.ch JA3 | core | CC0-1.0 | 97 | frozen since 2021 (`stale`) |
| abuse.ch Feodo Tracker | core | CC0-1.0 | 5 | |
| PT Open (Positive Technologies) | user-fetch | MIT | 430 | not in the published builds (see below) |
| Stamus lateral movement | core | GPL-3.0-only | 560 | |
| Travis Green hunting | core | GPL-3.0-only | 290 | |
| OISF Traffic ID | core | MIT | 34 | app identification (`stale`) |
| Etnetera aggressive | user-fetch | MIT (OISF index only) | 63 | IP lists, change often; not in the published builds (see below) |
| The Hunters Ledger | core | CC-BY-4.0 | 135 | |
| Echap stalkerware | core | CC-BY-4.0 | 990 | |
| aleksibovellan nmap | core | MIT | 10 | |
| julioliraup Antiphishing | community | GPL-3.0-only | 38,000 | IOC rules + dataset files |
| IPFire DBL | community | CC-BY-SA-4.0 | 56 + datasets | Suricata 8 only |
| opnsense/rules, daffainfo, quadrantsec, ESET, Volexity, 401trg, red-team-tool-countermeasures, FCSC shovel (Suricata 8), Quickdraw, ConnectWise CRU, sudohyak, travisbgreen repo | community | BSD / Apache / MIT / GPL | ~3,600 together | |
| ARPSyndicate vedas, Snort community, ditekshen | experimental | MIT / GPL-2.0 / BSD | ~20,000 | generated or Snort-dialect |
| PAW Patrules | experimental, `redistribute: no` | CC BY-NC-SA 4.0 | 21,000 | non-commercial: never redistributed |

30 sources in all (10 core, 14 community, 4 experimental, 2 user-fetch); names as in
`src/suriharvest/catalog/sources.yaml` (`suriharvest sources list` after `init`).

`user-fetch` sources are not republished in the nightly builds or on the site, and are listed in `recipes.tar.gz`
so you can fetch them yourself (`suriharvest sources enable NAME`, or `init --preset all`). Etnetera aggressive is
there until its publisher confirms in writing that the feed may be redistributed (its only licence statement is the
OISF index entry). PT Open is there pending a legal review of its redistribution.

## Add your own rules

A local folder with your own `.rules` files:

<!-- doctest -->
```bash
suriharvest sources add my-rules ~/suricata/local --type local --licence MIT --redistribute no --priority 5
suriharvest update
```

A Git repository:

<!-- doctest: skip example URL (adding is offline, but the next update would fetch it) -->
```bash
suriharvest sources add acme https://github.com/acme/suricata-rules --type git \
  --path 'rules/*.rules' --licence Apache-2.0 --redistribute yes
```

A single file or a tarball over HTTPS:

<!-- doctest: skip example URLs -->
```bash
suriharvest sources add vendor-x https://example.org/rules/latest.rules --type http-file --licence "LicenseRef-vendor" --redistribute no
suriharvest sources add vendor-y https://example.org/rules.tar.gz --type http-tarball --path '**/*.rules'
```

Tips:

- Give your own rules a **low priority number** (e.g. 5) so they win sid collisions against public sources.
- Use a **sid in the local range** (1,000,000-1,999,999) or a range allocated to you at
  [sidallocation.org](https://sidallocation.org/).
- Set `--redistribute no` for anything private. `--redistributable-only` exports will leave it out.
- To add many sources at once, write them in a YAML file with the same shape and run
  `suriharvest sources import FILE` (they are added disabled so you can review them).

## Sources that need a key or forbid redistribution

Some free feeds need a personal key (abuse.ch URLhaus and ThreatFox need a free Auth-Key) or have a
non-commercial licence (PAW Patrules). suriharvest never fetches these in the public nightly build, but you can
use them locally:

<!-- doctest: skip needs your own key -->
```bash
export ABUSECH_AUTH_KEY=...      # your own key; never commit it
suriharvest sources add threatfox 'https://example.invalid/threatfox-suricata.rules?key=${secret}' \
  --type http-file --auth ABUSECH_AUTH_KEY --redistribute no --tier user-fetch
```

`--auth VAR` sends the value as `Authorization: Bearer <value>`, or, when the URL contains `${secret}`, puts it
there instead. The key is read from the environment and never written to `sources.yaml`, logs, reports or
published files (URLs in published files are redacted: no credentials, no query string). Feeds that want the key
in another header (abuse.ch documents an `Auth-Key` header) are not supported yet; use a URL form that takes the
key, if the publisher offers one, or download the file yourself into a `local` source.

`release build --recipes-from CATALOG` writes `recipes.tar.gz` (the nightly workflow passes the bundled catalog):
a suricata-update `update.yaml` snippet and a README for each active catalog source that is not redistributed,
with `%(secret-code)s` where a key goes. Nothing in it is downloaded by the build.

## Priority, namespaces and sid collisions

A rule's identity is `(namespace, gid, sid)`. The namespace is the publisher: it comes from the
[sidallocation.org](https://sidallocation.org/) table when the source matches the range owner, otherwise from the
source name. Consequences:

- **Same publisher, same sid**: one rule; the highest `rev` of the publisher's own copy wins. A fork's old copy
  never overrides the publisher.
- **Same logic, different sid** (publishers sometimes duplicate their own rules): kept once in a build (one rule
  per logic hash).
- **Different publishers, same sid** (forks, copies, two repos using the same local range): a **collision**. The
  range owner (sidallocation.org) keeps the sid, else the rule that held it before, else the better `priority`.
  The other rule gets a new sid that stays stable in every later build (profiles remap by default; a plain
  `export` refuses until you pass `--remap-colliding-sids`). The mapping lives in `state/sid-map.tsv`. See
  [sids.md](sids.md) and [export.md](export.md#sid-collisions-and-remapping).

Rule `rev` values are only compared inside one namespace (some feeds use a Unix timestamp as rev, others restart
at 1 on every rebuild).

## Licences

The OISF index `license` field is a hint, not a guarantee. The catalog records what the **publisher's own text**
says. Examples where it matters:

- **ET Open** is labelled MIT in the index, but its bundled licence is BSD (sids 2,000,000-2,099,999 and the other
  ET ranges) plus GPL-2.0 for the old GPL rules. Both notices are shipped.
- **PAW Patrules** is labelled CC-BY-SA in the index, but its own site says CC BY-NC-SA 4.0 (non-commercial):
  user-fetch only.
- **abuse.ch**: SSLBL, JA3 and Feodo Tracker are CC0; URLhaus and ThreatFox are fair-use and need a personal key.

What this means for you:

| You... | What to check |
|---|---|
| run the rules on your own sensors | usually fine for every free source; non-commercial licences may still restrict commercial use |
| share a ruleset with others | use `--redistributable-only`; ship `NOTICE.md` and the licence texts |
| change a GPL or CC-BY-SA rule (sid, action, threshold) and share it | it stays under the same licence; mark the change (suriharvest does this in `NOTICE.md` for remapped sids) |

This is guidance, not legal advice.

## Discovering more sources

`suriharvest sources check` compares the catalog with the OISF suricata-update index (new free sources, sources
gone or deprecated upstream), checks that every active source answers, and with `--licences` fetches each
source's licence text and flags a changed hash against the previous `--health` file. It never edits the catalog.

The project checks the catalog weekly (dead URLs, changed licence text, new free sources in the OISF index) and
opens a pull request; humans decide what changes. To propose a source, open an issue with the URL, licence and sid
range. Requirements for the catalog: a clear licence that allows redistribution (or tier `user-fetch`), rules
that load on Suricata 7 or 8, and a sid range that does not squat on another publisher's allocation.
