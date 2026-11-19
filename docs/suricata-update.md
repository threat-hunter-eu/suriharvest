# Use the nightly release with suricata-update

The nightly release is a ready-made suricata-update source: no suriharvest on the sensor, no Python, no
workspace. suricata-update downloads one tarball, and its own `enable.conf` / `disable.conf` / `drop.conf` /
`modify.conf` keep working on top of it.

> **Availability.** A new `rules-YYYY-MM-DD` release is published on the nights a source changed (the first one
> on 2026-11-17); the `latest` URLs below always point at the newest one.

## Set it up

Pick the tarball for the Suricata major version your sensors run (`suricata -V`):

| Suricata | source name | URL |
|---|---|---|
| 8.x | `suriharvest-8` | `https://github.com/threat-hunter-eu/suriharvest-rules/releases/latest/download/suriharvest-8.tar.gz` |
| 7.x | `suriharvest-7` | `https://github.com/threat-hunter-eu/suriharvest-rules/releases/latest/download/suriharvest-7.tar.gz` |

<!-- doctest: skip root and network (suricata-update on a sensor) -->
```bash
sudo suricata-update add-source suriharvest-8 \
  https://github.com/threat-hunter-eu/suriharvest-rules/releases/latest/download/suriharvest-8.tar.gz
sudo suricata-update disable-source et/open     # ET Open is already inside: do not load it twice
sudo suricata-update list-enabled-sources       # check: suriharvest-8, and nothing it already contains
sudo suricata-update                            # fetch, apply your *.conf files, test with suricata -T, write
```

`releases/latest/download/...` always points at the newest release, so the URL never changes. To pin one day,
use `https://github.com/threat-hunter-eu/suriharvest-rules/releases/download/rules-YYYY-MM-DD/suriharvest-8.tar.gz`.

## Remove the duplicates

suriharvest merges the redistributable core sources (ET Open, OISF/Suricata's own rules and the other free sources
listed in each release's `NOTICE.md`). Keep a source enabled in suricata-update only if it is **not** in that list,
otherwise every rule is loaded twice and suricata-update prints one "duplicate rule" warning per rule.

<!-- doctest: skip root and network (suricata-update on a sensor) -->
```bash
sudo suricata-update list-enabled-sources
sudo suricata-update disable-source et/open
sudo suricata-update disable-source oisf/trafficid     # if enabled: it is part of the release too
```

The tarball itself carries a single rules file (`rules/suricata.rules`), so it does not cause duplicate warnings
on its own. Per-source files are separate release assets (`suricata-N.by-source.<source>.rules`) for people who
download plain files.

## What is in the tarball

| member | content |
|---|---|
| `rules/suricata.rules` | the merged ruleset for that Suricata major: deduplicated, only rules that load on it, flowbit setters included, sid collisions resolved (stable remapped sids) |
| `rules/classification.config`, `rules/reference.config` | merged from Suricata's defaults and what the sources ship |
| `rules/datasets/<source>/...` | files that dataset rules load (when a release has any) |
| `NOTICE.md`, `LICENSES/` | the sources in this build, their licences and copyright notices |

Other assets of the same release: `SHA256SUMS`, `manifest.jsonl.gz` (every rule with source, licence, original
and exported sid), `collisions.json`, `changes.json`, `index.yaml` (a suricata-update index, `version: 1`,
describing the per-engine sources). Details: [releases.md](releases.md).

## Your own changes

Keep using suricata-update's files: `disable.conf`, `enable.conf`, `drop.conf` and `modify.conf` match the rules
of this source like any other (by `gid:sid`, `re:`, `group:suricata.rules`, `metadata:`). A sid that collided
upstream has a new sid in the release; `collisions.json` and `manifest.jsonl.gz` list the original and the
exported sid, so check there before writing a sid-based entry for such a rule.

If you later move to suriharvest profiles, `suriharvest profile import-conf PROFILE /etc/suricata` converts those
files ([profiles.md](profiles.md#coming-from-suricata-update)). To build your own ruleset with suriharvest and keep
suricata-update on the sensors, see [export.md](export.md#feeding-suricata-update) (an export with `disable.conf`,
or the `suriharvest serve` feed URL `/feed/<profile>/<engine>.tar.gz`, [web.md](web.md#suricata-update-feed)).

## Check what you downloaded

<!-- doctest: skip downloads the nightly release -->
```bash
curl -LO https://github.com/threat-hunter-eu/suriharvest-rules/releases/latest/download/suriharvest-8.tar.gz
curl -LO https://github.com/threat-hunter-eu/suriharvest-rules/releases/latest/download/SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
```
