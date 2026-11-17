# Releases

`suriharvest release build OUT --engine suricata-7 --engine suricata-8` writes a flat set of files meant to be
published (for example as release assets), from the current index:

| file | content |
|---|---|
| `suricata-N.rules` | every enabled, non-junk rule that loaded in engine `suricata-N`, newest revision per rule key, global exclusions applied, flowbit setters added, sid collisions remapped through `state/sid-map.tsv` |
| `suricata-N.by-source.<source>.rules` | the same rules split by source (together they are exactly the merged file; the merged file is ordered by source too, with a `# ---- source NAME (LICENCE): N rules ----` line before each source) |
| `suriharvest-N.tar.gz` | suricata-update source: `rules/suricata.rules` (one rules file: suricata-update loads every `*.rules` member, so per-source copies would be reported as duplicates; they are the flat `suricata-N.by-source.*` assets), `rules/classification.config` and `rules/reference.config` (Suricata's defaults + what the sources ship, first definition wins, plus any classtype a rule uses that no file defines), `NOTICE.md`, `LICENSES/` |
| `manifest.jsonl.gz` | one line per published rule: engine, gid, sid, exported_sid, rev, rule_key, source, licence, logic_hash, flags, msg; plus one line per rule left out because a published rule has the same logic under another gid:sid (`excluded_reason: "duplicate"`, `duplicate_of: "gid:exported_sid"`, `exported_sid: null`; not counted in content id, changes or gates) |
| `summary.json` | schema version, content id, engines (version, image, rules, by source), sources, gates |
| `changes.json`, `RELEASE_NOTES.md` | added / removed / modified (rev, exported sid, source) against `--previous` |
| `collisions.json`, `validation.json` | remapped sids; loads/fails per source and engine |
| `index.yaml` | suricata-update index (`version: 1`) pointing at `--download-base` |
| `LICENSES.tar.gz` | `LICENSES/<source>/*` (licence files each publisher ships; for a source that ships none, `LICENSE.<id>.txt` is the MIT/BSD text with its real copyright line), `LICENSES/texts/<SPDX id>.txt` (full text of every licence named, from SPDX license-list-data), `LICENSES/INDEX.md` |
| `LICENSES.<SPDX id>.txt` | the full text of each licence in the build as its own asset, so a loose `.rules` file can link to it in the same release |
| `NOTICE.md`, `suricata-overrides.txt`, `sid-map.tsv`, `stats.json`, `SHA256SUMS` | licences and attribution, the `--set` lines used for validation, the sid map, a small summary, checksums |
| `recipes.tar.gz` | with `--recipes-from CATALOG`: suricata-update snippets for sources that are not redistributed |

By default only sources with `redistribute: yes` are included (`--no-redistributable-only` turns that off for a
private build). The output is reproducible: the only time stamp is `--build-epoch` (or `SOURCE_DATE_EPOCH`), files
are sorted and tarballs have fixed metadata, so an unchanged corpus gives byte-identical files and the same
`content_id`.
Two inputs besides the corpus: `state/sid-map.tsv` (copied as `sid-map.tsv`) records the date each remapped sid
was first assigned, and remapped sids depend on every earlier export and build of the workspace that wrote to the
map. Same corpus + same sid map + same epoch = same files; keep the map with the releases (the nightly workflow
commits it).

Gates (with `--previous DIR` holding the last release's `summary.json` and `manifest.jsonl.gz`): an engine losing
more than `--max-drop-pct` (5) of its rules, or a source losing more than `--max-source-drop-pct` (50) or vanishing,
makes the command exit 1. `--no-gates` skips them after a reviewed, intended change.

Licence header of every loose rules file (`suricata-N.rules`, `suricata-N.by-source.*.rules`, and
`rules/suricata.rules` in the tarball): the SPDX id of each licence of the rules in the file with the URL of its
full text (`LICENSES.<id>.txt` under `--download-base`) and its spdx.org page, the URLs of `NOTICE.md`,
`LICENSES.tar.gz` and `manifest.jsonl.gz` (per-rule source and licence), and the modification notice: the build
date and how many rules suriharvest changed (sids remapped because of a clash, `collisions.json`; dataset load
paths rewritten), "no other change to rule text". A GPL rule fetched on its own from the release therefore
always comes with a pointer to the GPL text in the same release; the tarball carries `NOTICE.md` and
`LICENSES/` next to `rules/`. `NOTICE.md` repeats the list of changes and gives the number of changed rules per
source; profile `modify` / `thresholds` overrides never apply to a release build.

Copyright lines: `release build` refuses to build when a source whose licence asks for the copyright notice
(everything but CC0-1.0, 0BSD, Unlicense, MIT-0, PDDL-1.0) has no copyright line: none in its `copyright:` field
(the bundled catalog has one for every redistributable source), none on top of its rules files and none in the
licence files it ships (git sources keep their root LICENSE / COPYING / NOTICE files, or `licence_files`).

Attribution: the comment block a publisher puts on top of its rules files (for ET: `Copyright (c) 2003-2026,
Emerging Threats`, the BSD conditions and the GPL pointer) is kept verbatim on top of
`suricata-N.by-source.<source>.rules` and in `NOTICE.md`; `NOTICE.md` also lists the copyright lines of every
source and points at the full licence texts; the merged `suricata-N.rules` starts with the copyright lines of the
publishers it contains.

The static site built from these files is described in [site.md](site.md).

## Timings (core tier, measured 2026-11-14)

Since then two sources left the redistributable core tier; the first release (`rules-2026-11-17`) has 10 sources and
65,968 rules per engine (Suricata 7.0.17 and 8.0.8), every file loaded by `suricata -T` with 0 errors.

One machine (WSL2, 22 threads), the 12 redistributable core sources (86,061 rule versions, 66,459 published per
engine), Suricata 7.0.3 as a local binary and 8.0.8 in Docker. Every published file (merged, tarball and each
per-source file, 14 per engine) passed `suricata -T` on its engine with 0 failed rules and the expected count.

| step | time |
|---|---:|
| `update`, cold (download, ingest, validate 7 and 8, index, default profile) | 151 s |
| validation in that update (7 / 8) | 36 s / 29 s |
| `update`, nothing changed upstream | 22 s |
| `profile build` (every rule, engine 8) | 21 s |
| `release build` (engines 7 and 8) | 45 s |
| `site build` | 2.8 s |
| `suricata -T` of one merged file (66,459 rules) | 22-36 s |
