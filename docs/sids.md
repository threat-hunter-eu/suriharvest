# Sids: ownership and stable remapping

## Who owns a sid

`src/suriharvest/sidalloc.py` holds a snapshot of the public allocation table of <https://sidallocation.org/>.
A gid 1 rule whose sid is in a publisher's range gets that publisher's namespace (`et`, `tgreen`, `stamus`,
`ptsecurity`, `abuse.ch-sslbl`, ...), so the same rule carried by a mirror, a fork or a bundle is recognised as the
same rule key. The ET ranges also require an `ET `/`GPL ` name prefix, and the OISF
engine-event range a `SURICATA ` prefix. Everything else (including the local range 1,000,000-1,999,999) keeps
the namespace of its source. A squatter in someone else's range does not merge with the owner: different logic
and names make the key ambiguous.

Which copy of a rule key is kept: `rev` only orders the revisions of one lineage (the texts one source ever
published under that key). Across sources, sid ownership decides first (the source whose `sid_namespace` owns the
key's namespace), then source priority. A copy from another source that the winner never published is dropped when
its rev is not higher (an old mirror or fork); with a higher rev it is a different rule that reuses the sid (for
example a lookalike with the publisher's name and a higher rev): it is kept, loses the sid (remapped, listed in
`collisions.json` with `sid_kept_by`) and can never replace the publisher's rule. In a redistributable build only
redistributable copies compete, so a non-redistributable copy can never push a redistributable rule out.

## Collisions and remapping

Suricata loads one rule per gid:sid. Without `--remap-colliding-sids`, an export with two different rules on the
same gid:sid stops with a list. With it (profiles remap by default), the best rule (source priority, then score,
then logic hash) keeps the sid and the others get new ones.

Remapped sids are **stable**: every clash decision is stored in `state/sid-map.tsv`
(`logic_hash  gid  original_sid  exported_sid  since  rule_key  source  note`): the rule that kept the sid and every remapped
rule. A rule alone on its sid gets no row, so the file stays small (it holds clashes, not the corpus). A rule in
the map keeps its recorded sid in every later build and export; it is found by logic hash, or by rule key plus
supplying source when that feed ships a new revision (new logic hash, same rule). The new revision takes over
the row (new logic hash, same sids, date and note) once the old revision is gone, so a source whose clashing rules
change every night keeps one row per rule. Another source with the same rule key never matches someone else's row.
New sids are only allocated above everything the map ever handed out (the `# floor=` header line keeps that value),
skipping every allocated range. `release build --previous DIR` retires the rows (without a note) of rules that neither the new
release nor the previous one lists (`sid_map_retired` in `summary.json`); their sids stay used, and a rule
that comes back later is a new clash with a new sid. Row dates come from `--build-epoch` in a release build and
from `SOURCE_DATE_EPOCH` (when set) in profile builds and exports, so rebuilding the same data writes the same map.
Commit the file next to anything you publish.

Policy: **once a rule has been published under a sid, it keeps that sid.** When a newcomer with the same gid:sid
appears later, the incumbent (the rule recorded as holder, or, for a clash seen for the first time, the rule that
had the sid unchanged in the previous profile build or in the `--previous` release manifest) keeps the sid and the newcomer is remapped, even when
the newcomer's source has a better priority or score. Rank (source priority, score, logic hash) only decides the
first time a clash is seen with neither a recorded holder nor a previous build that had the sid. Otherwise an upstream could renumber a rule that sensors,
suppressions, thresholds and alert history already know by its sid (and, with a well-chosen decoy, replace it).
When two different builds recorded different holders of the same sid, the older record wins.

One exception, against squatting: **the owner of the range keeps its sids.** When the sid lies in a range that
the sidallocation.org table (`catalog/sid-allocation.tsv`, `sidalloc.py`) assigns to a publisher, and one of the
clashing rules comes from that publisher's source (its `sid_namespace` is the range's namespace, e.g. `et` for
ET Open; the catalog sets it for every owner), that rule keeps (or takes back) the sid and the other one is
remapped, even if the other one was exported under it first. Otherwise a low-priority source could publish a rule
with an ET sid before ET does and push the real ET rule into remapping. Without an owner in the clash, the
incumbent rule above applies.

An owner reclaim is the one time a published sid moves: the displaced rule gets a fresh sid once, its sid-map row
carries the note `reclaimed_by=<owner source>` (an owner rule that had been remapped and moves back gets
`owner_reclaim=<source>`; it moves back only when another rule holds or claims the sid, never onto a sid that
is free because the rule holding it is gone), rows with a note never move again, and the release lists the move in `changes.json`
(`reclaimed`) and in `RELEASE_NOTES.md`. Every other published sid that moves (one sid map serves every engine,
so adding a second Suricata major can remap a rule that only clashes in the new major's ruleset) is listed under
`moved` in both files. The nightly check (`python3 -I src/suriharvest/sidmap_check.py OLD NEW
--manifest NEW_MANIFEST --previous-manifest PREVIOUS_MANIFEST --rules *.rules`) accepts exactly these transitions:
new rows (a new remapped sid above the old floor), owner reclaims, a revision take-over (only the logic hash
changes), and the retirement of rows without a note whose rule is in neither manifest (rows left out as duplicates
count as present; `SidMap.retire` uses the same predicate). It refuses every other changed or lost row, a lower
floor, any lost row without both manifests, and a manifest that misses a gid:sid of the published rules files.

Trust model of the nightly `state` job: OLD is the map at the tip of the dedicated `state` branch (the one the build
read; the job stops if the branch moved), NEW comes from the build artifact, and the checker itself runs from
`main`'s checkout, never from the artifact or the branch. The previous manifest, the only authority that allows a
row to be retired, is downloaded from the last **published** release, not taken from the build artifact or from the
`state` branch. The new map is checked a second time with OLD = the `sid-map.tsv` that last release shipped
(verified against its `SHA256SUMS`), so rows dropped from the `state` branch outside the job are caught too: the
previous published release stays the authority. The accepted map is pushed to `state` only (never to `main`), and every release ships its `sid-map.tsv`,
from which a lost `state` branch is restored (docs/automation.md#sid-map-state-branch).

Invariants the check enforces against the published rules files (`--rules`; it is a safety net, not a second
implementation: it reads gid:sid with the parser's own option splitter, `src/suriharvest/ruleopts.py`, which it
loads from its own folder when run as a script):

- every rule line in the files, enabled or commented out, has exactly one numeric sid and at most one numeric
  gid, and its gid:sid is a published row of the new manifest;
- a sid map row that exports a gid:sid found in the files belongs to a rule the manifest publishes (same logic
  hash, or same source and rule key);
- a row whose exported gid:sid is still in the files is never retired.

The first remapped sid is `remap_base` in `suriharvest.yaml` (default 1,900,000,000: above every range seen in
public feeds, below 2^31). Override it per export (`--remap-base`) or per profile (`profile set --remap-base`).
If you publish builds, request your own range at sidallocation.org and set `remap_base` to it.

Rules generated by `export --iocs-as-datasets` start at `--sid-base` (default 1,990,000,000). Every base is
checked against the shipped copy of the sidallocation.org registry (`src/suriharvest/catalog/sid-allocation.tsv`):
a base whose first 100,000 sids overlap an allocated range or the local range is refused.
