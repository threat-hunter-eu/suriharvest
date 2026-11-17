# FAQ

**Does this replace suricata-update?**
No. suricata-update is the standard way to install rules on a sensor, and suriharvest's nightly release is a
suricata-update source. suriharvest does the work before that: combining many sources, deduplicating by logic,
resolving sid collisions and testing everything on real engines.

**Why not just use ET Open?**
ET Open is the backbone and has the top priority. But useful free rules also come from abuse.ch, Positive
Technologies, Stamus, Travis Green, community GitHub repositories and others. Combining them by hand means dealing
with duplicates, sid clashes, Snort-only syntax and rules that need Suricata 8. That is what suriharvest automates.

**I enabled suriharvest in suricata-update and now see "duplicate sid" warnings.**
You probably still have `et/open` (or another source suriharvest includes) enabled. Run
`suricata-update list-enabled-sources` and disable the overlap, e.g. `suricata-update disable-source et/open`.

**Which Suricata versions are supported?**
7.0.x and 8.0.x. 6.0 is end-of-life and not tested. Validate on the same major version your sensors run; the
nightly release has one ruleset per major.

**Why are some rules missing for Suricata 7?**
Some rules use Suricata 8 features (the `domain` transform, newer keywords). They load on 8 only and are left out
of the Suricata 7 ruleset. `suriharvest search 'fails:local'` shows what fails on your engine and why
(`suriharvest show SID`).

**Do I need Docker?**
No. A local `suricata` binary is enough. Docker is handy to validate on several versions without installing them.

**Can I run it without Suricata?**
Yes, with `suriharvest update --no-validate`, but you lose the main safety net: knowing that every rule loads.

**How long does an update take?**
First run: a few minutes (about 100k rules validated). Daily runs: under a minute when nothing changed, a minute or
two otherwise; only new or changed rules are validated.

**Will my sids stay stable?**
Original sids are only changed when two publishers collide on one `gid:sid` (profiles and releases remap the
loser; a plain `export` asks first). The publisher that owns the range at sidallocation.org keeps its sid. Every
decision is recorded in `state/sid-map.tsv` and reused in later builds. Back that file up.

**What happens if a source goes down or ships a broken file?**
The source keeps its last good copy and the run report lists it. If a source suddenly loses most of its rules, or
the corpus drops sharply, the update gate stops and nothing is rebuilt. Check with `suriharvest runs show latest`;
if the change is real, `suriharvest runs accept latest`.

**How do I stop a noisy rule from coming back after every update?**
Exclude it in your profile (`suriharvest profile exclude default SID --kind sid --reason "..."`). Exclusions are
applied on every build and survive upstream changes; matching by message or logic also survives sid changes.
If you feed suricata-update with `export --format suricata-update`, load the exported `disable.conf` too
([export.md](export.md#feeding-suricata-update)).

**I excluded a rule and the build did not change.**
The rule was not in the build: its publisher ships it disabled (the `on` column in `suriharvest show SID` says
`no`; many deprecated ET rules are), or it does not load on the profile's engine. `profile build` prints what each
exclusion removed (`excluded by: sid 1`); `profile diff` shows the rules that left.

**How do I find the rules for a CVE?**
`suriharvest search CVE-2021-44228` (the same as `cve:CVE-2021-44228`, also in the web search and
`/api/search`): rules that name the CVE in the message, a `reference:cve` or `metadata: cve`. See
[cli.md](cli.md#rules-for-a-cve).

**Can I add rules from a commercial feed I pay for?**
Yes, locally: add it as a source with `--auth` and `--redistribute no`. Never publish or commit those rules, and
check your licence terms. The public project never includes commercial feeds.

**Is PAW Patrules / URLhaus / ThreatFox included?**
Not in the public release (non-commercial licence or personal key required). You can add them to your own
workspace; see [sources.md](sources.md#sources-that-need-a-key-or-forbid-redistribution).

**Does it handle Snort rules?**
Rules in Snort syntax are detected (`dialect:snort`) and kept out of builds unless they actually load in Suricata.
Snort community rules are in the experimental tier.

**Can I expose the web UI to my team?**
It binds to `127.0.0.1` by default. Binding elsewhere requires an access token (`suriharvest serve --host 0.0.0.0
--token-env VAR`); put TLS in front with a reverse proxy.

**Does it send any data anywhere?**
No telemetry. It only contacts the source URLs you enabled.


**How does suriharvest compare with other Suricata tools?**
suriharvest is a *producer* of rulesets; suricata-update is the best *consumer*, and they work together. If you only
use ET Open, `suricata-update` alone is the simplest choice. suriharvest helps when you combine many free sources
and want duplicates, collisions and broken rules handled for you.

| | suriharvest | [suricata-update](https://github.com/OISF/suricata-update) | [Scirius CE](https://github.com/StamusNetworks/scirius) | [suricata-check](https://github.com/Koen1999/suricata-check) | [Suricata Language Server](https://github.com/StamusNetworks/suricata-language-server) | [Aristotle](https://github.com/secureworks/aristotle) |
|---|---|---|---|---|---|---|
| What it is | Aggregator + build tool | Official rule updater | Ruleset management web app | Static rule linter | Editor / CI diagnostics | Metadata-based rule filter |
| Fetch many sources | Yes (catalog + GitHub repos) | Yes (OISF index) | Yes | No | No | No |
| Validate with `suricata -T` | Yes, several engine versions | Yes, one local engine | Via the sensor | No (static checks) | Yes (real binary) | No |
| Dedup by sid | Yes, per publisher namespace | Keeps the highest rev | Per ruleset | No | Workspace sid conflicts | No |
| Dedup by logic | Yes | No | No | No | No | No |
| sid collision policy | Priority + stable remap map | One silently wins | Manual | Flags | Flags | No |
| Exclusions | Profiles with reasons and review dates | `disable.conf` / `drop.conf` / `modify.conf` | Per-rule UI | n/a | n/a | Boolean filters |
| Per-rule licence + provenance | Yes | No | No | No | No | No |
| Build diff / history | Yes | No | Partial | No | No | No |
| Licence | MIT | GPL-2.0 | GPL-3.0 | EUPL-1.2 | GPL-3.0 | Apache-2.0 |

**suriharvest or suricata-update?**

- **Same job on a sensor, different scope.** suricata-update fetches the sources you enable from the OISF index,
  applies `enable/disable/drop/modify.conf`, resolves flowbits and writes one `suricata.rules` for the local
  engine. suriharvest builds rulesets from many free sources, for one or more engine versions, ahead of time.
- **Duplicates.** suricata-update keeps the highest `rev` of each `gid:sid` it reads. suriharvest also merges the
  same detection logic shipped under different sids, and gives a colliding rule a new sid that is recorded and
  stays stable, instead of dropping one of the two.
- **Validation.** suricata-update runs `suricata -T` on the result and fails the update if it does not load.
  suriharvest tests each rule, leaves out the ones that fail (with the reason) and still ships the rest.
- **Your local decisions.** suricata-update keeps them in four `.conf` files; suriharvest keeps them in a profile
  (exclusions with reasons and review dates, enable/modify/threshold entries) and can import the `.conf` files.
  A random 80-configuration comparison against suricata-update 1.3.3 gives the same enabled rules in all cases;
  the remaining text differences come from one suricata-update behaviour documented in
  [profiles.md](profiles.md#coming-from-suricata-update) (modify lines on rules drop.conf changed).
- **They combine.** Point suricata-update at the nightly release, or at the suricata-update export of your own
  build ([docs/suricata-update.md](suricata-update.md)).
