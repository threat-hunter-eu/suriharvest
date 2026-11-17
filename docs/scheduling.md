# Unattended updates

`suriharvest update` runs: sync every enabled source -> validate new rules in every engine of `suriharvest.yaml` ->
rebuild the index -> compare counts with the last passing run (gates) -> write `reports/runs/<stamp>.md`
and `.json` (reports that older versions wrote to `reports/update-*.md` are moved there by the next update). Exit
code 0 = everything passed; 1 = a source or a gate failed; 2 = bad options, not a workspace, the workspace is busy,
or the database schema is behind (`suriharvest doctor`); see [exit codes](cli.md#runs-health-and-scripting).

## Gates

| gate | fails when | usual cause |
|---|---|---|
| unique logic | live unique logic drops more than 5% | a source emptied or rewritten; a parser/identity regression |
| quarantine | unparsable lines grow more than 20% **and** by 50+ | parser regression; a new source with broken lines |
| failed sources | more than 10% of enabled sources fail to fetch (1 always allowed, unless every enabled source failed: with one source, its failure fails the run) | network, rate limit, a source moved or died |
| rules | the corpus has no rules after the run | every source failed on the first run, or no source is enabled |
| index complete | a live logic is missing from the index | interrupted index: run `suriharvest index` |
| loads in `<engine>` | rules that do not load grow more than 20% **and** by 50+ | engine upgrade, config change, a source shipping rules for a newer Suricata |

The `rules` gate and the "every enabled source failed" case apply with `--allow-failures` too: an update that
updated nothing exits 1. A failed run never becomes the baseline. When a change is intended (a source removed on
purpose), make that run the baseline with `suriharvest runs accept <id>`. `suriharvest runs list` and
`suriharvest runs show latest` show history and reports. A failed source keeps its previous rules, so a network outage cannot shrink the corpus by itself.

## systemd

Files in [`deploy/systemd/`](../deploy/systemd/): `suriharvest-update.service` (oneshot, waits up to 10 minutes for a busy workspace),
`suriharvest-update.timer` (daily 05:15, `Persistent=true`), `suriharvest-update-failed@.service` (OnFailure hook:
replace its ExecStart with your notifier). Tokens for sources that need one (`auth:`) go in `/etc/suriharvest/env`
(`EnvironmentFile=`), never in sources.yaml.

On WSL, systemd works when `/etc/wsl.conf` has `[boot] systemd=true`; the timer runs only while the WSL VM is up.
A Windows Task Scheduler entry running `wsl.exe -u root -- /opt/suriharvest/.venv/bin/suriharvest update` (with
`SURIHARVEST_HOME` exported) is the alternative.
