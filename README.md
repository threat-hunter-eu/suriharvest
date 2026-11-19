<p align="center">
  <img src="src/suriharvest/web/static/favicon.svg" width="84" alt="suriharvest logo">
</p>

<h1 align="center">suriharvest</h1>

<p align="center">
  <b>Free Suricata rulesets, merged, deduplicated and tested on a real engine.</b><br>
  One ruleset per Suricata version that loads cleanly, with every rule's source and licence.
</p>

<p align="center">
  <a href="https://github.com/threat-hunter-eu/suriharvest/actions/workflows/ci.yml"><img src="https://github.com/threat-hunter-eu/suriharvest/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/threat-hunter-eu/suriharvest/blob/main/LICENSE"><img src="https://img.shields.io/badge/licence-MIT-2456b5" alt="MIT licence"></a>
  <img src="https://img.shields.io/badge/python-3.12%2B-2456b5" alt="Python 3.12+">
</p>

<p align="center">
  <a href="https://threat-hunting.eu/tools/suriharvest">Website</a> ·
  <a href="#quickstart">Quickstart</a> ·
  <a href="https://github.com/threat-hunter-eu/suriharvest/blob/main/docs/features.md">Features</a> ·
  <a href="#download-the-rules">Download the rules</a> ·
  <a href="#documentation">Docs</a>
</p>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/overview-dark.png">
  <img src="docs/screenshots/overview-light.png" alt="suriharvest overview: unique rules, load rate in local Suricata, duplicates merged, rulesets and top sources">
</picture>

suriharvest downloads the free rulesets (ET Open, abuse.ch, Stamus, OISF Traffic ID and more), tests **every rule
with `suricata -T`**, merges duplicates, fixes sid clashes with stable new sids, and builds the ruleset your sensors
load, directly or through suricata-update. Every rule keeps its source and licence.

## Quickstart

You need Python 3.12+, [uv](https://docs.astral.sh/uv/) (or [pipx](https://pipx.pypa.io/): `pipx install suriharvest`)
and Suricata (or Docker) to test the rules.

<!-- doctest -->
```bash
uv tool install suriharvest
suriharvest init ~/suri && cd ~/suri && suriharvest update   # first run: a few minutes
suriharvest serve                                            # http://127.0.0.1:8077
```

Development version from Git: `uv tool install git+https://github.com/threat-hunter-eu/suriharvest`.
Prefer the terminal: `suriharvest search 'cobalt strike'`, `suriharvest profile build default`.
Suricata 8, Docker engines and no local Suricata: [Getting started](https://github.com/threat-hunter-eu/suriharvest/blob/main/docs/getting-started.md).

## Highlights

- **Tested on the real engine**: every rule goes through `suricata -T` on each engine you add (Suricata 7 and 8).
- **Duplicates merged** by sid and by detection logic; **sid clashes fixed** with new sids that stay stable.
- **Flowbits aware**: a rule that needs a flowbit brings the rule that sets it.
- **Coming from suricata-update**: `profile import-conf` reads your `enable/disable/drop/modify.conf`.
- **Licence-aware**: every rule keeps its publisher's licence; `--redistributable-only` gives a file you can share.
- **Local and private**: the web UI binds to 127.0.0.1 and loads nothing from the internet.

Screenshots of search, rule pages, export and builds, and how the pipeline works: [Features](https://github.com/threat-hunter-eu/suriharvest/blob/main/docs/features.md).

## Download the rules

No install needed: the **[suriharvest-rules](https://github.com/threat-hunter-eu/suriharvest-rules/releases/latest)**
nightly release has the redistributable free rulesets, merged, deduplicated and tested on Suricata 7 and 8. The
first release (`rules-2026-11-17`): 65,968 rules per engine, 0 load errors. Every file: [suricata-update](https://github.com/threat-hunter-eu/suriharvest/blob/main/docs/suricata-update.md).

<!-- doctest: skip downloads the nightly release (root, network) -->
```bash
sudo suricata-update add-source suriharvest-8 \
  https://github.com/threat-hunter-eu/suriharvest-rules/releases/latest/download/suriharvest-8.tar.gz
sudo suricata-update
```

## Documentation

| | |
|---|---|
| **Start** | [Getting started](https://github.com/threat-hunter-eu/suriharvest/blob/main/docs/getting-started.md) · [Features](https://github.com/threat-hunter-eu/suriharvest/blob/main/docs/features.md) · [CLI recipes](https://github.com/threat-hunter-eu/suriharvest/blob/main/docs/cli.md) · [Web UI](https://github.com/threat-hunter-eu/suriharvest/blob/main/docs/web.md) · [FAQ](https://github.com/threat-hunter-eu/suriharvest/blob/main/docs/faq.md) |
| **Rulesets** | [Profiles](https://github.com/threat-hunter-eu/suriharvest/blob/main/docs/profiles.md) · [Export](https://github.com/threat-hunter-eu/suriharvest/blob/main/docs/export.md) · [suricata-update](https://github.com/threat-hunter-eu/suriharvest/blob/main/docs/suricata-update.md) · [Sources and licences](https://github.com/threat-hunter-eu/suriharvest/blob/main/docs/sources.md) |
| **Run it** | [Releases](https://github.com/threat-hunter-eu/suriharvest/blob/main/docs/releases.md) · [Unattended updates](https://github.com/threat-hunter-eu/suriharvest/blob/main/docs/scheduling.md) · [GitHub Actions](https://github.com/threat-hunter-eu/suriharvest/blob/main/docs/automation.md) · [Architecture](https://github.com/threat-hunter-eu/suriharvest/blob/main/docs/architecture.md) |

## Contributing

Contributions are welcome: see [CONTRIBUTING](https://github.com/threat-hunter-eu/suriharvest/blob/main/.github/CONTRIBUTING.md); security reports: [SECURITY](https://github.com/threat-hunter-eu/suriharvest/blob/main/.github/SECURITY.md).
Maintainers: [@angstromissa](https://github.com/angstromissa), [@elhoim](https://github.com/elhoim).

## Licence

suriharvest is released under the [MIT licence](https://github.com/threat-hunter-eu/suriharvest/blob/main/LICENSE). Every rule keeps its publisher's licence; the only
changes to rule text (a new sid on a clash, a dataset path) are noted in each rules file's header
([rule licences](https://github.com/threat-hunter-eu/suriharvest/blob/main/docs/sources.md#licences), [NOTICE](https://github.com/threat-hunter-eu/suriharvest/blob/main/NOTICE)). To have a rule corrected or removed,
[open an issue](https://github.com/threat-hunter-eu/suriharvest/issues) or write to security@threat-hunting.eu.

Not affiliated with or endorsed by SigmaHQ, OISF, Proofpoint/Emerging Threats or MITRE. Suricata and OISF are
trademarks of the Open Information Security Foundation; Emerging Threats and Proofpoint are trademarks of
Proofpoint, Inc.; MITRE ATT&CK® and ATT&CK® are registered trademarks of The MITRE Corporation.
