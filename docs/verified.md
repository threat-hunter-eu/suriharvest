# Facts checked while building the source catalog (2026-11-05, rechecked 2026-11-14)

| item | result |
|---|---|
| OISF index | https://www.openinfosecfoundation.org/rules/index.yaml, `version: 1`; per source: vendor, summary, `license`, `url` with `%(__version__)s`, `parameters.secret-code` for paid feeds, `min-version`, `obsolete`, `deprecated`, `replaces`. Recommended Suricata: 8.0.8. 16 free, current sources after filtering. |
| ET Open URL | `https://rules.emergingthreats.net/open/suricata-<ver>/emerging.rules.tar.gz` answers 200 for 6.0, 7.0, 7.0.3, 8.0, 8.0.8. Licence in the index: MIT. |
| ET Open size | 7.0.3 tarball: 61 rule files, 72,366 rules, 18,825 disabled by default, 0 unparsable. |
| ET sid range | 2,000,005 - 2,9xx,xxx in ET Open; OISF traffic-id uses 300,000,000+. |
| ET metadata keys | signature_severity, created_at, updated_at (all rules), confidence, deployment, attack_target, tag, mitre_tactic_id/name, mitre_technique_id/name (33.5k rules), affected_product, performance_impact, malware_family, reviewed_at, deprecation_reason (5.5k), former_category, cve, former_sid (258). |
| ptresearch/attackdetection | marked `obsolete: no longer exists` in the OISF index; ptrules/open (rules.ptsecurity.com) replaces it but did not answer when checked. |
| abuse.ch/urlhaus | listed as current, but the URL returns HTTP 410 Gone. |
| `suricata -T` errors | `E: detect: error parsing signature "<rule>" from file F at line N`, preceded by the cause (`unknown rule keyword 'x'`, `protocol "modbus" cannot be used ...`, `datasets: fopen 'x' failed`). Suricata continues after a bad rule, so one run reports all of them. Exit code 1 when any failed. |
| Protocols disabled by default | modbus, dnp3, enip, ... need `--set app-layer.protocols.<p>.enabled=yes` and `detection-enabled=yes`. |
| Suricata 8 only | the `domain` transform (ipfire-dbl) fails in 7.0.3 as `unknown rule keyword`. |

Not checked yet: container images and digests for Suricata 6, `--engine-analysis` output format, pcap dataset
licences.
