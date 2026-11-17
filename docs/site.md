# Static rules site

`suriharvest site build OUT --release DIR` turns a release folder (only `summary.json` is required; the manifest,
`changes.json`, `validation.json`, `collisions.json`, `NOTICE.md` and `SHA256SUMS` are used when present) into a
static site: overview with download links and checksums, sources, changes, Suricata check, notice, and a search
page that filters a metadata index (`search-index.json`: msg, gid, sid, source, licence, engines) in the browser.
It needs no workspace and shows no rule text. Pages reuse the web UI's stylesheet, icons, fonts and template
macros; there is no inline script or style, and each page carries a `Content-Security-Policy` meta tag. Options:
`--tag`, `--download-base` (prefix of the download links), `--base-url` (path the site is served under, e.g.
`/suriharvest/`), `--site-url` (origin, for canonical links), `--build-epoch`. Same input, same bytes.

Every page footer names where to ask for a correction or a removal: the repository's issues and the address
`security@threat-hunting.eu` (the project's role address, read by the maintainers; `SURIHARVEST_CONTACT`
overrides it for a fork, an empty value hides it; `SURIHARVEST_REPO` sets the repository). The same address is the
`Contact:` of `.well-known/security.txt` (RFC 9116, expires one year after `--build-epoch`; the Pages workflow
uploads hidden files for it).
