# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | yes |

Security fixes go into the latest release and `main`.

## Reporting a vulnerability

Please report security problems **privately**, not in a public issue: write to
[security@threat-hunting.eu](mailto:security@threat-hunting.eu) (read by the maintainers), or, once the repository is
public, use GitHub's private vulnerability reporting, the *Report a vulnerability* button on the **Security**
tab of this repository
(<https://github.com/threat-hunter-eu/suriharvest/security/advisories/new>). The report and the discussion stay visible
to the maintainers and you only, until an advisory is published. If the button is missing, private reporting is not
enabled yet: use the e-mail address. Include the suriharvest version
or commit, what an attacker controls
(a source URL? a rule file? a web request?), and a minimal reproduction. You should get a first answer within 7
days; we will agree on a disclosure date and credit you if you wish.

## Threat model

suriharvest downloads and parses third-party content and treats all of it as **untrusted**:

- **Downloads**: size limits (per file, per archive, member count), conditional requests, safe archive extraction
  (absolute paths, `..`, symlinks, hardlinks and device files are skipped), a corrupt archive fails only its own
  source. Git: only https, ssh and local paths, `-`-prefixed URLs and refs refused, hooks disabled, bare clones
  without checkout or submodules. A git token is sent as `http.<origin>.extraHeader` (only to the source's own
  scheme, host and port) and git does not follow redirects (`http.followRedirects=false`).
- **Where downloads connect**: every connection (including each redirect hop) resolves the host once, refuses
  it unless all addresses are public, and connects to that checked address (no DNS rebinding window). Internal
  mirrors need `allow_private: true` on the source or `SURIHARVEST_ALLOW_PRIVATE_DOWNLOADS=1`. Redirects never go
  from https to http, at most 10 are followed, and a download has a total deadline
  (`SURIHARVEST_DOWNLOAD_DEADLINE`, 900 s) that covers connecting, TLS, response headers and body.
- **Proxies**: `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` and `NO_PROXY` are honoured for http sources (git uses
  its own proxy settings). The address check still applies: suriharvest resolves the name itself, refuses it
  unless every address is public (also when it cannot be resolved: fail closed), and asks the proxy for that
  checked address (`GET http://<ip>/...` or `CONNECT <ip>:443`, with the real name in `Host`, SNI and the
  certificate check), so the proxy cannot be steered elsewhere by another DNS answer. Behind a proxy without
  local DNS set `SURIHARVEST_TRUST_PROXY=1`: the proxy then resolves the names and **must enforce its own
  internal-address deny policy** (suriharvest still refuses `localhost`, internal IP literals in every notation (decimal, hex, octal, short IPv4; IPv6 that is internal or embeds an internal IPv4; 6to4, Teredo and IPv4-compatible IPv6 are refused outright), and names its own resolver maps to internal addresses). Hosts in
  `NO_PROXY` are fetched directly, with the usual pinning.
- **Published files** never carry fetch URLs with credentials: userinfo, query strings and fragments are removed,
  local paths are dropped, and a source's homepage is shown instead of its fetch URL when it has one. Licence files
  are copied only from redistributable sources (local folders only what `licence_files` names). Copied upstream
  notices cannot end in a backslash, and every release file is checked to load exactly the announced number of
  rules.
- **Rule text**: parsed by suriharvest's own parser; never executed. Validation runs `suricata -T` with a minimal
  config. With Docker engines it runs as `docker run --rm --network=none`. Lua rules are not allowed in validation.
- **Keys** for sources that need one are read from environment variables named in `sources.yaml` (`auth:`). They
  are never written to `sources.yaml`, logs, reports or the database.
- **The web UI** binds to `127.0.0.1` and accepts only local `Host` headers (DNS rebinding). Binding to another
  address requires an access token (`--token-env`). Writes require a same-origin request with a CSRF token; bodies
  are capped; a strict Content-Security-Policy forbids inline scripts; rule text is autoescaped.

Out of scope: the detection quality of third-party rules, and denial of service against your sensor by a rule that
loads but is expensive (review `performance_impact` and test on your traffic).

## Verifying a release

`SHA256SUMS.sigstore.json` is present only when the repository is public and the maintainers enabled signing
(`SURIHARVEST_SIGNING_ENABLED`, docs/automation.md); `sha256sum --check` works on every release.

The files (and `SHA256SUMS.sigstore.json`) are assets of the data repository
[suriharvest-rules](https://github.com/threat-hunter-eu/suriharvest-rules/releases); they are built and signed by this
repository's workflow, so the identity below names `threat-hunter-eu/suriharvest`.

```bash
sha256sum --check --ignore-missing SHA256SUMS

cosign verify-blob SHA256SUMS \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/threat-hunter-eu/suriharvest/\.github/workflows/nightly\.yml@'
```

The signature is made by the `sign` job of `.github/workflows/nightly.yml` running on the default branch, so
the identity is `https://github.com/threat-hunter-eu/suriharvest/.github/workflows/nightly.yml@refs/heads/main`
(the nightly workflow is opt-in: there is no signed release until it has been switched on).

Every release is also re-validated in clean Suricata 7 and 8 containers before it is published.

## Dependency advisories

`pip-audit` over `uv.lock` (all groups) reports no known advisory today. Dependabot (`.github/dependabot.yml`)
proposes weekly grouped updates for the GitHub Actions pins and `uv.lock`; the nightly build pins its Suricata
images by digest.
