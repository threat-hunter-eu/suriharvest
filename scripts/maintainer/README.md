# Maintainer tooling

Not needed to use or contribute to the tool; contributors only need `scripts/ci-full-local.sh`.

- `privacy_gate.py`: the CI privacy gate (secrets, private paths, non-noreply e-mails; tree and history), stdlib only.
- `pypi_readme.py`: makes README links absolute for the PyPI page (run by `publish.yml` before `uv build`).
- `screenshots.py`: regenerates `docs/screenshots/` and `docs/social-preview.png` from a running demo workspace.
- `refresh_catalog.py`: checks every catalog source upstream (same as `suriharvest sources check`); a human edits the catalog.
