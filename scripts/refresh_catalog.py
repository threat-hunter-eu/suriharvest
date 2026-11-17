"""Compare the bundled source catalog with the OISF suricata-update index and check that every source answers.

Usage: uv run python scripts/refresh_catalog.py   (same as `suriharvest sources check`)
"""

from __future__ import annotations

import sys

from suriharvest.catalog_check import check, render_report

if __name__ == "__main__":
    result = check()
    print(render_report(result))
    sys.exit(result.exit_code)
