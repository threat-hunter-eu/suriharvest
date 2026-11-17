"""Where corrections, attribution fixes and removal requests go, and the project's non-affiliation statement.

The repository is `owner/name` on GitHub. SURIHARVEST_REPO overrides it (a fork or a mirror); the default follows the
repository the project is published from (the public-release script rewrites it to the launch organisation).
"""

from __future__ import annotations

import os
import re
from datetime import UTC, datetime, timedelta

DEFAULT_REPO = "threat-hunter-eu/suriharvest"
# The organisation's public role address: security reports (SECURITY.md, security.txt) and correction/removal requests.
SECURITY_CONTACT = "security@threat-hunting.eu"
# Shown next to the issues link on the site and in the UI; SURIHARVEST_CONTACT overrides it (a fork), empty hides it.
CONTACT_EMAIL = os.environ.get("SURIHARVEST_CONTACT", SECURITY_CONTACT).strip()
NOT_AFFILIATED = "Not affiliated with or endorsed by SigmaHQ, OISF, Proofpoint/Emerging Threats or MITRE."
TRADEMARKS = (
    "Suricata and OISF are trademarks of the Open Information Security Foundation. Emerging Threats and Proofpoint are "
    "trademarks of Proofpoint, Inc. MITRE ATT&CK® and ATT&CK® are registered trademarks of The MITRE Corporation."
)


def repo() -> str:
    """`owner/name` of the project repository (SURIHARVEST_REPO when it is a valid GitHub slug)."""
    value = os.environ.get("SURIHARVEST_REPO", "").strip()
    return value if re.fullmatch(r"[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}", value) else DEFAULT_REPO


def repo_url() -> str:
    return f"https://github.com/{repo()}"


def issues_url() -> str:
    """Where to ask for a correction or for a rule to be removed."""
    return f"{repo_url()}/issues"


def security_txt(issued: datetime, canonical: str = "") -> str:
    """RFC 9116 security.txt for the published site, valid for a year from `issued` (the build time)."""
    expires = issued.astimezone(UTC).replace(microsecond=0) + timedelta(days=365)
    lines = ["# Report security problems privately, not in a public issue (see Policy)."]
    if CONTACT_EMAIL:
        lines.append(f"Contact: mailto:{CONTACT_EMAIL}")
    lines += [f"Contact: {repo_url()}/security/advisories/new", f"Expires: {expires:%Y-%m-%dT%H:%M:%SZ}", "Preferred-Languages: en"]
    if canonical:
        lines.append(f"Canonical: {canonical}")
    lines.append(f"Policy: {repo_url()}/blob/main/.github/SECURITY.md")
    return "\n".join(lines) + "\n"
