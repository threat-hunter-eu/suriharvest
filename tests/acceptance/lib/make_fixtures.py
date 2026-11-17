#!/usr/bin/env python3
"""Build the offline fixture git repositories for the acceptance harness (stdlib only).

    make_fixtures.py sigma    OUT     -> OUT/fixture-sigma-alpha, OUT/fixture-sigma-beta
    make_fixtures.py suricata OUT     -> OUT/fixture-suri-alpha,  OUT/fixture-suri-beta
    make_fixtures.py suricata-bump OUT  second commit in fixture-suri-alpha: sid 9000002 rev 2 -> rev 3
    make_fixtures.py sigma-bump OUT     second commit in fixture-sigma-alpha: the DNS rule keeps its id, new logic
    make_fixtures.py suricata-major OUT -> OUT/fixture-major/suricata-7/ and suricata-8/ (served over HTTP: one
                                         ruleset per Suricata major, ${suricata_version} in the source URL)

Files come from ../fixtures/; things that are awkward to keep in a source tree are added here:
- sigma: a rule whose file name is not valid UTF-8 (latin-1 byte 0xE9), same logic as proc_certutil.yml.
- The surrogate escape "\\ud800" is already in fixtures/sigma/alpha/rules/proc_whoami_surrogate.yml.
Each repo gets one commit with a fixed author/date, so commit SHAs are reproducible.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIX = HERE.parent / "fixtures"
GIT_ENV = {
    "GIT_AUTHOR_NAME": "Acceptance Fixture",
    "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
    "GIT_COMMITTER_NAME": "Acceptance Fixture",
    "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
    "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
    "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
    "GIT_CONFIG_NOSYSTEM": "1",
}

NON_UTF8_RULE = b"""title: Fixture Certutil Decode (latin-1 file name)
id: 6f8a1c2e-0002-4a5b-9c1d-000000000002
status: test
description: Same logic as Fixture Certutil Decode; stored under a file name that is not valid UTF-8.
author: Acceptance Fixture
date: 2026-01-03
tags:
    - attack.defense-evasion
    - attack.t1140
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\certutil.exe'
        CommandLine|contains: ' -decode '
    condition: selection
level: high
"""


def git(repo: Path, *args: str, date: str | None = None) -> None:
    env = {**os.environ, **GIT_ENV, "HOME": str(repo.parent)}
    if date:
        env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = date
    subprocess.run(["git", "-C", str(repo), *args], check=True, env=env, stdout=subprocess.DEVNULL)


def make_repo(src: Path, dest: Path, extra: dict[bytes, bytes] | None = None) -> None:
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(src, dest)
    for rel, data in (extra or {}).items():
        p = os.path.join(os.fsencode(dest), rel)
        with open(p, "wb") as fh:
            fh.write(data)
    git(dest, "init", "-q", "-b", "main")
    git(dest, "config", "core.quotepath", "off")
    git(dest, "add", "-A")
    git(dest, "commit", "-q", "-m", "fixture: initial rules")


# Per-major ruleset (ET Open style): the same file name under suricata-7/ and suricata-8/.
#   9200001 identical in both majors      -> one logic, published by both engines with the same sid
#   9200002 different detection per major -> two logics under one rule key, each engine publishes its own text
#   9200003 only in the Suricata 8 copy   -> only in suricata-8.rules
MAJOR_HEADER = """# fixture-major: synthetic per-major Suricata rules for the acceptance harness.
# Copyright (c) 2026 Major Fixture Publisher
# Licensed under the MIT licence.

"""
MAJOR_SHARED = 'alert dns any any -> any any (msg:"FIXTURE major shared"; dns.query; content:"major-shared.fixture.invalid"; nocase; classtype:bad-unknown; sid:9200001; rev:1;)\n'
MAJOR_RULES = {
    "7": MAJOR_SHARED
    + 'alert dns any any -> any any (msg:"FIXTURE major per-major text"; dns.query; content:"major-v7.fixture.invalid"; nocase; classtype:bad-unknown; sid:9200002; rev:1;)\n',
    "8": MAJOR_SHARED
    + 'alert dns any any -> any any (msg:"FIXTURE major per-major text"; dns.query; content:"major-v8.fixture.invalid"; nocase; classtype:bad-unknown; sid:9200002; rev:1;)\n'
    + 'alert dns any any -> any any (msg:"FIXTURE major only in 8"; dns.query; content:"major-only8.fixture.invalid"; nocase; classtype:bad-unknown; sid:9200003; rev:1;)\n',
}


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] not in ("sigma", "suricata", "suricata-bump", "sigma-bump", "suricata-major"):
        print(__doc__, file=sys.stderr)
        return 2
    kind, out = sys.argv[1], Path(sys.argv[2]).resolve()
    out.mkdir(parents=True, exist_ok=True)
    if kind == "sigma":
        # ACCEPT_FIXTURE_SKIP=nonutf8 leaves the latin-1 file name out (to isolate other failures; counts do not change)
        extra = {} if "nonutf8" in os.environ.get("ACCEPT_FIXTURE_SKIP", "") else {b"rules/proc_certutil_copie_\xe9.yml": NON_UTF8_RULE}
        make_repo(FIX / "sigma" / "alpha", out / "fixture-sigma-alpha", extra)
        make_repo(FIX / "sigma" / "beta", out / "fixture-sigma-beta")
    elif kind == "suricata":
        make_repo(FIX / "suricata" / "alpha", out / "fixture-suri-alpha")
        make_repo(FIX / "suricata" / "beta", out / "fixture-suri-beta")
    elif kind == "sigma-bump":
        repo = out / "fixture-sigma-alpha"
        f = repo / "rules" / "dns_fixture_domain.yml"
        text = f.read_text(encoding="utf-8")
        if "'.fixture.invalid'" not in text:
            print("sigma-bump: DNS rule already bumped?", file=sys.stderr)
            return 1
        f.write_text(text.replace("'.fixture.invalid'", "'.fixture-bumped.invalid'"), encoding="utf-8")
        git(repo, "commit", "-q", "-am", "fixture: DNS rule detects another domain (same id)", date="2026-01-02T00:00:00Z")
    elif kind == "suricata-major":
        root = out / "fixture-major"
        for major, body in MAJOR_RULES.items():
            d = root / f"suricata-{major}"
            d.mkdir(parents=True, exist_ok=True)
            (d / "fixture-major.rules").write_text(MAJOR_HEADER + body, encoding="utf-8")
        print(root)
        return 0
    else:
        repo = out / "fixture-suri-alpha"
        f = repo / "fixture-alpha.rules"
        text = f.read_text(encoding="utf-8")
        old = 'http.user_agent; content:"FixtureBot"; classtype:trojan-activity; sid:9000002; rev:2;'
        new = 'http.user_agent; content:"FixtureBot/2"; classtype:trojan-activity; sid:9000002; rev:3;'
        if old not in text:
            print("bump: rev 2 line not found (already bumped?)", file=sys.stderr)
            return 1
        f.write_text(text.replace(old, new), encoding="utf-8")
        git(repo, "commit", "-q", "-am", "fixture: sid 9000002 rev 3", date="2026-01-02T00:00:00Z")
    for p in sorted(out.iterdir()):
        print(p)
    return 0


if __name__ == "__main__":
    sys.exit(main())
