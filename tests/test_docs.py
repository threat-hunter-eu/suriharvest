"""The shell examples in README.md and docs/*.md must work as written.

Every ```bash block in the docs carries a marker on the line above it:

    <!-- doctest -->                 run it (commands that need the network or root are skipped, see SKIP below)
    <!-- doctest: skip REASON -->    never run it (a server, a remote host, a placeholder, ...)

A block of any language marked `<!-- doctest: write PATH -->` is appended to ~/suri/PATH when the run reaches it
(an exclusions file with overrides, a suricata-update disable.conf), so the examples that follow use exactly the
file the docs show.

`test_every_bash_block_is_marked` (plain pytest) makes sure no new block escapes. `test_doc_commands_run` (marker
`docs`, needs a real `suricata`) runs the marked blocks of each file, in order, in one shell, against an offline fixture
workspace: `suriharvest init` + every source replaced by a local folder of synthetic rules (same names, namespaces and
sids as the doc examples), then `suriharvest update`. HOME points at a scratch folder, so `~/suri` is the fixture.

    uv run pytest -m docs tests/test_docs.py
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
DOC_FILES = [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]
MARK = re.compile(r"<!--\s*doctest(?::\s*(?P<verb>skip|write)\b\s*(?P<arg>[^>]*?))?\s*-->")

# Commands that are never run: they need the network, root, a long-running server or a remote host. Matched on the
# first word(s) of a command after `\` continuations are joined.
SKIP = (
    (r"(sudo|wget|uv|pipx|docker|apt|add-apt-repository|systemctl|git|suricata-update|crontab)\b", "network/root"),
    (r"curl\b(?!.*127\.0\.0\.1:8077)", "network"),  # curl to the local web UI runs: the harness starts it
    (r"suriharvest (serve|web)\b", "long-running server"),
    (r"suriharvest sources check\b", "downloads the OISF index"),
)
NEEDS = {"jq": "jq", "suricata": "suricata"}  # a command whose tool is missing is skipped (CI installs both)


def blocks(path: Path) -> list[tuple[int, str, str | None, str, str]]:
    """(line, language, marker, argument, code) for every fenced block. marker: 'run', 'skip', 'write' (the block is
    a file the following examples use: written, appended, to the path given relative to ~/suri) or None."""
    lines = path.read_text(encoding="utf-8").splitlines()
    out, i = [], 0
    while i < len(lines):
        if lines[i].startswith("```"):  # an opening fence (the closing one is skipped below)
            j = i - 1
            while j >= 0 and not lines[j].strip():
                j -= 1
            m = MARK.search(lines[j]) if j >= 0 else None
            marker = None if m is None else (m.group("verb") or "run")
            k = i + 1
            while k < len(lines) and lines[k].strip() != "```":
                k += 1
            out.append((i + 1, lines[i][3:].strip(), marker, (m.group("arg") or "").strip() if m else "", "\n".join(lines[i + 1 : k])))
            i = k
        i += 1
    return out


def bash_blocks(path: Path) -> list[tuple[int, str | None, str]]:
    """(line, marker, code) for every ```bash block; marker is 'run', 'skip' or None (unmarked)."""
    return [(line, marker, code) for line, lang, marker, _, code in blocks(path) if lang == "bash"]


def commands(code: str) -> list[str]:
    """Logical commands of a block: `\\` continuations joined, blank lines and comment-only lines dropped."""
    out, cur = [], ""
    for line in code.splitlines():
        if line.rstrip().endswith("\\"):
            cur += line.rstrip()[:-1] + " "
            continue
        cur += line
        if cur.strip() and not cur.strip().startswith("#"):
            out.append(cur.strip())
        cur = ""
    return out


def skip_reason(cmd: str) -> str | None:
    for pat, why in SKIP:
        if re.match(pat, cmd):
            return why
    first = cmd.split()[0]
    if first in NEEDS and shutil.which(NEEDS[first]) is None:
        return f"{first} not installed"
    if first == "suricata" and "/etc/suricata/suricata.yaml" in cmd and not Path("/etc/suricata/suricata.yaml").is_file():
        return "no /etc/suricata/suricata.yaml"
    return None


def test_every_bash_block_is_marked():
    """A new example must say whether it runs (and then it is tested) or why not."""
    unmarked = [f"{p.relative_to(ROOT)}:{line}" for p in DOC_FILES for line, marker, _ in bash_blocks(p) if marker is None]
    assert not unmarked, "bash blocks without <!-- doctest --> or <!-- doctest: skip REASON -->: " + ", ".join(unmarked)
    runnable = [p for p in DOC_FILES if any(m == "run" for _, m, _ in bash_blocks(p))]
    assert {"README.md", "getting-started.md", "cli.md", "export.md", "profiles.md"} <= {p.name for p in runnable}


def test_markdown_tables_render():
    """Every run of `|` lines outside code blocks is a table GitHub renders: a header row, then a `|---|` row with
    as many columns. A blank line inside a table leaves the rows after it as plain text."""
    bad = []
    for p in DOC_FILES:
        fence, run = False, []
        for n, line in enumerate([*p.read_text(encoding="utf-8").splitlines(), ""], start=1):
            if line.startswith("```"):
                fence = not fence
            if not fence and line.startswith("|"):
                run.append((n, line))
                continue
            if run:

                def cols(x):
                    return len(re.split(r"(?<!\\)\|", x.strip().strip("|")))

                head, sep = run[0], run[1] if len(run) > 1 else (run[0][0], "")
                if not re.fullmatch(r"\|(\s*:?-+:?\s*\|)+", sep[1].strip()) or cols(sep[1]) != cols(head[1]):
                    bad.append(f"{p.relative_to(ROOT)}:{head[0]}")
                run = []
    assert not bad, "tables without a |---| row under their header (a blank line inside a table?): " + ", ".join(bad)


def test_local_images_exist():
    """Every image a document shows is in the repository (getting-started once pointed at a missing search.png)."""
    missing = [
        f"{p.relative_to(ROOT)}: {m}"
        for p in DOC_FILES
        for m in re.findall(r"!\[[^\]]*\]\(([^)\s]+)\)", p.read_text(encoding="utf-8"))
        if not m.startswith(("http://", "https://")) and not (p.parent / m).is_file()
    ]
    assert not missing, missing


def test_tarball_is_not_described_with_by_source_copies():
    """Suriharvest-N.tar.gz carries rules/suricata.rules only (suricata-update loads every
    *.rules member, per-source copies would be duplicates); no document may list rules/by-source/ in it."""
    texts = [*DOC_FILES, ROOT / "src" / "suriharvest" / "release.py"]
    bad = [str(p.relative_to(ROOT)) for p in texts if "rules/by-source" in p.read_text(encoding="utf-8")]
    assert not bad, bad


def test_skip_rules():
    assert skip_reason("sudo suricata-update") == "network/root"
    assert skip_reason("suriharvest serve --port 8078") == "long-running server"
    assert skip_reason("suriharvest search x") is None
    assert skip_reason("curl -s 'http://127.0.0.1:8077/api/stats'") is None
    assert skip_reason("curl -LO https://github.com/x") == "network"
    m = MARK.search("<!-- doctest: write exclusions/default.yaml -->")
    assert m and m.group("verb") == "write" and m.group("arg") == "exclusions/default.yaml"
    assert MARK.search("<!-- doctest: skip needs a server -->").group("verb") == "skip"
    assert MARK.search("<!-- doctest -->").group("verb") is None
    assert commands("a \\\n  b  # c\n\n# only a comment\nd") == ["a    b  # c", "d"]


# ---------------------------------------------------------------------------------------------------------------
# the fixture: synthetic rules (written for these tests, not copied from any publisher) under the catalog's names

ET = r"""
# synthetic ET-style rules for the documentation tests (sids as in the doc examples)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Dropbox paper Document Request Observed"; flow:established,to_server; http.method; content:"GET"; http.host; content:"paper.dropbox.com"; endswith; classtype:misc-activity; sid:2052813; rev:2; metadata:signature_severity Informational, updated_at 2026_10_01;)
# alert dns $HOME_NET any -> any any (msg:"ET INFO Observed DNS Query to .cloud TLD"; dns.query; content:".cloud"; endswith; classtype:bad-unknown; sid:2027865; rev:6; metadata:signature_severity Informational;)
# alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO curl User-Agent Outbound"; flow:established,to_server; http.user_agent; content:"curl/"; startswith; classtype:attempted-recon; sid:2013028; rev:8; metadata:deprecation_reason Performance, signature_severity Informational;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE Cobalt Strike Beacon Observed"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"/fixture-beacon"; startswith; http.cookie; content:"SESSIONID="; classtype:trojan-activity; sid:2100001; rev:1; metadata:signature_severity Major, mitre_tactic_id TA0011, mitre_technique_id T1071, malware_family Cobalt_Strike;)
alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Cobalt Strike Malleable C2 TLS Certificate"; flow:established,to_client; tls.cert_subject; content:"CN=fixture-cs.example"; classtype:trojan-activity; sid:2100002; rev:1; metadata:signature_severity Major, mitre_technique_id T1071;)
alert dns $HOME_NET any -> any any (msg:"ET MALWARE Cobalt Strike CnC Domain in DNS Lookup (cs-fixture.example)"; dns.query; content:"cs-fixture.example"; nocase; isdataat:!1,relative; classtype:command-and-control; sid:2100003; rev:1; metadata:signature_severity Major;)
alert dns $HOME_NET any -> any any (msg:"ET MALWARE CobaltStrike Stager Domain (stager-fixture.example)"; dns.query; content:"stager-fixture.example"; nocase; isdataat:!1,relative; classtype:command-and-control; sid:2100004; rev:1;)
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET EXPLOIT Apache log4j RCE Attempt (CVE-2021-44228)"; flow:established,to_server; http.header; content:"${jndi:"; nocase; reference:cve,2021-44228; classtype:attempted-admin; sid:2100005; rev:1; metadata:cve CVE_2021_44228, signature_severity Major;)
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET EXPLOIT Possible log4j Obfuscation Observed"; flow:established,to_server; http.uri; content:"${lower:"; nocase; reference:cve,2021-44228; classtype:attempted-admin; sid:2100006; rev:1; metadata:signature_severity Major;)
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"ET POLICY Observed SSL Cert for Fixture Proxy Service"; flow:established,to_server; tls.sni; content:"proxy-fixture.example"; endswith; classtype:policy-violation; sid:2100007; rev:1;)
alert smb any any -> any any (msg:"ET POLICY SMB Fixture Share Access"; flow:established,to_server; smb.share; content:"FIXTURE$"; classtype:policy-violation; sid:2100008; rev:1;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Fixture Login Page"; flow:established,to_server; http.uri; content:"/fixture-login"; flowbits:set,ET.fixture.login; flowbits:noalert; classtype:misc-activity; sid:2100009; rev:1;)
alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET INFO Fixture Login Reply"; flow:established,to_client; flowbits:isset,ET.fixture.login; http.stat_code; content:"200"; classtype:misc-activity; sid:2100010; rev:1;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO Fixture rule that does not load"; flow:established,to_server; http.uri; content:"/nope"; fixture_unknown_keyword; sid:2100011; rev:1;)
"""
ETNETERA = """
alert ip $HOME_NET any -> [192.0.2.10] any (msg:"ETN AGGRESSIVE IPs Group 1"; reference:url,security.example; threshold:type limit, track by_src, seconds 3600, count 1; classtype:misc-attack; sid:7000001; rev:1;)
alert dns $HOME_NET any -> any any (msg:"ETN AGGRESSIVE Domain fixture-bad.example"; dns.query; content:"fixture-bad.example"; nocase; isdataat:!1,relative; classtype:misc-attack; sid:7000002; rev:1;)
"""
SSLBL = """
alert tls $EXTERNAL_NET any -> $HOME_NET any (msg:"SSLBL: Malicious SSL certificate detected (Fixture C&C)"; tls.cert_fingerprint; content:"00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33"; reference:url, sslbl.abuse.ch; sid:902200001; rev:1;)
"""
OPNSENSE = """
alert http any any -> any any (msg:"OPNsense fixture app rule"; flow:established,to_server; http.host; content:"app-fixture.example"; endswith; classtype:policy-violation; sid:3200001; rev:1;)
"""
LOCAL = """
alert http any any -> any any (msg:"LOCAL fixture own rule"; flow:established,to_server; http.uri; content:"/our-app"; classtype:policy-violation; sid:1000001; rev:1;)
"""
FIXTURES = {"et-open": ET, "etnetera-aggressive": ETNETERA, "abuse.ch-sslbl": SSLBL, "opnsense-rules": OPNSENSE}


def _cli() -> str:
    """The suriharvest console script of this environment (the doc commands call it by name)."""
    exe = shutil.which("suriharvest", path=str(Path(sys.executable).parent)) or shutil.which("suriharvest")
    if exe is None:
        pytest.fail("the suriharvest console script is not installed (uv sync)")
    return exe


def _run(env: dict[str, str], cwd: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([_cli(), *args], check=False, env=env, cwd=cwd, capture_output=True, text=True)


@pytest.fixture(scope="session")
def doc_workspace(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A HOME with ~/suri: the catalog workspace, every source swapped for local synthetic rules, updated once."""
    if shutil.which("suricata") is None:
        pytest.skip("needs a suricata binary")
    home = tmp_path_factory.mktemp("dochome")
    ws = home / "suri"
    env = {**os.environ, "HOME": str(home)}
    env.pop("SURIHARVEST_HOME", None)
    r = _run(env, home, "init", str(ws))
    assert r.returncode == 0, r.stdout + r.stderr
    fx = home / "fixture-sources"
    for name, text in FIXTURES.items():
        (fx / name).mkdir(parents=True)
        (fx / name / f"{name}.rules").write_text(textwrap.dedent(text).lstrip(), encoding="utf-8")
    data = yaml.safe_load((ws / "sources.yaml").read_text(encoding="utf-8"))
    keep = []
    for src in data["sources"]:
        if src["name"] in FIXTURES:
            src.update(type="local", url=str(fx / src["name"]), paths=["*.rules"])
            src.pop("url_versions", None)
            src["enabled"] = src["name"] != "opnsense-rules"  # cli.md enables it
            keep.append(src)
    data["sources"] = keep
    (ws / "sources.yaml").write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    # files the examples refer to: own rules folders and a catalog to import
    for d in (home / "rules", home / "suricata" / "local"):
        d.mkdir(parents=True)
        (d / "local.rules").write_text(LOCAL.lstrip(), encoding="utf-8")
    extra = {"sources": [{"name": "extra-local", "type": "local", "url": str(home / "rules"), "licence": "MIT"}]}
    (ws / "extra-catalog.yaml").write_text(yaml.safe_dump(extra), encoding="utf-8")
    r = _run(env, ws, "update")
    assert r.returncode == 0, r.stdout + r.stderr
    # the fixture looks like the real thing: ET namespace, validation ran, the broken rule fails
    r = _run(env, ws, "show", "et:1:2052813")
    assert r.returncode == 0 and "Dropbox paper" in r.stdout, r.stdout + r.stderr
    r = _run(env, ws, "search", "fails:local", "--per-logic", "--json")
    assert '"sid": 2100011' in r.stdout, r.stdout + r.stderr
    return home


def _script(home: Path, doc: Path, scratch: Path) -> tuple[str, list[str]]:
    """The shell script for one doc file, and the commands it skips."""
    cli_dir = str(Path(_cli()).parent)
    init = (  # `init PATH`: the fixture already is ~/suri; init the same way into a scratch folder (offline: catalog only)
        'suriharvest() { if [ "$1" = init ]; then shift; local a=() x; for x in "$@"; do'
        f' if [ "$x" = "$HOME/suri" ]; then x=$(mktemp -d -u -p {_q(scratch)} init.XXXX); fi;'
        ' a+=("$x"); done; command suriharvest init "${a[@]}"; else command suriharvest "$@"; fi; }'
    )
    lines = [
        "set -eo pipefail",
        f'export HOME={_q(home)} PATH={_q(cli_dir)}:"$PATH" COLUMNS=200 NO_COLOR=1',
        "unset SURIHARVEST_HOME",
        init,
        "cd ~/suri",
    ]
    skipped = []
    port = _free_port()
    if any("127.0.0.1:8077" in c for ln, m, c in bash_blocks(doc) if m == "run"):
        # examples that talk to `suriharvest serve`: start it (on a free port) for the whole file
        lines += [
            f"command suriharvest serve --port {port} >/dev/null 2>&1 & WEB=$!; trap 'kill $WEB 2>/dev/null' EXIT",
            f"for i in $(seq 100); do curl -sf -o /dev/null http://127.0.0.1:{port}/api/stats && break; sleep 0.2; done",
        ]
    for line, lang, marker, arg, code in blocks(doc):
        if marker == "write":
            assert arg and ".." not in arg and not arg.startswith("/"), f"{doc.name}:{line}: write needs a path inside ~/suri"
            lines += [f"echo {_q('# appended to ' + arg)}", f"cat >> ~/suri/{_q(arg)} <<'DOCTEST_EOF'", code, "DOCTEST_EOF"]
            continue
        if marker != "run" or lang != "bash":
            continue
        lines.append(f"cd ~/suri  # {doc.name}:{line}")
        for cmd in commands(code):
            why = skip_reason(cmd)
            if why:
                skipped.append(f"{cmd}  ({why})")
                continue
            cmd = cmd.replace("127.0.0.1:8077", f"127.0.0.1:{port}")
            lines.append(f"echo {_q('$ ' + cmd)}")
            lines.append(cmd)
    return "\n".join(lines) + "\n", skipped


def _free_port() -> int:
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _q(s: str) -> str:
    return "'" + str(s).replace("'", "'\\''") + "'"


RUNNABLE = [p for p in DOC_FILES if any(m == "run" for _, m, _ in bash_blocks(p))]


@pytest.mark.docs
@pytest.mark.parametrize("doc", RUNNABLE, ids=[p.name for p in RUNNABLE])
def test_doc_commands_run(doc: Path, doc_workspace: Path, tmp_path: Path):
    home = tmp_path / "home"
    shutil.copytree(doc_workspace, home, symlinks=True)
    # sources.yaml still points at the session fixture's synthetic source folders (read only)
    script, skipped = _script(home, doc, tmp_path)
    r = subprocess.run(["bash", "-c", script], check=False, cwd=home, capture_output=True, text=True, timeout=900)
    out = r.stdout + r.stderr
    assert r.returncode == 0, f"{doc.name}: a documented command failed (last '$ ' line is the command):\n{out[-6000:]}"
    print(f"{doc.name}: skipped {len(skipped)}:", *skipped, sep="\n  ")
