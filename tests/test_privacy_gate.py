"""scripts/maintainer/privacy_gate.py: generic rules in the repo, sensitive terms only from an external file."""

import hashlib
import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest

GATE = Path(__file__).resolve().parents[1] / "scripts" / "maintainer" / "privacy_gate.py"


def load_gate():
    spec = importlib.util.spec_from_file_location("privacy_gate_under_test", GATE)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod  # dataclasses look the module up
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(autouse=True)
def _no_terms_env(monkeypatch):
    # The gate also reads SIGHARVEST_PRIVACY_TERMS and PRIVACY_TERMS: a value from the shell must not leak in.
    for name in ("SIGHARVEST_PRIVACY_TERMS", "SURIHARVEST_PRIVACY_TERMS", "PRIVACY_TERMS"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    subprocess.run(["git", "init", "-q", str(r)], check=True)
    (r / "notes.txt").write_text("mentions the zorbex platform\n")
    return r


def test_gate_has_no_project_specific_terms():
    text = GATE.read_text()
    # Only the term loader may know about project-specific words; the repo copy must stay generic.
    assert "SURIHARVEST_PRIVACY_TERMS" in text
    gate = load_gate()
    assert not any(r.sensitive for r in gate.RULES)
    assert not any(r.category == "vendor" for r in gate.RULES)


def test_session_scratch_path_blocks(repo, monkeypatch, capsys):
    monkeypatch.delenv("SURIHARVEST_PRIVACY_TERMS", raising=False)
    (repo / "log.txt").write_text("written to /tmp/agent-0" + "/-home-me-proj/scratch/out.json\n")  # split: no hit here
    rc = load_gate().run([str(repo), "--gitleaks", "off"])
    assert rc == 1 and "internal-path-tmp-session" in capsys.readouterr().out
    (repo / "log.txt").write_text("cache in /tmp/tool-session-1234" + "/-srv-build/x.json\n")  # any tool's session folder
    assert load_gate().run([str(repo), "--gitleaks", "off"]) == 1
    rule = next(r for r in load_gate().RULES if r.id == "internal-path-tmp-session")
    assert re.match(r"/tmp/\[", rule.pattern)  # a character class, no tool name


def test_without_terms_runs_generic_rules_and_says_so(repo, monkeypatch, capsys):
    monkeypatch.delenv("SURIHARVEST_PRIVACY_TERMS", raising=False)
    rc = load_gate().run([str(repo), "--gitleaks", "off"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "sensitive terms: NOT loaded" in out


def test_terms_file_blocks_and_hides_the_term_name(repo, tmp_path, monkeypatch, capsys):
    terms = tmp_path / "terms.txt"
    terms.write_text("# comment\nsecret-platform-name block content \\bzorbex\\b\n")
    monkeypatch.setenv("SURIHARVEST_PRIVACY_TERMS", str(terms))
    rc = load_gate().run([str(repo), "--gitleaks", "off"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "sensitive-term" in out
    assert "secret-platform-name" not in out  # rule ids from the terms file are not printed
    assert "zorbex" not in out  # nor the matched line (CI logs)


def test_terms_file_exceptions(repo, tmp_path, monkeypatch, capsys):
    terms = tmp_path / "terms.txt"
    terms.write_text("p1 block content zorbex\nallow notes.txt p1 -- public mention\n")
    monkeypatch.setenv("SURIHARVEST_PRIVACY_TERMS", str(terms))
    rc = load_gate().run([str(repo), "--gitleaks", "off"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "public mention" not in out  # justification stays in the terms file


def test_missing_terms_file_is_an_error(repo, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SURIHARVEST_PRIVACY_TERMS", str(tmp_path / "missing.txt"))
    assert load_gate().run([str(repo), "--gitleaks", "off"]) == 2


def test_bad_terms_line_names_only_the_line(repo, tmp_path, monkeypatch, capsys):
    terms = tmp_path / "terms.txt"
    terms.write_text("zorbex-rule block content (unclosed\n")
    monkeypatch.setenv("SURIHARVEST_PRIVACY_TERMS", str(terms))
    assert load_gate().run([str(repo), "--gitleaks", "off"]) == 2
    err = capsys.readouterr().err
    assert "terms file:1" in err and "zorbex" not in err


# SHA-256 of scripts/maintainer/privacy_gate.py. The script is a shared file: it must stay byte-identical in sigharvest and
# suriharvest (each repo keeps its own .github/privacy-allowlist.txt; the sensitive terms live outside both).
GATE_SHA256 = "7971e341becfc1a4ff4acd8459b5463a6e33f20a1d0bd33b98463093e7f4de96"


def test_gate_is_the_shared_copy() -> None:
    """scripts/maintainer/privacy_gate.py is byte-identical in sigharvest and suriharvest.

    To change it: edit the script in one repo, copy the same bytes to scripts/maintainer/privacy_gate.py of the other repo,
    run `sha256sum scripts/maintainer/privacy_gate.py` and put the new hash in GATE_SHA256 of tests/test_privacy_gate.py in
    BOTH repos (same commit message in each). CRLF is normalised to LF so a Windows checkout gives the same hash.
    """
    path = Path(__file__).resolve().parents[1] / "scripts" / "maintainer" / "privacy_gate.py"
    data = path.read_bytes().replace(b"\r\n", b"\n")
    assert data.splitlines()[1].startswith(b"# shared file; keep identical in sigharvest and suriharvest")
    assert hashlib.sha256(data).hexdigest() == GATE_SHA256, "privacy_gate.py changed: update it in both repos (see this docstring)"


def test_reports_redact_the_addresses_they_block(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """CI logs are public: a blocked address is shown redacted, the full one is kept only for allowlist matching."""
    gate = load_gate()
    address = "jane.doe" + "@" + "acme-widgets" + ".com"  # built at run time: the tree scan must not see it
    assert gate.redact_email(address) == "j***@a***.com"
    (finding,) = [f for f in gate.scan_text("docs/a.md", f"contact {address}", "tree") if f.rule == "email-real"]
    assert address not in finding.snippet and "j***@a***.com" in finding.snippet and finding.raw_line.endswith(address)
    repo = tmp_path / "repo"
    repo.mkdir()
    run = lambda *a: subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True)  # noqa: E731
    run("init", "-q")
    run("-c", "user.name=Jane", "-c", f"user.email={address}", "commit", "-q", "--allow-empty", "-m", "x")
    found = [f for f in gate.scan_commit_identities(repo) if f.rule == "email-commit-author"]
    assert len(found) == 2 and all(address not in f.snippet and f.raw_line == address for f in found)  # author, committer
