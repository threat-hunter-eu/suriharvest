"""scripts/maintainer/allowed_actions.py: every third-party action pin is in .github/allowed-actions.txt."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "maintainer" / "allowed_actions.py"
SHA_OK = "a" * 40
SHA_NEW = "b" * 40


def run(root: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-I", str(SCRIPT), str(root)], capture_output=True, text=True, check=False)


def tree(tmp_path: Path, pin: str) -> Path:
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "allowed-actions.txt").write_text(f"# comment\nastral-sh/setup-uv@{SHA_OK} # v1.0.0\n", encoding="utf-8")
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text(
        "jobs:\n  a:\n    steps:\n"
        "      - uses: actions/checkout@0000000000000000000000000000000000000000 # v1\n"
        f"      - uses: astral-sh/setup-uv@{pin} # v1.0.1\n"
        "      - uses: ./.github/actions/local\n",
        encoding="utf-8",
    )
    return tmp_path


def test_repository_pins_are_all_allowed():
    result = run(ROOT)
    assert result.returncode == 0, result.stdout + result.stderr


def test_listed_pin_passes(tmp_path: Path):
    assert run(tree(tmp_path, SHA_OK)).returncode == 0


def test_dependabot_style_new_sha_fails(tmp_path: Path):
    result = run(tree(tmp_path, SHA_NEW))
    assert result.returncode == 1
    assert f"astral-sh/setup-uv@{SHA_NEW} is not in .github/allowed-actions.txt" in result.stdout
    assert "file=.github/workflows/ci.yml,line=5" in result.stdout


def test_composite_action_is_checked(tmp_path: Path):
    root = tree(tmp_path, SHA_OK)
    (root / "action.yml").write_text(
        f"runs:\n  using: composite\n  steps:\n    - uses: sigstore/cosign-installer@{SHA_NEW}\n", encoding="utf-8"
    )
    assert run(root).returncode == 1


def test_list_entries_must_be_exact_sha_pins(tmp_path: Path):
    root = tree(tmp_path, SHA_OK)
    (root / ".github" / "allowed-actions.txt").write_text(f"astral-sh/setup-uv@{SHA_OK}\nastral-sh/setup-uv@v7\n", encoding="utf-8")
    assert run(root).returncode == 1
