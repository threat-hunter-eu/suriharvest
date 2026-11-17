"""Workflow hardening invariants (docs/automation.md): checked on every CI run so they cannot regress.

- Only the read-only check workflows (ci.yml, ci-full.yml, ci-docs.yml) may use the setup-uv cache. Every other
  setup-uv step (jobs that publish, deploy, push, sign or parse untrusted data, and the composite action) has
  `enable-cache: false`, so a poisoned cache entry can never reach them, and they never write one.
- Their jobs never get a write permission (that is what makes their cache exemption safe).
- The push set stays small: ci.yml (every push) has only the jobs in PUSH_JOBS, Linux, no matrix; the expensive
  jobs live in ci-full.yml / ci-docs.yml (pull requests to main, a schedule gated by FULL_CI_VAR, manual).
- Every job has a timeout; every check workflow cancels superseded runs.
- uv itself is pinned in every setup-uv step; every third-party action is pinned to a full commit SHA.
- No `${{ }}` expression inside a `run:` script (values go through `env:`).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
ACTION = ROOT / "action.yml"
CHECKS = ("ci.yml", "ci-full.yml", "ci-docs.yml")
CACHE_ALLOWED = set(CHECKS)
PUSH_JOBS = {"lint", "test", "engine", "privacy"}  # docs/automation.md#what-runs-when
FULL_CI_VAR = "SURIHARVEST_FULL_CI_ENABLED"


def _load(name: str) -> dict:
    return yaml.safe_load((ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8"))


def _on(doc: dict) -> dict:
    on = doc.get("on", doc.get(True))  # PyYAML reads the bare key `on` as True
    return {on: None} if isinstance(on, str) else dict(on)


def _steps(path: Path):
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    if "runs" in doc:  # composite action
        for step in doc["runs"].get("steps", []):
            yield "action", {}, step
        return
    for name, job in (doc.get("jobs") or {}).items():
        for step in job.get("steps", []) or []:
            yield name, job, step


FILES = [*WORKFLOWS, *([ACTION] if ACTION.is_file() else [])]


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_setup_uv_pinned_and_cache_off_outside_ci(path: Path):
    for job, _, step in _steps(path):
        uses = str(step.get("uses", ""))
        if not uses.startswith("astral-sh/setup-uv@"):
            continue
        cfg = step.get("with") or {}
        assert re.fullmatch(r"\d+\.\d+\.\d+", str(cfg.get("version", ""))), f"{path.name}/{job}: setup-uv without a pinned uv version"
        if path.name not in CACHE_ALLOWED:
            assert cfg.get("enable-cache") is False, f"{path.name}/{job}: setup-uv must set enable-cache: false"


@pytest.mark.parametrize("name", CHECKS)
def test_check_workflows_are_read_only(name: str):
    doc = _load(name)
    perms = [doc.get("permissions") or {}] + [job.get("permissions") or {} for job in doc["jobs"].values()]
    for p in perms:
        assert p in ("read-all", {}) or (isinstance(p, dict) and "write" not in p.values()), f"{name} grants write: {p}"


def test_push_set_stays_small():
    """Every push is billed: ci.yml keeps to a few Linux jobs without a matrix (aim: under 6 billed minutes)."""
    doc = _load("ci.yml")
    on = _on(doc)
    assert set(on) == {"push", "pull_request", "workflow_dispatch"}, "ci.yml runs on push, PRs to main and on demand"
    assert on["pull_request"]["branches"] == ["main"]
    for name in ("lint", "privacy"):  # required on every PR, from a fork or Dependabot too
        assert "if" not in doc["jobs"][name], f"ci.yml/{name} must always run"
    assert set(doc["jobs"]) == PUSH_JOBS, f"ci.yml jobs changed: {sorted(doc['jobs'])}; expensive jobs go to ci-full.yml"
    for name, job in doc["jobs"].items():
        assert "strategy" not in job, f"ci.yml/{name}: no matrix on push"
        assert str(job["runs-on"]).startswith("ubuntu-"), f"ci.yml/{name}: Linux only on push"
        assert job.get("timeout-minutes", 99) <= 15, f"ci.yml/{name}: push jobs stay short"


@pytest.mark.parametrize("name", CHECKS[1:])
def test_full_ci_runs_on_pr_schedule_and_demand_only(name: str):
    doc = _load(name)
    on = _on(doc)
    assert set(on) == {"pull_request", "schedule", "workflow_dispatch"}, f"{name}: not on push"
    assert on["pull_request"]["branches"] == ["main"]
    for job_name, job in doc["jobs"].items():  # the schedule costs nothing until the variable is set
        assert f"vars.{FULL_CI_VAR} == 'true'" in job.get("if", ""), f"{name}/{job_name}: schedule not gated by {FULL_CI_VAR}"


def test_only_ci_and_path_filtered_pages_run_on_push():
    for path in WORKFLOWS:
        push = _on(yaml.safe_load(path.read_text(encoding="utf-8"))).get("push")
        if path.name == "ci.yml" or push is None:
            continue
        assert push.get("paths") and push.get("branches") == ["main"], f"{path.name}: unfiltered push trigger"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_every_job_has_a_timeout(path: Path):
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    for name, job in doc["jobs"].items():
        assert "uses" in job or "timeout-minutes" in job, f"{path.name}/{name}: no timeout-minutes"


@pytest.mark.parametrize("name", CHECKS)
def test_check_workflows_cancel_superseded_runs(name: str):
    conc = _load(name).get("concurrency") or {}
    assert conc.get("cancel-in-progress") is True and "github.ref" in conc.get("group", ""), f"{name}: concurrency"


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_actions_pinned_by_sha_and_no_expressions_in_run(path: Path):
    for job, _, step in _steps(path):
        uses = str(step.get("uses", ""))
        if uses and not uses.startswith("./"):
            assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", uses), f"{path.name}/{job}: not pinned by SHA: {uses}"
        assert "${{" not in str(step.get("run", "")), f"{path.name}/{job}: expression inside run: (use env:)"


def test_publish_needs_a_dated_changelog_section():
    """A package release needs `## [X.Y.Z] - YYYY-MM-DD` in CHANGELOG.md, not `Unreleased`."""
    text = (ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")
    assert "CHANGELOG.md has no dated" in text and "[0-9]{4}-[0-9]{2}-[0-9]{2}" in text
    head = re.search(r"^## \[(\d+\.\d+\.\d+)\] - (\S+)", (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"), re.M)
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert head and f'version = "{head.group(1)}"' in pyproject, "the newest CHANGELOG section is the package version"
