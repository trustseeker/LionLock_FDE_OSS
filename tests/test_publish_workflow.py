"""The publish workflow installs and smoke-tests both distribution files before any upload.

The checks read .github/workflows/publish.yml as text, because the default environment has no YAML
parser; each one is scoped to a single job by its header line.
"""

from __future__ import annotations

import re
from pathlib import Path

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "publish.yml"


def _job(name: str) -> str:
    """The lines of one job: from its two-space-indented header to the next job header."""
    text = WORKFLOW.read_text(encoding="utf-8")
    match = re.search(
        rf"^  {re.escape(name)}:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", text, re.M | re.S
    )
    assert match is not None, f"job {name!r} not found"
    return match.group(1)


def _step(job: str, step_name: str) -> str:
    """One step's text, from its ``- name:`` line to the next step."""
    match = re.search(
        rf"^      - name: {re.escape(step_name)}\n(.*?)(?=^      - |\Z)", job, re.M | re.S
    )
    assert match is not None, f"step {step_name!r} not found"
    return match.group(1)


def _smoke_commands(step: str, venv: str) -> list[str]:
    """The smoke commands a step runs with one environment's interpreter or scripts."""
    prefix = f'"$RUNNER_TEMP/{venv}/bin/'
    return [line.strip()[len(prefix) :] for line in step.splitlines() if prefix in line]


def test_the_sdist_is_installed_in_its_own_fresh_environment() -> None:
    job = _job("test-dist")
    install = _step(job, "Install the sdist")
    assert '"$RUNNER_TEMP/venv-sdist/bin/python" -m pip install dist/*.tar.gz' in install
    create = _step(job, "Create a second fresh environment for the sdist")
    assert 'python -m venv "$RUNNER_TEMP/venv-sdist"' in create
    # After the wheel has been checked, so a wheel failure is reported first.
    assert job.index("- name: Smoke test the installed wheel") < job.index(
        "- name: Install the sdist"
    )


def test_the_sdist_gets_the_same_smoke_steps_as_the_wheel() -> None:
    job = _job("test-dist")
    wheel = _step(job, "Smoke test the installed wheel")
    sdist = _step(job, "Smoke test the installed sdist")
    assert _smoke_commands(wheel, "venv")  # the wheel steps are where this file expects them
    assert _smoke_commands(sdist, "venv-sdist") == _smoke_commands(wheel, "venv")
    for step in (wheel, sdist):
        # Called by absolute path from a scratch directory, so the checkout cannot supply lionlock.
        assert 'smoke="$PWD/scripts/release_smoke.py"' in step
        assert 'cd "$RUNNER_TEMP"' in step
    assert '"$RUNNER_TEMP/venv-sdist/bin/python" -m pip check' in _step(job, "pip check (sdist)")


def test_the_test_job_stays_read_only() -> None:
    job = _job("test-dist")
    assert re.search(r"^    permissions:\n      contents: read\n", job, re.M)
    assert "id-token" not in job
    assert "secrets." not in job
    # Only the publish job may mint the upload token.
    assert "id-token: write" in _job("publish")
