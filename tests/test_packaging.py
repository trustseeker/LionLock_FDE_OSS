import importlib.util
import json
import os
import subprocess
import sys
from importlib import metadata
from pathlib import Path

import pytest

import lionlock
from lionlock.sample_data import load_sample_sessions

REPO = Path(__file__).resolve().parents[1]


def _child_env() -> dict[str, str]:
    # A child process started elsewhere must find the same lionlock this test imported.
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(lionlock.__file__).resolve().parents[1])
    return env


def test_version_is_a_nonempty_string() -> None:
    assert isinstance(lionlock.__version__, str) and lionlock.__version__


def test_py_typed_marker_exists_in_package() -> None:
    assert (Path(lionlock.__file__).parent / "py.typed").is_file()


def test_packaged_sample_sessions_match_test_fixture() -> None:
    fixture = json.loads((REPO / "tests/fixtures/sample_sessions.json").read_text("utf-8"))
    assert load_sample_sessions() == fixture


def test_quickstart_defaults_to_packaged_samples_regardless_of_cwd(tmp_path, monkeypatch) -> None:
    spec = importlib.util.spec_from_file_location("qs", REPO / "examples/quickstart.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.chdir(tmp_path)
    assert module.load_fixture_sessions() == load_sample_sessions()


def test_sample_data_module_runs_and_matches_labels(tmp_path) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "lionlock.sample_data"],
        cwd=tmp_path,
        env=_child_env(),
        capture_output=True,
        text=True,
        check=True,
    )
    assert "Sample summary: FLAGGED=3 CLEAN=2" in result.stdout
    assert list(tmp_path.iterdir()) == []


def _installed() -> bool:
    try:
        metadata.version("lionlock")
    except metadata.PackageNotFoundError:
        return False
    return True


@pytest.mark.skipif(not _installed(), reason="release smoke check needs an installed lionlock")
def test_release_smoke_script_passes() -> None:
    result = subprocess.run(
        [sys.executable, str(REPO / "scripts/release_smoke.py")],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def _pyproject() -> dict:
    if sys.version_info >= (3, 11):
        import tomllib
    else:
        import tomli as tomllib
    return tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))


def test_runtime_dependencies_are_only_what_the_runtime_imports() -> None:
    # Pydantic left the runtime in 1.0.0b2; installing it anyway adds a compiled third-party
    # extension, and a plugin loader, to every installation for nothing.
    assert _pyproject()["project"]["dependencies"] == ['tomli>=2.0.0; python_version < "3.11"']


def test_license_is_an_spdx_expression() -> None:
    project = _pyproject()["project"]
    assert project["license"] == "Apache-2.0"
    assert project["license-files"] == ["LICENSE", "NOTICE"]
    assert not [c for c in project["classifiers"] if c.startswith("License ::")]


def test_readme_links_work_on_pypi() -> None:
    # README.md is the PyPI project description, where a relative link resolves against
    # pypi.org and leads nowhere. Every link must be absolute or an in-page anchor.
    import re

    text = (REPO / "README.md").read_text(encoding="utf-8")
    targets = re.findall(r"\]\(([^)\s]+)\)", text) + re.findall(r'(?:href|src)="([^"]+)"', text)
    relative = [t for t in targets if not t.startswith(("https://", "http://", "#", "mailto:"))]
    assert relative == []
