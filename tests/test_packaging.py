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
    import tomllib

    return tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))


def test_the_runtime_has_no_third_party_dependencies() -> None:
    # Pydantic left the runtime in 1.0.0b2; installing it anyway adds a compiled third-party
    # extension, and a plugin loader, to every installation for nothing. tomllib replaces tomli
    # now that Python 3.11 is the minimum.
    project = _pyproject()["project"]
    assert project["dependencies"] == []
    assert project["requires-python"] == ">=3.11"


def _requirement_names(requirements: list[str]) -> set[str]:
    import re

    return {re.split(r"[\[<>=!~;\s]", item, maxsplit=1)[0].lower() for item in requirements}


def test_streamlit_is_in_the_gui_extra_only() -> None:
    # The dev extra is what contributors and CI tooling install; Streamlit (and the large stack
    # it pulls in) is only for the optional GUI, so it belongs to the gui extra alone.
    extras = _pyproject()["project"]["optional-dependencies"]
    assert "streamlit" not in _requirement_names(extras["dev"])
    assert "streamlit" in _requirement_names(extras["gui"])


def _floor(requirements: list[str], name: str) -> tuple[int, ...]:
    """The ``>=`` minimum a requirement list gives ``name``, as a tuple of release numbers."""
    import re

    for item in requirements:
        match = re.fullmatch(rf"{re.escape(name)}>=([0-9]+(?:\.[0-9]+)*)", item.strip())
        if match:
            return tuple(int(part) for part in match.group(1).split("."))
    raise AssertionError(f"no {name}>= requirement in {requirements}")


def test_dev_tools_require_their_current_releases() -> None:
    # pre-commit 4.7.0 and pip-audit 2.10.1 were the latest releases on 28 November 2026, with no
    # published advisories. Raising a floor later still passes; lowering it does not.
    dev = _pyproject()["project"]["optional-dependencies"]["dev"]
    assert _floor(dev, "pre-commit") >= (4, 7, 0)
    assert _floor(dev, "pip-audit") >= (2, 10, 1)


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
