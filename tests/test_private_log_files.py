"""New local log files are owner-only from creation; existing ones keep their modes."""

from __future__ import annotations

import argparse
import importlib.util
import os
import stat
from pathlib import Path
from typing import Callable, Iterator

import pytest

from lionlock import TrustVaultLogger
from lionlock.logging.event_log import append_event
from lionlock.trust_overlay.logger import append_annotation, append_trust_record, build_trust_record

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX file modes only")

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture
def umask_022() -> Iterator[None]:
    previous = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(previous)


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _trust_record() -> dict:
    return build_trust_record(
        session_id="session-1",
        turn_index=1,
        model_id="model-1",
        prompt_type="qa",
        derived_signals={"overall_risk": 0.2},
        aggregate_score=0.2,
        response_text=None,
        response_hash=None,
        score_history=[],
        timestamps=[],
        config={},
    )


def _trustvault(base: Path) -> Path:
    path = base / "audit" / "trustvault.log"
    TrustVaultLogger(path).record(event="detect", payload={"n": 1})
    return path


def _trustvault_flush(base: Path) -> Path:
    path = base / "audit" / "trustvault.log"
    TrustVaultLogger(path).flush()
    return path


def _event_log(base: Path) -> Path:
    path = base / "events" / "lionlock_events.jsonl"
    append_event(path, {"decision": "ALLOW", "timestamp_utc": "2026-01-01T00:00:00Z"})
    return path


def _trust_overlay(base: Path) -> Path:
    return append_trust_record(_trust_record(), base_dir=base / "overlay")


def _annotation(base: Path) -> Path:
    return append_annotation({"label": "ok"}, base_dir=base / "annotations")


WRITERS: dict[str, Callable[[Path], Path]] = {
    "TrustVaultLogger.record": _trustvault,
    "TrustVaultLogger.flush": _trustvault_flush,
    "event_log.append_event": _event_log,
    "trust_overlay.append_trust_record": _trust_overlay,
    "trust_overlay.append_annotation": _annotation,
}


@pytest.mark.parametrize("writer", sorted(WRITERS))
def test_new_files_are_0600_and_new_directories_0700_under_umask_022(
    tmp_path: Path, umask_022: None, writer: str
) -> None:
    base = tmp_path / "new-parent"
    path = WRITERS[writer](base)
    assert _mode(path) == 0o600
    assert _mode(path.parent) == 0o700
    assert _mode(base) == 0o700


@pytest.mark.parametrize("writer", sorted(WRITERS))
def test_existing_files_and_directories_keep_their_modes(
    tmp_path: Path, umask_022: None, writer: str
) -> None:
    first = WRITERS[writer](tmp_path)
    os.chmod(first, 0o644)
    os.chmod(first.parent, 0o755)
    before = first.read_bytes()
    second = WRITERS[writer](tmp_path)
    assert second == first
    assert _mode(first) == 0o644 and _mode(first.parent) == 0o755
    assert first.read_bytes().startswith(before)  # appended to, never rewritten


def test_files_are_private_from_the_open_call_not_by_a_later_chmod(
    tmp_path: Path, umask_022: None, monkeypatch
) -> None:
    def refuse_chmod(*_args, **_kwargs):
        raise AssertionError("a log file must not need chmod to become private")

    monkeypatch.setattr(os, "chmod", refuse_chmod)
    for writer in WRITERS.values():
        assert _mode(writer(tmp_path)) == 0o600


# --- scripts/log_token_tool.py ----------------------------------------------------------------


def _token_tool():
    spec = importlib.util.spec_from_file_location(
        "log_token_tool", REPO / "scripts" / "log_token_tool.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _generate(tool, token_path: Path, *, force: bool = False, hashes: Path | None = None) -> None:
    args = argparse.Namespace(
        token_path=str(token_path), hashes_path=str(hashes) if hashes else "", force=force
    )
    assert tool.cmd_generate(args) == 0


def test_token_file_is_0600_from_creation(tmp_path: Path, umask_022: None, monkeypatch) -> None:
    tool = _token_tool()
    chmods: list = []
    monkeypatch.setattr(os, "chmod", lambda *args, **kwargs: chmods.append(args))
    token, hashes = tmp_path / "upload.token", tmp_path / "token_hashes.txt"
    _generate(tool, token, hashes=hashes)
    assert chmods == []  # nothing to tighten afterwards: there was never a readable moment
    assert _mode(token) == 0o600 and _mode(hashes) == 0o600
    assert len(token.read_text(encoding="utf-8").strip()) > 20


def test_token_tool_refuses_an_existing_path_or_dangling_symlink(tmp_path: Path) -> None:
    tool = _token_tool()
    token = tmp_path / "upload.token"
    token.write_text("existing\n", encoding="utf-8")
    with pytest.raises(FileExistsError):
        _generate(tool, token)
    assert token.read_text(encoding="utf-8") == "existing\n"

    target = tmp_path / "elsewhere" / "planted.token"
    target.parent.mkdir()
    link = tmp_path / "link.token"
    link.symlink_to(target)
    with pytest.raises(FileExistsError):
        _generate(tool, link)
    assert not target.exists()  # the link was not followed to create its target


def test_force_replaces_a_symlink_instead_of_writing_through_it(
    tmp_path: Path, umask_022: None
) -> None:
    tool = _token_tool()
    victim = tmp_path / "victim.txt"
    victim.write_text("do not overwrite\n", encoding="utf-8")
    os.chmod(victim, 0o644)
    token = tmp_path / "upload.token"
    token.symlink_to(victim)

    _generate(tool, token, force=True)
    assert victim.read_text(encoding="utf-8") == "do not overwrite\n"
    assert not token.is_symlink() and _mode(token) == 0o600
    assert sorted(p.name for p in tmp_path.iterdir()) == ["upload.token", "victim.txt"]
