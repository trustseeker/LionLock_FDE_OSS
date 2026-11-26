"""``log_token_tool.py register --verbose`` must not print the database connection string.

A connection string can hold a password. Even redacted, printing it sends data derived from the
password to the screen, which code scanning (CodeQL clear-text logging) rightly flags.
"""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SECRET = "S3cretPW"
HOST = "db.example.com"


def _token_tool():
    spec = importlib.util.spec_from_file_location(
        "log_token_tool", REPO / "scripts" / "log_token_tool.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_verbose_register_does_not_print_the_connection_string(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    tool = _token_tool()
    monkeypatch.setattr(tool, "_connect_execute", lambda dsn, sql_text, params: None)
    monkeypatch.setenv("LIONLOCK_TEST_LOG_TOKEN", "synthetic-token-value")
    args = argparse.Namespace(
        env_file="",
        token_env="LIONLOCK_TEST_LOG_TOKEN",
        token_path="",
        db_uri=f"postgresql://user:{SECRET}@{HOST}:5432/ll",
        label="",
        scope="",
        verbose=True,
    )

    assert tool.cmd_register(args) == 0

    out = capsys.readouterr().out
    assert "token_registered=true" in out
    assert SECRET not in out
    assert HOST not in out
    assert "postgresql" not in out
