"""The ``sql`` and ``postgres`` extras: what they declare, and that the paths they serve run.

``sql`` is SQLAlchemy, which every SQL sink and reader uses for a URI other than ``sqlite:///...``.
``postgres`` adds psycopg (version 3): SQLAlchemy 2.1 and later pick it for a ``postgresql://``
URI, and the token allowlist imports it directly. psycopg2 is only a fallback for schema setup when
SQLAlchemy is absent, so neither extra installs it.

The declaration tests always run. The others need the extra installed and skip without it, so the
default environment keeps neither package. No database server is used: the PostgreSQL checks point
the driver at a socket directory that does not exist, so each attempt fails inside psycopg and
nothing goes over the network.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import pytest
import tomllib

REPO = Path(__file__).resolve().parents[1]

SQLALCHEMY = "sqlalchemy>=2.1.0"
PSYCOPG = "psycopg[binary]>=3.2.10"

HAS_SQLALCHEMY = importlib.util.find_spec("sqlalchemy") is not None
HAS_PSYCOPG = importlib.util.find_spec("psycopg") is not None
requires_sql = pytest.mark.skipif(not HAS_SQLALCHEMY, reason="sql extra not installed")
requires_postgres = pytest.mark.skipif(
    not (HAS_SQLALCHEMY and HAS_PSYCOPG), reason="postgres extra not installed"
)
requires_psycopg = pytest.mark.skipif(not HAS_PSYCOPG, reason="postgres extra not installed")

# A Unix-socket directory that does not exist: libpq gives up at once, with no server and no
# network connection.
NO_SERVER = "/nonexistent-lionlock-socket-dir"


def _extras() -> dict[str, list[str]]:
    text = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    return tomllib.loads(text)["project"]["optional-dependencies"]


def test_sql_extra_is_sqlalchemy() -> None:
    assert _extras()["sql"] == [SQLALCHEMY]


def test_postgres_extra_is_sqlalchemy_plus_psycopg() -> None:
    # The same SQLAlchemy floor as ``sql``: 2.0 would send a postgresql:// URI to psycopg2, which
    # this extra does not install.
    assert _extras()["postgres"] == [SQLALCHEMY, PSYCOPG]


def _event(turn: int) -> dict[str, Any]:
    return {
        "session_id": "session-1",
        "turn_index": turn,
        "timestamp": "2025-01-01T00:00:00Z",
        "signal_bundle": {
            "signal_scores": {"hallucination_risk": 0.2},
            "derived_signals": {},
            "missing_inputs": [],
        },
        "gating_decision": "ALLOW",
        "decision_risk_score": 0.1,
        "trigger_signal": "hallucination_risk",
        "trust_logic_version": "v1",
        "policy_version": "GC-0.3.1",
        "config_hash": "a" * 64,
        "code_fingerprint": "fp",
        "prompt_type": "qa",
        "response_hash": f"hash-{turn}",
        "replay_id": "replay-1",
        "severity": "green",
    }


@requires_sql
def test_replay_reader_through_sqlalchemy_matches_the_native_reader(tmp_path: Path) -> None:
    from lionlock.logging import events_sql, sql_init
    from lionlock.replay import sql_reader

    db = tmp_path / "events.db"
    native = f"sqlite:///{db}"
    ok, message = sql_init.init_schema(native)
    assert ok, message
    for turn in (1, 2):
        ok, message = events_sql.record_gating_event(uri_or_dsn=native, event=_event(turn))
        assert ok, message

    # sqlite+pysqlite:// is a SQLAlchemy URI, so this read goes through SQLAlchemy.
    through_sqlalchemy = sql_reader.read_events(f"sqlite+pysqlite:///{db}", schema="main")
    assert [event.turn_index for event in through_sqlalchemy] == [1, 2]
    assert through_sqlalchemy == sql_reader.read_events(native)


@requires_postgres
def test_the_dsn_lionlock_builds_loads_psycopg(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sqlalchemy import create_engine

    from lionlock.logging import connection

    # No .env from the working directory or the checkout can change the result.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(connection, "_repo_root", lambda: tmp_path / "no-repo")
    host = "db.invalid"
    monkeypatch.setenv("LIONLOCK_TELEMETRY_DB_HOST", host)
    monkeypatch.setenv("LIONLOCK_WRITER_PASSWORD", "placeholder")

    dsn = connection.build_postgres_dsn("writer")
    assert dsn.startswith("postgresql://")
    engine = create_engine(dsn)  # imports the driver; does not connect
    try:
        assert engine.dialect.driver == "psycopg"
    finally:
        engine.dispose()


@requires_postgres
def test_sql_sink_setup_reaches_psycopg() -> None:
    from lionlock.logging import sql_telemetry

    uri = f"postgresql:///lionlock?host={NO_SERVER}"
    ok, message = sql_telemetry.init_db(uri, "lionlock_signals", "lionlock_sessions")
    assert not ok
    # Without the driver this would read "No module named 'psycopg'".
    assert "(psycopg.OperationalError)" in message, message


@requires_psycopg
def test_token_allowlist_refresh_reaches_psycopg() -> None:
    from lionlock.logging.token_auth import TokenVerifier

    verifier = TokenVerifier(enabled=True, token_db_uri=f"postgresql:///lionlock?host={NO_SERVER}")
    assert verifier.is_token_allowed("any-token") == (False, "allowlist_refresh_failed")
    # Without the driver this would be ModuleNotFoundError.
    assert verifier.last_error == "OperationalError"
