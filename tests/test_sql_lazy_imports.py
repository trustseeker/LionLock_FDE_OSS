"""SQLAlchemy is optional and loaded only when a SQLAlchemy code path runs.

Each check runs in a fresh interpreter, so modules imported by other tests cannot hide a regression,
and it passes whether or not SQLAlchemy is installed.
"""

import subprocess
import sys
from pathlib import Path

import pytest

SRC = str(Path(__file__).resolve().parents[1] / "src")

SQL_MODULES = [
    "lionlock.logging.sql_init",
    "lionlock.logging.sql_telemetry",
    "lionlock.logging.missed_signal_sql",
    "lionlock.logging.anomaly_sql",
    "lionlock.logging.events_sql",
    "lionlock.sim.runner",
    "lionlock.trust_overlay.sql_sink",
    "lionlock.replay.sql_reader",
    "lionlock.replay.evaluation_labels",
    "lionlock.utils.sql_batch_writer",
    "lionlock.utils.sql_writer_keys",
]


def _run(code: str) -> subprocess.CompletedProcess[str]:
    prologue = f"import sys; sys.path.insert(0, {SRC!r})\n"
    return subprocess.run(
        [sys.executable, "-c", prologue + code], capture_output=True, text=True, timeout=120
    )


@pytest.mark.parametrize("module", SQL_MODULES)
def test_importing_sql_module_does_not_load_sqlalchemy(module: str) -> None:
    result = _run(
        f"import importlib; importlib.import_module({module!r})\n"
        "assert 'sqlalchemy' not in sys.modules, 'sqlalchemy was imported'\n"
    )
    assert result.returncode == 0, result.stderr


def test_sqlite_paths_do_not_load_sqlalchemy(tmp_path: Path) -> None:
    uri = f"sqlite:///{tmp_path / 'x.db'}"
    result = _run(
        "from lionlock.logging import sql_init, sql_telemetry\n"
        f"assert sql_init.init_schema({uri!r})[0]\n"
        f"assert sql_telemetry.init_db({uri!r}, 'lionlock_signals', 'lionlock_sessions')[0]\n"
        "assert 'sqlalchemy' not in sys.modules, 'sqlalchemy was imported'\n"
    )
    assert result.returncode == 0, result.stderr


def test_absent_sqlalchemy_keeps_the_fallback_messages() -> None:
    """A None entry in sys.modules makes ``import sqlalchemy`` fail, as if it were not installed."""
    uri = "postgresql://user@localhost/db"
    result = _run(
        "sys.modules['sqlalchemy'] = None\n"
        "from lionlock.logging import sql_telemetry, events_sql\n"
        f"ok, msg = sql_telemetry.init_db({uri!r}, 'lionlock_signals', 'lionlock_sessions')\n"
        "expected = 'SQLAlchemy not installed; cannot initialize non-sqlite URI.'\n"
        "assert (ok, msg) == (False, expected), msg\n"
        "from lionlock.replay import sql_reader\n"
        "try:\n"
        f"    sql_reader.read_events({uri!r})\n"
        "except sql_reader.ReadError as exc:\n"
        "    assert str(exc) == 'SQLAlchemy not installed; cannot read non-sqlite URI.', str(exc)\n"
        "else:\n"
        "    raise AssertionError('expected ReadError')\n"
    )
    assert result.returncode == 0, result.stderr
