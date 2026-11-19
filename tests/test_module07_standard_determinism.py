import hashlib
import sqlite3
from pathlib import Path

from lionlock.sim import reporting, runner


def _run_sim(tmp_path: Path, label: str) -> runner.SimResult:
    out_dir = tmp_path / label
    db_path = tmp_path / f"{label}.db"
    return runner.run_simulation(
        profile="standard",
        turns=100,
        seed=123,
        output_dir=str(out_dir),
        db_url=f"sqlite:///{db_path}",
        schema="main",
        policy_version="dev-local",
        policy_registry_path=None,
        append_run=False,
    )


def _db_counts(db_path: Path) -> tuple[int, int, int, int]:
    conn = sqlite3.connect(db_path)
    try:
        event_count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        missed_count = conn.execute("SELECT COUNT(*) FROM missed_signal_events").fetchone()[0]
        refresh_count = conn.execute(
            "SELECT COUNT(*) FROM events WHERE gating_decision='REFRESH'"
        ).fetchone()[0]
        warn_count = conn.execute(
            "SELECT COUNT(*) FROM events WHERE gating_decision='WARN'"
        ).fetchone()[0]
    finally:
        conn.close()
    return event_count, missed_count, refresh_count, warn_count


def test_module07_standard_determinism(tmp_path: Path) -> None:
    first = _run_sim(tmp_path, "run1")
    second = _run_sim(tmp_path, "run2")

    assert first.run_id == second.run_id

    report_first = first.report
    report_second = second.report
    assert report_first == report_second

    report_json_first = Path(first.output_paths["report_json"]).read_text(encoding="utf-8")
    report_json_second = Path(second.output_paths["report_json"]).read_text(encoding="utf-8")
    assert report_json_first == report_json_second

    labels_first = Path(first.output_paths["labels_jsonl"]).read_bytes()
    labels_second = Path(second.output_paths["labels_jsonl"]).read_bytes()
    assert labels_first == labels_second

    labels_sha = hashlib.sha256(labels_first).hexdigest()
    assert report_first["labels_sha256"] == labels_sha
    assert report_first["report_json_sha256"] == reporting.report_json_hash(report_first)

    event_count_1, missed_count_1, refresh_count_1, warn_count_1 = _db_counts(
        Path(first.db_uri[len("sqlite:///") :])
    )
    event_count_2, missed_count_2, refresh_count_2, warn_count_2 = _db_counts(
        Path(second.db_uri[len("sqlite:///") :])
    )
    assert event_count_1 == event_count_2
    assert missed_count_1 == missed_count_2

    assert report_first["missed"]["rate"] <= 0.05
    assert report_first["missed"]["count"] >= 1
    # Coverage describes the synthetic inputs fed to gating. The fatigue values here are hand-built
    # and beyond anything the scorer produces, so this is not a claim about fatigue detection.
    assert report_first["inputs"]["origin"] == "synthetic"
    assert report_first["inputs"]["produced_by_scorer"] is False
    assert report_first["coverage"]["basis"] == "synthetic_inputs"
    assert report_first["coverage"]["fatigue_input_high"] is True
    assert report_first["coverage"]["low_conf_halluc_input_high"] is True
    assert report_first["coverage"]["congestion_input_high"] is True
    assert report_first["coverage"]["expected_block"] is True
    assert "fatigue_high" not in report_first["coverage"]
    assert refresh_count_1 >= 1 and refresh_count_2 >= 1
    assert warn_count_1 == 0 and warn_count_2 == 0


def test_no_database_is_an_error_not_a_probe_or_a_fallback(monkeypatch) -> None:
    """Without --db or LIONLOCK_DB_URL there is nothing to resolve, and nothing is guessed.

    This replaces a test of the old offline fallback, which decided between Postgres and SQLite by
    opening connections to public DNS resolvers. test_sim_offline.py proves no socket is used.
    """

    def _unexpected(uri: str, *, timeout_s: float = 1.0) -> None:  # pragma: no cover
        raise AssertionError("no Postgres connection may be attempted without a configured DSN")

    monkeypatch.setattr(runner, "_test_postgres_connection", _unexpected)
    assert not hasattr(runner, "_detect_offline")
    try:
        runner._resolve_db_target(explicit_db=None, env_db=None, schema_override=None)
    except RuntimeError as exc:
        assert "--db" in str(exc)
        assert "LIONLOCK_DB_URL" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("an unconfigured database must be an error")


def test_explicit_sqlite_target_is_used_as_given(tmp_path: Path) -> None:
    uri = f"sqlite:///{tmp_path / 'explicit.db'}"
    target = runner._resolve_db_target(explicit_db=uri, env_db=None, schema_override=None)
    assert (target.uri, target.engine, target.db_source, target.schema) == (
        uri,
        "sqlite",
        "cli",
        "main",
    )
    env_target = runner._resolve_db_target(explicit_db=None, env_db=uri, schema_override=None)
    assert env_target.db_source == "env"
