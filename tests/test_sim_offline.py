"""The simulator never touches the network, names its inputs as synthetic, and is reproducible.

* No socket: with no database configured the simulator used to try Postgres on localhost and then
  open connections to public DNS resolvers to decide whether to fall back to SQLite. The audit
  test runs the CLI in a fresh interpreter with a PEP 578 hook that records every ``socket.*``
  event, installed before lionlock is imported, and requires the record to stay empty.
* Synthetic inputs: the simulator hand-builds its signal bundles. Their fatigue values exceed
  anything the scorer can produce, so every output says the inputs are synthetic and that the run
  is not evidence of detection.
* Reproducible: ``--append-run`` used to add a uuid4 nonce to the run id.
"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from lionlock.core.scoring import _fatigue_risk_score
from lionlock.replay import policy_registry, replay_engine
from lionlock.replay.sql_reader import read_events
from lionlock.sim import runner
from lionlock.sim.profiles import build_profile

SRC_DIR = Path(__file__).resolve().parents[1] / "src"

_AUDIT_CHILD = r"""
import contextlib
import io
import json
import os
import sys

events = []


def _hook(event, args):
    if event.startswith("socket."):
        events.append(event)


sys.addaudithook(_hook)
sys.path.insert(0, sys.argv[1])
work = sys.argv[2]
os.chdir(work)

from lionlock.sim import cli  # imported under the hook, so import-time sockets count too

results = {}
for label, extra in (
    ("no_db", []),
    ("sqlite", ["--db", "sqlite:///" + os.path.join(work, "sim.db")]),
):
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        code = cli.run(["run", "--turns", "6", "--out-dir", "out-" + label] + extra)
    results[label] = {"exit": code, "stderr": err.getvalue()}
results["socket_events"] = sorted(set(events))
print(json.dumps(results))
"""


@pytest.fixture(autouse=True)
def _isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LIONLOCK_DB_URL", raising=False)
    monkeypatch.delenv("LIONLOCK_GATING_ENABLED", raising=False)
    monkeypatch.chdir(tmp_path)


def _run(tmp_path: Path, db_name: str, out: str, *, append_run: bool) -> runner.SimResult:
    return runner.run_simulation(
        profile="standard",
        turns=8,
        seed=7,
        output_dir=str(tmp_path / out),
        db_url=f"sqlite:///{tmp_path / db_name}",
        schema="main",
        policy_version="dev-local",
        append_run=append_run,
    )


def test_simulator_cli_opens_no_socket(tmp_path: Path) -> None:
    env = {key: value for key, value in os.environ.items() if not key.startswith("LIONLOCK_")}
    completed = subprocess.run(
        [sys.executable, "-I", "-c", _AUDIT_CHILD, str(SRC_DIR), str(tmp_path)],
        capture_output=True,
        text=True,
        check=False,
        env=env,
        timeout=120,
    )
    assert completed.returncode == 0, completed.stderr
    results = json.loads(completed.stdout.strip().splitlines()[-1])

    assert results["socket_events"] == [], f"the simulator used sockets: {results}"
    # No database configured: a clear error, not a guess.
    assert results["no_db"]["exit"] == 1
    assert "no database configured" in results["no_db"]["stderr"]
    assert "--db" in results["no_db"]["stderr"]
    assert not (tmp_path / "sim_out").exists()
    # An explicit local database works without any network.
    assert results["sqlite"]["exit"] == 0, results["sqlite"]["stderr"]
    assert (tmp_path / "out-sqlite" / "report.json").exists()


def test_append_run_ids_are_deterministic(tmp_path: Path) -> None:
    first = [_run(tmp_path, "a.db", f"a{i}", append_run=True) for i in range(2)]
    second = [_run(tmp_path, "b.db", f"b{i}", append_run=True) for i in range(2)]
    plain = _run(tmp_path, "c.db", "c", append_run=False)

    assert [r.run_id for r in first] == [r.run_id for r in second]
    assert [r.run_id for r in first] == [f"{plain.run_id}-0001", f"{plain.run_id}-0002"]
    assert [r.report for r in first] == [r.report for r in second]
    with sqlite3.connect(tmp_path / "a.db") as conn:
        sessions = {row[0] for row in conn.execute("SELECT DISTINCT session_id FROM events")}
    assert sessions == {r.run_id for r in first}


def test_every_output_labels_the_inputs_synthetic(tmp_path: Path) -> None:
    result = _run(tmp_path, "s.db", "s", append_run=False)
    report = result.report
    assert report["inputs"]["origin"] == "synthetic"
    assert report["inputs"]["produced_by_scorer"] is False
    assert "not evidence of detection" in report["inputs"]["note"]
    assert report["coverage"]["basis"] == "synthetic_inputs"

    markdown = Path(result.output_paths["report_md"]).read_text(encoding="utf-8")
    assert "- origin: synthetic" in markdown
    assert "- produced_by_scorer: False" in markdown
    assert "not detection" in markdown

    labels = [
        json.loads(line)
        for line in Path(result.labels_path).read_text(encoding="utf-8").splitlines()
    ]
    assert labels and all(label["input_origin"] == "synthetic" for label in labels)

    with sqlite3.connect(tmp_path / "s.db") as conn:
        bundles = [json.loads(row[0]) for row in conn.execute("SELECT signal_bundle FROM events")]
    assert bundles and all(bundle["input_origin"] == "synthetic" for bundle in bundles)


def test_synthetic_fatigue_exceeds_what_the_scorer_can_produce() -> None:
    """Why the label is needed: the scorer's fatigue ceiling is far below the simulator's inputs."""
    scorer_ceiling = _fatigue_risk_score(
        entropy_decay=1.0, turn_index=10**6, drift_slope=1.0, turn_cap=50.0
    )
    assert scorer_ceiling < 0.12
    specs = build_profile("standard", 100, 123)
    synthetic = [runner._bundle_for_spec(spec, 123).derived_signals for spec in specs]
    assert max(d.fatigue_risk_index for d in synthetic) > 0.8
    assert scorer_ceiling < 0.8


def test_replay_reads_the_labelled_rows(tmp_path: Path) -> None:
    result = _run(tmp_path, "r.db", "r", append_run=False)
    policy = policy_registry.PolicyBundle(
        "dev-local", runner._baseline_policy_config(), result.report["config_hash"]
    )
    events = read_events(result.db_uri, session_id=result.run_id)
    replayed = replay_engine.replay(events, policy)
    assert replayed.report["summary"]["bundle_errors"] == 0
    assert replayed.report["summary"]["replayed_count"] == 8
    assert replayed.report["summary"]["decision_mismatch"] == 0


def test_an_invalid_policy_entry_is_an_error_not_a_silent_baseline(tmp_path: Path) -> None:
    (tmp_path / "policies.toml").write_text(
        '[policies."dev-local"]\ngating.hallucination_mode = "warn_onyl"\n', encoding="utf-8"
    )
    with pytest.raises(ValueError, match="gating.hallucination_mode = 'warn_onyl'"):
        _run(tmp_path, "p.db", "p", append_run=False)
