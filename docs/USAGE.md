# Usage

## Local Development
- Create an environment outside the repo (see `docs/internal/VENV_REDIRECT_POLICY.yaml.md`):
  ```bash
  python -m venv ~/.lionlock_env && source ~/.lionlock_env/bin/activate
  ```
  Or use your preferred venv location (e.g., `$HOME/.venv` or `/tmp/lionlock_venv`):
- Install the package with dev tools: `pip install -e .[dev]`

## Logging
```python
from lionlock import TrustVaultLogger

logger = TrustVaultLogger("build/trustvault.log")
logger.record(event="detect", payload={"signal": "noop"})
logger.flush()
logger.close()
```

## Simulation harness (`lionlock-sim`)
```bash
lionlock-sim run --db sqlite:///sim_out/lionlock_sim.db --out-dir sim_out
```
- **Inputs are synthetic.** The simulator does not run the scorer. It hand-builds signal bundles
  from scenario parameters and feeds them to the gating policy. Their fatigue values reach about
  0.86, which `lionlock.core.scoring` cannot produce (its `fatigue_risk_index` never exceeds
  0.1192), and they are declared measured so that gating acts on them. A run exercises gating,
  SQL logging and replay; it is not evidence of detection, and `fatigue_risk_index` remains
  uncalibrated. Every output says so: `report.json` has `inputs.origin = "synthetic"` and
  `inputs.produced_by_scorer = false`, its `coverage` flags (`fatigue_input_high` and so on) describe
  the inputs fed to gating, and each label and stored bundle carries `input_origin: "synthetic"`.
- **The database is explicit.** Pass `--db` or set `LIONLOCK_DB_URL`; there is no default and no
  fallback. `sqlite:///...` writes a local file and never opens a socket; a `postgresql://` DSN is
  contacted because you named it, and an unreachable one is an error. (Before 1.0.0b2 the
  simulator tried Postgres on localhost and then probed public DNS resolvers to decide whether to
  fall back to SQLite.) `report.json`'s `logging.offline_fallback_engaged` is kept for
  compatibility and is always `false`.
- **Run ids are deterministic.** A run's id is a hash of its profile, turns, seed, policy and code
  fingerprint; rerunning replaces that run's rows. `--append-run` writes under `<id>-<n>` instead,
  where `n` is one more than the highest already in the database, so the same database gives the
  same id. Run append writers one at a time.
- `--policy` is looked up in `--policy-registry`, else `policies.toml` in the working directory.
  Only the implicit `policies.toml` lookup falls back to the built-in baseline, and only when the
  file or the entry is missing. With `--policy-registry`, a missing file or entry is an error. An
  invalid or malformed entry is always an error.

## Tests and Checks
- Run pytest (or `python -m unittest discover -s tests` if pytest is unavailable): `pytest -q`
- If you skip the editable install, run tests with `PYTHONPATH=src`.
- Byte-compile sources: `python -m compileall src`

## Local CI Checks
- Run the full lint/type/test suite: `bash tools/ci_local.sh` (requires dev extras installed)

## Developer Setup (one-command helper)
- `bash tools/dev_setup.sh` creates the venv at `$LIONLOCK_VENV_PATH` (default `<repo>/.venv`) if needed, installs dev extras, and runs pytest.
- `tools/venv_guard.sh` checks that the venv at `$LIONLOCK_VENV_PATH` (default `<repo>/.venv`) is the active interpreter.

## Lockdown Workflow
- Run `./tools/lockdown.sh` to generate a SHA256 manifest and OpenTimestamps proof.
- Commit the generated manifest and `.ots` proof to track release integrity.

## Archived Assets
FastAPI, React, and docker-compose prototypes now live in `archive/experimental/`. They are not part of the supported OSS surface but remain available for reference.


## Audit logging
- Canonical tamper-evident audit stream: `TrustVaultLogger` (see `docs/AUDIT_LOGGING.md`).
- Verify chain integrity with `TrustVaultLogger.verify_chain()`.
- Public JSONL/SQL telemetry in `lionlock.logging.event_log` is non-canonical analytics output.
