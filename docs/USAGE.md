# Usage

## Local Development
- Use one virtual environment: a git-ignored `.venv` in the repository by default, or the path in
  `LIONLOCK_VENV_PATH` to keep it outside the project tree (see
  [`VENV_REDIRECT_POLICY.yaml.md`](VENV_REDIRECT_POLICY.yaml.md)). `bash tools/dev_setup.sh` creates
  it and installs the dev tools. To do it by hand:
  ```bash
  python -m venv .venv && source .venv/bin/activate
  pip install -e '.[dev]'
  ```

## Logging
```python
from lionlock import TrustVaultLogger

logger = TrustVaultLogger("build/trustvault.log")
logger.record(event="detect", payload={"signal": "noop"})
logger.flush()
logger.close()
```

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
- Run `./tools/lockdown.sh` to write a SHA-256 manifest of the tree, and an OpenTimestamps proof
  when the `ots` client is installed.
- The manifest shows whether files changed after it was made; the proof shows the manifest
  existed by the time it was stamped. Neither shows who wrote the files.


## Audit logging
- Canonical hash-chained audit stream: `TrustVaultLogger` (see [`AUDIT_LOGGING.md`](AUDIT_LOGGING.md)).
- Verify chain integrity with `TrustVaultLogger.verify_chain()`. The chain detects edits, removals
  and reordering inside the log; to detect a rewrite of the whole log, compare its latest head with
  a copy kept somewhere the log's writer cannot change.
- Public JSONL/SQL telemetry in `lionlock.logging.event_log` is non-canonical analytics output.
