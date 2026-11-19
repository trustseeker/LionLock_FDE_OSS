# LionLock 5-Minute Quickstart

This quickstart runs a small set of synthetic sample sessions through the OSS flow:

1. Signal scoring (Module 02)
2. Gating decision (Module 05)
3. Public telemetry logging to the local SQLite file `logs/lionlock.db`
4. Trust Overlay record generation

## Run

### After `pip install lionlock`

No clone is needed. The package ships a few invented sample sessions, so this works anywhere:

```bash
python -m lionlock.sample_data
```

It scores and gates each sample in memory, prints the decision next to the sample's label, and
writes nothing to disk. Expected output ends with:

```text
Sample summary: FLAGGED=3 CLEAN=2
```

To run the full flow below (gating, the SQLite log, Trust Overlay records) from an installed
package, save [`examples/quickstart.py`](../examples/quickstart.py) from the repository and run
`python quickstart.py`. It reads the packaged samples by default, so it does not depend on the
working directory. It creates `logs/lionlock.db` under the current directory.

### In a clone

```bash
PYTHONPATH=src python examples/quickstart.py
```

To use your own sessions file (same format as below), set `FIXTURE_PATH` at the top of the script.

Expected output format:

```text
Quickstart mode: <active-gating|log-only>
Quickstart summary: FLAGGED=<n> CLEAN=<n>
Telemetry log: logs/lionlock.db
```

## Look at the log

```bash
lionlock-telemetry status    # row counts and upload state (uploads are off by default)
lionlock-telemetry verify    # check the log's hash chains
lionlock-telemetry preview   # what an upload would contain, if you ever opt in
```

See [TELEMETRY.md](TELEMETRY.md) for the log format and the opt-in upload pipeline.

## Fixture dataset

The samples are synthetic. They are packaged as `lionlock/sample_sessions.json` (read with
`lionlock.sample_data.load_sample_sessions()`), and a copy lives at
`tests/fixtures/sample_sessions.json` for the tests; a test keeps the two identical.

Each record contains:

- `id`
- `text`: the prompt
- `response`: a sample model response that exhibits the labeled behavior
- `label` (`FLAGGED` or `CLEAN`)
- optional `notes`

With the bundled fixtures the summary is `FLAGGED=3 CLEAN=2`, matching the labels.
