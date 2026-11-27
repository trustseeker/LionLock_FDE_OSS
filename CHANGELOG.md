# Changelog

## Unreleased

### Added

- **Optional `sql` and `postgres` extras.** `pip install "lionlock[sql]"` adds SQLAlchemy, which
  the SQL sinks and readers use for any URI except `sqlite:///...`. `pip install
  "lionlock[postgres]"` adds SQLAlchemy and psycopg, the PostgreSQL driver that SQLAlchemy and the
  token allowlist use. Until now these had to be found and installed by hand. Both extras require
  SQLAlchemy 2.1 or later, the first release that uses psycopg for a `postgresql://` URI (2.0
  uses psycopg2, which LionLock does not install). psycopg must be 3.2.10 or later, the first
  release that supports Python 3.14. On 25 November 2026 PyPI listed no security advisories for
  any release these ranges allow. A plain `pip install lionlock` still installs no other package.

### Fixed

- **`scripts/log_token_tool.py register --verbose` no longer prints the database connection
  string**, not even redacted. A connection string can hold a password, and code scanning
  (CodeQL, clear-text logging) flagged the redacted output. `--verbose` now only confirms that a
  connection string was set.

## 1.0.0b2 — 25 November 2026 — security, integrity and data-preservation fixes

Recommended for everyone on `1.0.0b1`. That release was published before everything below, so an
install pinned to it still fails open on the settings described under Fixed.

This release also includes the fixes from the November 2026 review: the gate decision rule
(D1), runtime, audit-log and receiver hardening, and a release process that tests the built files
before they are uploaded. Every behaviour change below has a test that fails on the code before
the fix.

**If you use the opt-in `sqlite:///...` telemetry sink, or run a telemetry receiver, read the
Compatibility notes before upgrading.**

### Fixed

- **The gate could name a signal that did not drive the decision, and soften a worse reply more
  than a milder one.** The raw-channel trigger was the largest *unweighted* score, so
  `hallucination_risk` (weight 0 by default) could be named, and warn-only mode then softened the
  decision. A reply that repeated "banana" 200 times was refreshed while one repeating an on-topic
  word was blocked. The trigger is now the enabled signal with the largest weighted contribution;
  warn-only softens a red decision only when hallucination evidence alone makes it red; the
  hard-gate list keeps a block whenever the listed evidence alone is red; and raising any score
  never lowers the action (spec LL-0002, decision D1).
- **Invalid settings no longer fail open.** A `nan` weight could turn BLOCK into ALLOW, a `nan` red
  threshold meant nothing was ever red, and a misspelt `hallucination_mode` behaved like `block`.
  Invalid modes, thresholds, weights and enabled signals, and non-finite scores, are now refused
  with an error that names the setting, both in `evaluate_policy` and when a config is loaded.
  The trust overlay no longer reports a non-finite risk as TRUSTED.
  Weights and scores at numeric extremes are refused too: positive weights must lie in
  `[1e-6, 1e6]` (two weights of `1e308` overflowed and one of `5e-324` underflowed, each turning
  a BLOCK into an ALLOW), and every signal score and derived value must be a number from 0 to 1
  (out-of-range values used to be clamped, and could weaken a decision through overflow).
- **A decision could differ between Python versions.** Means used built-in `sum()`, whose
  rounding changed in Python 3.12; they now use `math.fsum`, which is identical on 3.10-3.14.
- **Replay used the shell's `LIONLOCK_GATING_ENABLED`, and replay and the simulator used default
  weights.** Replay now uses only the recorded policy, and both pass the policy's weights and
  enabled signals to the gate. A malformed `policies.toml` entry is an error rather than a silent
  fall-back to the baseline.
- **The simulator probed the network.** It no longer opens any connection; `--db` or
  `LIONLOCK_DB_URL` is required.
- **Scores differed between Python 3.10 and later versions.** Standard deviations are now computed
  exactly and rounded once, so scores are identical bit for bit on Python 3.10 to 3.14 for every
  input tested; metadata integers too large for a float count as missing instead of crashing.
- **Validation depended on whether pydantic was installed, and pydantic plugins could see prompts
  and replies.** There is now one pure-Python validator that matches pydantic 2.13.5's verdicts.
- **Honest `TrustVaultLogger` logs with integer payload keys failed verification, and NaN was
  written as invalid JSON.** New entries use a documented canonical format (format 2, RFC 8785)
  that any language can verify; payloads without a canonical form are refused before anything is
  written, and a line with a repeated JSON member is rejected.
- **Rows deleted from either end of the local SQLite log still verified.** `verify` now checks
  contiguity, the prune anchor and SQLite's sequence counter, and can check against a head
  recorded elsewhere (`lionlock-telemetry head`, `verify --expected-head FILE`).
- **New log files and the token file could be read by other users.** They are now created owner
  only (files 0600, directories 0700). Trust Overlay records no longer hold an unsalted hash of the
  reply or of the hostname, nor free-text notes; `response_hash` is keyed with the configured salt.
- **SQL writers mishandled two database errors.** A MySQL/MariaDB duplicate entry (error 1062)
  was not recognised as a duplicate, and two PostgreSQL writers starting together on a table that
  still needed its idempotency key could fail with "already exists". 1062 is now a duplicate
  (SQLSTATE 23000 alone never is). The PostgreSQL upgrade now takes a table lock and inspects the
  table again before changing it; a table that already has the key is not locked, so a sink role
  with only SELECT and INSERT still starts. The PostgreSQL change was checked against a real
  PostgreSQL 16 server; the MySQL change was not tested against a real MySQL server.
- **`redact_dsn` could show part of a database password.** It missed `sslpassword`, a
  `password = value` setting written with spaces, the rest of a quoted password or of one with a
  backslash-escaped space, text after an unencoded `#` or `?` in a password, and any key=value
  string whose password contained `://`; a bad port raised an error. Every password-like setting
  is now redacted, and a connection string it cannot parse is shown as `REDACTED`. It is used by
  `scripts/log_token_tool.py --verbose`.
- **The receiver could be worked around or held up.** A second `Authorization` header could dodge
  the per-token rate limit (now 400); one partner could upload for another's install (now 403);
  slow clients could hold connections indefinitely (now a 60 s deadline and a 32-connection cap);
  deeply nested JSON crashed validation (now a normal rejection); and control characters reached
  the log (now escaped). New receiver data paths are created owner only.
- **The LLM connector could leak its API key.** urllib follows a redirected POST (301/302/303) as
  a GET that still carries `Authorization`, so one redirect sent the bearer key to whatever host
  the server named. Redirects are no longer followed, the key is never sent over plain http except
  to localhost, and only http/https endpoints are called.
- **A streamed reply could be billed and shown twice.** An empty `choices` chunk (usage or content
  filter) or a dropped stream fell back to a second, non-streaming request and replayed the whole
  reply after the partial one. A stream that fails after text was shown now returns
  `stream_interrupted`.
- **A `.env` file could switch gating off.** A `.env` found implicitly in the current directory or
  repo root was copied into the environment in full. It may now only set database connection
  settings; `load_dotenv(path)` with an explicit path still loads everything.
- **Database credentials in the environment switched SQL telemetry on** (and crashed startup under
  the default backend), and the DSN was copied into `logging_sql.token`. The SQL sink is now
  enabled only by `logging_sql.enabled = true`.
- **A broken `lionlock.toml` was silently ignored**, dropping token auth, failsafe and custom
  thresholds back to defaults. It now raises.
- **`TrustVaultLogger` could fork its chain under concurrent writers**, and a damaged last line
  silently restarted the chain. Appends are now locked, the head is read from the end of the file,
  and a damaged last entry stops writes. `head()` plus `verify_chain(expected_head=,
  expected_count=)` detect truncation and rewrites, which the chain alone cannot.
- **The Trust Overlay table name was put into SQL unchecked.** It must now be a plain identifier.
- **Resending the same upload bypassed the receiver's rate limit**, and a full rate table reset
  every client's budget. Duplicates now count, and only stale buckets are evicted.
- **`evaluate_policy` ignored configured signal weights** while the logged `config_hash` claimed
  they applied. It now takes `weights` and `enabled_signals`, and the quickstart passes them.
- The SQL privacy scrubber now refuses `content`, `completion`, `tool_calls` and the other raw-text
  keys the event log already refused.
- Per-event SQL telemetry no longer rebuilds the token verifier (and its database connection) or
  re-reads `.env` for every event.
- **The opt-in SQL telemetry sink could destroy existing tables on initialization.** The native
  `sqlite:///...` path rebuilt its tables, dropping and recreating them. Initialization now checks
  the existing `lionlock_sessions`, `lionlock_signals` and `lionlock_failsafe` objects against
  their roles first and **never rebuilds, drops or renames a table**. A keyed table missing
  `auth_token_id` and `auth_signature` is upgraded by adding those two nullable columns, preserving
  existing rows and keys, and a leftover `lionlock_signals_v2` is left untouched. The guard covers
  the native `sqlite:///...` path only; SQLAlchemy URI forms such as `sqlite+pysqlite:///...`,
  PostgreSQL and the Trust Overlay initializers are unchanged.
- **Uploads could switch themselves on.** `telemetry_upload.enabled` went through `bool()`, so a
  quoted `"false"`, `"no"`, `"0"` or `"off"` in a config file enabled uploads. Only a real boolean
  or a recognised true word enables them now; anything else leaves them off.
- **Pruning could switch itself off.** A negative `sqlite_max_rows` collapsed to `0`, which means
  "keep every row". `LogStore` now rejects a negative limit and `open_store` falls back to the
  default.
- **A receiver's upload rate limit could be reset at will.** In token mode the limit counts per
  token, so rotating an install id no longer clears it. Anonymous mode can only count per
  client-chosen install id, which is bypassable by design: require tokens on any internet-facing
  endpoint.
- `decide_gate` declares all five inputs it is missing for a metadata-free payload, not only the
  three fatigue inputs. Decisions themselves are unchanged.
- The README's quick-start example now runs as written, and the claim that logging happens
  automatically is corrected.

### Added

- `lionlock-telemetry head` and `verify --expected-head FILE`; `LogStore.head()`, `heads()` and
  `verify(expected_head=...)`.
- `GateDecision.policy_adjustment`, which names the policy that changed an action
  (`warn_only_hallucination`, `hard_gate_reason_disabled` or `gating_disabled`).
- A `py.typed` marker, `lionlock.__version__`, and packaged synthetic sample sessions:
  `python -m lionlock.sample_data` runs the quickstart after `pip install`.
- The publish workflow tests the exact wheel and sdist in a fresh environment (`twine check
  --strict`, `pip check`, a smoke test and both CLIs) before upload, records their sha256, and
  states PEP 740 attestations explicitly. `scripts/reproducible_build.py` gives byte-identical
  files for the same commit.
- An agent-agnostic development harness. `make verify` is one gate over tests, lint, type checks,
  determinism, privacy and file scope, and it behaves identically for every contributor.
- A runtime check that scoring and gating reach no network, rather than only a claim that they do
  not: the scoring path is imported in a child process with the socket layer patched, and the
  third-party compiled extensions it loads are pinned so that a new binary fails a test instead of
  arriving unnoticed.
- CI refuses an unapproved change to the harness contract lock, so a change cannot edit a protected
  file and then re-bless itself by regenerating the lock.
- Releases are built and uploaded by GitHub Actions through PyPI Trusted Publishing, so no API
  token has to be stored.
- A full security policy, `SECURITY.md`, at the repository root. It covers how to report privately,
  what happens next, supported versions, what counts as a vulnerability in LionLock and which
  documented limits do not, and how releases are protected. It ships in the sdist and is linked
  from the package metadata; `docs/SECURITY.md` now points to it.

### Changed

- `severity` is always the band of `decision_risk_score`; policy changes only the action, and says
  so in `policy_adjustment`. Before, warn-only and the hard-gate list rewrote red to orange.
- `lionlock-sim --append-run` ids are `<id>-<n>`; the sim report gains an `inputs` block marking its
  sessions as synthetic, and coverage keys are renamed `*_input_high`.
- Validation errors no longer echo their input. Pydantic is no longer used at runtime, and is no
  longer installed with LionLock. LionLock now has no runtime dependencies.
- Package metadata: the licence is the SPDX expression `Apache-2.0`, and the supported Python
  versions (3.11 to 3.14) are listed. The README, which PyPI shows as the project description,
  uses absolute links so they work there.
- Optional SQLAlchemy is imported only when a SQLAlchemy code path runs, so importing the SQL
  sinks, readers or simulator no longer loads it.
- The package description now says what LionLock does and does not claim.
- **The SQL sinks no longer give up on a COMMIT with an unknown outcome.** Each stored row now
  carries an idempotency key, `(writer_id, writer_seq)`, with a UNIQUE index on it, so such a
  write is retried safely: the writer looks up which of the batch's keys are already stored and
  inserts only the rest. Events are counted as `in_doubt` only when the outcome is still unknown
  after the retries. Writer ids are assigned by the database, so the keys involve no randomness.
  A new `reconciled` counter reports events found already stored.
- **A writer id is never reused, and a key collision is never reported as a duplicate.** The next
  id is claimed above every id in both the writers table and the sink table, so emptying or
  dropping `lionlock_sql_writers` cannot make new events collide with stored ones. A UNIQUE
  violation is counted as `duplicates` only after a lookup confirms the event's own key is free;
  if another writer holds the key, the event is counted as `failed` and `key_collisions` and
  logged at ERROR level.
- Two claims about the no-network guarantee were stronger than the evidence and have been narrowed
  to what is actually proved. Parsing imports cannot see a module reaching the network through a
  dependency it never names, and a third-party compiled extension *is* loaded on the scoring path
  (`pydantic_core`), which name-based audits cannot speak to either way. Both gaps are now stated
  as open, and the extension surface is pinned by a test. (Later in this release pydantic was
  removed from the runtime path; see above.)

### Compatibility

- **Python 3.11 or newer is required.** Python 3.10 reached its end of life in October 2026 and no
  longer receives security fixes. pip on Python 3.10 cannot install 1.0.0b2, and an unpinned
  install there falls back to 1.0.0b1, which lacks the fixes above: upgrade Python first. With
  3.10 gone, `tomli` is no longer installed; LionLock reads TOML with the standard library.
- **The payload validation classes are LionLock's own.** `SignalPayload` and `SignalMetadata` in
  `lionlock.signal_schemas` are no longer pydantic models, and validation raises
  `lionlock.signal_schemas.ValidationError`, a `ValueError`, instead of pydantic's.
  `SignalPayload.model_validate` and `SignalMetadata.model_dump` remain; pydantic-only methods such
  as `model_json_schema` and `model_dump_json` do not. `score_payload` and `score_response` behave
  as before.
- **`pydantic` is no longer installed with LionLock.** If your own code imports it and relied on
  LionLock to install it, add it to your own requirements.
- The optional `failsafe` extra now needs `cryptography>=50.0.2` (it allowed `>=42`). Every
  earlier `cryptography` release has published vulnerabilities; 50.0.2 has none and supports
  Python 3.11 to 3.14.
- **Configs and policies that loaded before may now be refused**, with an error naming the bad
  setting. Finite scores outside `[0, 1]` are now refused instead of clamped. A `severity` of `red` can now come with a `REFRESH` or `ALLOW` action; read
  `policy_adjustment`. `trigger_signal` and `reason_code` can differ, because attribution is now
  weighted.
- **An older LionLock cannot verify format-2 `TrustVaultLogger` entries.** Existing logs are not
  rewritten and verify exactly as before. Existing file modes are not tightened: run `chmod 600`
  on older logs.
- **Receiver warehouses gain an `install_owners` table on first start and are then refused by
  older receivers and older `bigquery-sync`.** Upgrade both together, and receivers before
  clients. When a partner's token is replaced, re-bind its installs with an
  `UPDATE install_owners` statement (see `docs/TELEMETRY.md`).
- Trust Overlay records lose `host_id_hash`, `container_id_hash` and `signal_summary.notes`, and
  joins on the old unsalted `response_hash` no longer match.
- `lionlock-sim` needs `--db` or `LIONLOCK_DB_URL`.
- The database host and port no longer fall back to the generic `HOST` and `PORT` variables; set
  `LIONLOCK_DB_HOST` / `LIONLOCK_DB_PORT` (or the `LIONLOCK_TELEMETRY_DB_*` forms).
- Deployments that relied on environment credentials alone to turn on SQL telemetry must set
  `logging_sql.enabled = true` (and `logging.backend = "sql"` or `"both"`).
- Settings other than database connection settings must come from the real environment or an
  explicit `load_dotenv(path)`, not from an implicitly found `.env`. In particular a
  `LIONLOCK_GATING_ENABLED` line in `.env` is now ignored: set `[gating] enabled` in
  `lionlock.toml`, or export the variable. This also removes an inconsistency where the first
  `load_config()` ignored `.env` and a later one, after a database DSN was built, applied it.
  `.env.example` is now a database-settings template.
- Calling the LLM connector with an API key over plain http to a non-local host now fails with
  `insecure_endpoint_for_api_key`; use https.
- A `TrustVaultLogger` file whose last line is damaged must be inspected (and repaired) before new
  entries can be written.
- The SQL telemetry and Trust Overlay tables gain two nullable columns, `writer_id` and
  `writer_seq`, and a UNIQUE index on them; a new `lionlock_sql_writers` table records each
  writer. Existing tables are upgraded in place the first time a writer starts, keeping their
  rows (with NULL keys). This needs privileges to alter the table and create the index, and
  building the index takes one pass over a large table. A Trust Overlay table missing any of the
  sink's columns is now refused at startup instead of failing every insert.
- **The upgrade is one-way for native SQLite telemetry databases.** Earlier code that checks the
  telemetry schema, including the earlier pre-release 1.0.0b2 source commit `05434565`, refuses an
  upgraded `lionlock_signals`. 1.0.0b1, Trust Overlay tables and telemetry through SQLAlchemy keep
  working. `docs/AUDIT_LOGGING.md` ("Going back to an earlier release") gives the tested SQL that
  restores the earlier layout.
- **On the native `sqlite:///...` path, extra custom columns on a telemetry table are now
  refused**, even where named-column inserts worked before. This can turn startup into a
  `RuntimeError` through `get_writer`. Review customized schemas and take a backup before
  upgrading: initialization will not remove columns or their data to make a schema fit, and
  unknown layouts need a separately reviewed manual migration. SQLAlchemy URI forms such as
  `sqlite+pysqlite:///...`, PostgreSQL and the Trust Overlay initializers are unaffected.
- Receivers admit `1.0.0b2` as a public version label. **Upgrade a receiver before its clients**,
  because an older receiver rejects snapshots that carry the new label.

## 1.0.0b1 — first public beta

The first public beta of open-source LionLock. Interfaces may still change before 1.0.0.

- Local, hash-chained SQLite telemetry log, with opt-in uploads of allowlisted, pseudonymized
  fields to a receiver you run (`lionlock-telemetry`).
- Reference ingest server that validates every upload as untrusted input and stores only
  rebuilt, validated snapshots.
- `lionlock-telemetry bigquery-sync`: copies the receiver's warehouse into BigQuery. Each
  `events` and `trust_records` row is loaded exactly once, and `uploads` is replaced as a
  snapshot whenever it changes.
- `low_conf_halluc` no longer flags grounded answers, and the uncalibrated `fatigue_risk_index`
  no longer gates when its inputs are missing (signal schema `SE-0.4.0`).
- Receivers admit `1.0.0b1` as a public version label. Upgrade a receiver before its clients,
  because an older receiver rejects snapshots that carry the new label.

## 0.1.0

Initial open-source preview.
