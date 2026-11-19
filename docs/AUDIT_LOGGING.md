# Audit Logging Canonical Surface

## Canonical audit stream

The canonical tamper-evident audit log in OSS LionLock is `TrustVaultLogger` (`src/lionlock/logger.py`).
Each entry includes `prev_hash` and `sha256` so records are chained in append order.

Use `TrustVaultLogger.verify_chain()` to validate the on-disk chain. It detects entries that were
edited, inserted, reordered or removed from the start or middle. Appends are serialized across
threads and, on POSIX, across processes; a damaged last entry (for example from a crash mid-write)
stops further writes instead of silently starting a new chain.

A self-contained hash chain cannot detect that its newest entries were removed, or that the whole
log was rewritten with freshly computed hashes. To detect those, record `TrustVaultLogger.head()`
(entry count and last hash) somewhere the log's writer cannot change, and later pass it back:

```python
count, head = logger.head()  # store these elsewhere
logger.verify_chain(expected_head=head, expected_count=count)
```

A log that has grown since the head was recorded still verifies, as long as the recorded head is
still in it.

`record()` refuses a payload that has no canonical form (see below) with a `ValueError` that names
the offending path, for example `payload.turn_scores: key 9 (int) is not text`. It checks before
touching the disk, so a refused call creates and changes nothing. A new log file is created
owner-only (mode 0600) by the call that creates it, and missing parent directories 0700, whatever
the umask. An existing file or directory keeps its mode; LionLock never changes it, so tighten an
older log yourself if it is readable by others (`chmod 600 trustvault.log`).

## TrustVaultLogger entry format

A log is UTF-8 text with one entry per line, each line ending in LF. Blank lines are ignored.
Every entry is a JSON object. Since 1.0.0b2 entries are written in **format 2**; entries written
before carry no `format` member and are called **legacy** entries. One log may hold both: a legacy
log continues in format 2 when a newer LionLock appends to it, and the old lines are never
rewritten. A verifier checks each entry by the rule of its own format.

### Format 2

An entry has exactly these six members:

| Member | Value |
| --- | --- |
| `ts` | UTC time of the append, ISO 8601 with a `Z` suffix |
| `event` | the event name passed to `record()` |
| `format` | the number `2` |
| `payload` | the payload passed to `record()` |
| `prev_hash` | `sha256` of the previous entry; 64 `0` characters for the first entry |
| `sha256` | lowercase hex SHA-256 of `C(entry without its sha256 member)`, where `C` is below |

To verify a line: parse it as JSON, reading every number as the nearest IEEE-754 double (as
JavaScript's `JSON.parse` does); check the members and `format`; remove `sha256`; compute `C` of
the rest; compare its SHA-256 with `sha256`, and `prev_hash` with the previous entry's `sha256`.
The hash covers the values, not the line's bytes, so a line re-encoded by another JSON writer
still verifies. LionLock writes each line as exactly `C(entry)`, `sha256` included.

`C` is the JSON Canonicalization Scheme of RFC 8785, so any RFC 8785 implementation computes it.
In full, `C(value)` is UTF-8 text built as follows, with no whitespace anywhere:

- `null`, `true`, `false`: those words.
- **String**: `"`, the characters, `"`. Only these are escaped: `"` as `\"`, `\` as `\\`,
  U+0008 `\b`, U+0009 `\t`, U+000A `\n`, U+000C `\f`, U+000D `\r`, and every other character from
  U+0000 to U+001F as `\u00xx` with lowercase hex. Everything else, including U+007F, non-ASCII
  text and U+2028/U+2029, is written as its own UTF-8 bytes. A string must not contain an unpaired
  surrogate.
- **Number**: the double `x` written as JavaScript's `String(x)` writes it. NaN and Infinity are
  not allowed. If `x` is zero (including -0) write `0`. Otherwise write `-` if `x < 0`, then for
  `|x|` take the shortest digit string `d` (`k` digits, no leading or trailing zeros) and the
  integer `n` such that `0.d × 10^n` reads back as exactly `|x|`; when several `k`-digit strings
  qualify, take the one closest to `|x|`. Then:
  - `k ≤ n ≤ 21`: `d` followed by `n − k` zeros (`1.0` → `1`, `1e16` → `10000000000000000`);
  - `0 < n ≤ 21`: the first `n` digits, `.`, the rest (`3.5` → `3.5`);
  - `−6 < n ≤ 0`: `0.`, then `−n` zeros, then `d` (`1e-6` → `0.000001`);
  - otherwise: the first digit, then `.` and the other digits if `k > 1`, then `e`, `+` or `-`,
    and `|n − 1|` (`1e-7` → `1e-7`, `1e21` → `1e+21`, `5e-324` → `5e-324`).
- **Array**: `[`, the items' `C` joined by `,`, `]`.
- **Object**: `{`, then the members `C(key):C(value)` joined by `,`, then `}`. Members are sorted
  by key, comparing keys as sequences of UTF-16 code units (`"10"` before `"9"`; U+1D11E, stored as
  the surrogates D834 DD1E, before U+FF5A). Keys are always strings.

`record()` also refuses, so that every implementation reads the same values back: non-string keys
(LionLock never converts a key to text), integers outside ±(2^53 − 1) (pass larger magnitudes as
floats or text), and any other type than dict, list, tuple, str, int, float, bool and None. A tuple
is written as an array. Because a number is its double value, a payload `1.0` reads back as `1`,
`-0.0` as `0` and `1e20` as the integer `100000000000000000000`; they compare equal.

**Test vectors.** `tests/fixtures/trustvault_format2_vectors.json` holds a synthetic six-entry
chain covering every rule above, each with its line, the exact text hashed and the hash.
`tests/test_trustvault_vectors.py` recomputes them from this section alone, without LionLock's
code. The first two:

```text
hashed: {"event":"detect","format":2,"payload":{"signal":"noop"},"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","ts":"2026-01-01T00:00:00Z"}
sha256: db5f2c557e0c4d35e2038c0c92501e32338d1abe7a5d056c385e960f18643ef6

hashed: {"event":"detect","format":2,"payload":{"turn_scores":{"10":0.7,"9":0.4}},"prev_hash":"db5f2c557e0c4d35e2038c0c92501e32338d1abe7a5d056c385e960f18643ef6","ts":"2026-01-01T00:00:01Z"}
sha256: 066299926f6389f9c27fca2fce15d79a02b4ba6881b90f71836424d50a3493f1
```

The remaining hashes, in chain order: `4d322f0a…cdaf63` (numbers), `aa59d134…e0c28d` (strings and
escapes), `4484f33a…62f1d752` (key order) and `40d53f34…6a058407` (nesting and literals).

An entry with a `format` member other than the number 2, with members other than the six above, or
with a value that has no canonical form (for example a NaN written into the line) fails
verification with a message saying so.

### Legacy entries

An entry without a `format` member is verified exactly as before 1.0.0b2: `sha256` is the SHA-256
of Python's `json.dumps(entry_without_sha256, sort_keys=True, separators=(",", ":"))`. That rule
is specific to Python (its float formatting, ASCII escaping and bare `NaN`/`Infinity`), so other
languages cannot reliably reproduce it. It also has a known flaw that is kept as it was: a payload
dict with integer keys was hashed with the keys in numeric order, but they read back as text and
re-sort as text, so an honest legacy entry such as `{"turn_scores": {9: 0.4, 10: 0.7}}` fails with
`Entry #N hash mismatch`. Verification stops at the first failing entry, so in such a log the later
entries are not checked. LionLock does not rewrite or migrate legacy logs to fix this; their
verification result is unchanged. Format 2 makes the problem impossible for new entries by
refusing non-text keys.

`tests/test_trustvault_format2.py` checks that legacy logs (honest, with integer keys, with NaN,
and tampered in several ways) give exactly the results of the pre-1.0.0b2 verifier, and that a
legacy log can continue in format 2.

## Public telemetry stream

`src/lionlock/logging/event_log.py` writes sanitized public telemetry events for analysis. By
default they go to the local SQLite log `logs/lionlock.db`, which also holds Trust Overlay
records. Each table in that file is a per-table SHA-256 hash chain, checked with
`lionlock-telemetry verify` (see [TELEMETRY.md](TELEMETRY.md)). Detecting rows removed from the
end, or a history rewritten with fresh hashes, needs a head recorded where the log's writer cannot
change it: `lionlock-telemetry head`, later `verify --expected-head`. JSONL and SQL backends
remain available. This stream is privacy-focused and operational; `TrustVaultLogger` remains the
canonical audit chain.

New JSONL files written by the event log (`logging.path`) and by the Trust Overlay
(`logs/trust_overlay/*.jsonl`, including annotations) are created owner-only (0600), and missing
directories 0700, by the call that creates them. Existing files and directories keep their modes.
Trust Overlay records no longer hold guessable digests or free text: `response_hash` is an
HMAC-SHA256 of the reply under a key derived from the configured salt (`TRUST_OVERLAY_SALT` or
`[trust_overlay] salt`), or null when no salt is set; the hostname and container digests are gone;
and `signal_summary.notes` is dropped. Each new record says which rules it was written under in
`hash_scheme` (`keyed-v1`, `caller` for a hash the caller passed in, or `none`); records without
it predate the change and may hold unkeyed SHA-256 digests. Existing files are not rewritten.

## SQL sink delivery guarantees

### Native SQLite initialization and preservation

For the opt-in SQL telemetry sink, `sqlite:///...` initialization checks all existing
`lionlock_sessions`, `lionlock_signals` and `lionlock_failsafe` objects before creating or
altering any requested table. The table names must match their roles. Views, virtual tables,
`WITHOUT ROWID`/`STRICT` tables, and unknown column layouts are refused. Column names, normalized
declared types, primary keys and hidden/generated columns are checked through SQLite metadata;
column order is immaterial. Extra CHECK/UNIQUE constraints, indexes and triggers are retained.
These checks require SQLite 3.37 or newer (`table_list` and `table_xinfo`); an older engine is
refused before schema changes. A matching layout establishes structural compatibility, not
database ownership or the authenticity of its contents.

All three canonical tables are checked even when the operation requests only one or two. An
incompatible, unrequested failsafe table can therefore prevent writer startup or session writes.
**Upgrade compatibility:** extra custom columns are refused, even on a telemetry table that worked
previously with named-column inserts. This can turn startup into a `RuntimeError` through
`get_writer`. Review customized schemas and backups before upgrading; initialization does not
remove those columns or their data to make the schema fit.

The supported older layouts are the initial OSS signals schema, which has `event_pk` and
`session_pk` but lacks `auth_token_id` and `auth_signature`, and the schema with those two columns
but without the writer key (`writer_id`, `writer_seq`; see "Idempotency keys" below). Each is
upgraded by adding the nullable columns it lacks and the writer key's UNIQUE index, preserving
the existing rows, keys, indexes and triggers. Initialization also creates the
`lionlock_sql_writers` table. Initialization never rebuilds, drops or renames a table. Unknown layouts, including unkeyed partial tables, need a separately reviewed
manual migration. A leftover `lionlock_signals_v2` table is left untouched, even if the original
signals table is absent; initialization does not recover its rows automatically.

Native initialization uses one connection, explicit `BEGIN IMMEDIATE`, and one commit or rollback.
Schema validation and requested DDL share that transaction. Session begin/update and failsafe
inserts validate under the same write lock as their DML. The connection timeout bounds startup
lock waits (five seconds by default; writer startup uses `connect_timeout_s`). Another writer can
therefore cause a startup refusal on timeout. No claim of power-loss durability follows from
transaction rollback tests, and running background batches do not revalidate a schema changed by
another actor after startup.
Session anomaly updates now initialize a missing sessions table, database file and parent
directory before the update; the previous bare update did not create that schema.

Refusals preserve the existing API contracts: `init_db` returns `(False, message)` and SQL writer
startup records its error, which `get_writer` propagates as `RuntimeError`. `begin_session` returns
`None` and `update_session_anomalies` returns silently, so their callers cannot distinguish a schema
refusal from other caught failures through the return value. A rejected `write_failsafe_blob`
returns `(False, message)` and does **not** persist the new blob. Callers must handle these outcomes;
unhandled telemetry startup errors can interrupt a caller even though scoring/gating are unchanged.

This preservation guard applies to the native `sqlite:///...` path. SQLAlchemy URI forms such as
`sqlite+pysqlite:///...`, PostgreSQL, and the separate Trust Overlay/Module 04 schema initializers
retain their existing behavior and are outside this guard, apart from the writer key upgrade
described under "Idempotency keys". Existing production databases are not
migrated by installing this code; initialization runs only when invoked.
Relative file paths remain supported. `:memory:` initialization remains ephemeral; sessions and
failsafe writes do not report those connection-local records as persisted across calls.

### Delivery policy

The opt-in SQL sinks (`logging_sql` for public telemetry, `trust_overlay.sql` for Trust Overlay
records) queue events in memory and insert them in batches from a background thread. Both share
one delivery policy, `src/lionlock/utils/sql_batch_writer.py`:

- **Every accepted event is accounted for exactly once**, as `written`, `duplicates` (already
  stored: rejected by a UNIQUE or PRIMARY KEY constraint), `failed` (a write was attempted but
  the row was not persisted), `in_doubt` (the COMMIT failed without a known outcome, so the row
  may or may not be stored) or `dropped` (never attempted). Until then it is `pending`, so
  `enqueued == written + duplicates + failed + in_doubt + dropped + pending` always holds.
- **Shutdown flushes.** `stop_writer()`, which also runs at interpreter exit, writes everything
  still queued before returning, bounded by `stop_timeout_s`. Events it cannot start writing in
  time are counted as `dropped_on_stop`.
- **Transient errors are retried, not fatal.** Lock contention (`database is locked`) and lost
  connections are retried up to `max_retries` times with exponential backoff: `retry_backoff_ms`,
  doubling per retry, capped at 2 s, with no jitter. Write errors never disable the writer and
  never raise into `log_event()` or `append_trust_record()`.
- **No write is stored twice.** Every event carries an idempotency key, and a UNIQUE index on
  it lets the database itself refuse a second copy. If a COMMIT fails without a known outcome,
  for example because the connection was lost, the writer looks up which of the batch's keys are
  already stored, counts those events as `written` (and `reconciled`), and inserts only the rest.
  Events are counted as `in_doubt` only if the outcome is still unknown when the retries run out.
- **One bad row cannot sink its batch.** A non-transient batch error, such as a UNIQUE violation,
  rolls the batch back and re-inserts it row by row. True duplicates are skipped and counted as
  `duplicates`, other constraint failures are counted as `failed`, and every other row is written.
- **A duplicate is confirmed, not assumed.** `duplicates` means "already stored", so a UNIQUE
  violation counts as one only after the writer has looked up the event's own key and found it
  free: another UNIQUE constraint on the table refused the row. If the key itself is taken, see
  "Key collisions" below. If the lookup fails, the event is counted as `failed`.
- **Overflow is reported.** When the queue (`max(100, 10 * batch_size)` events) is full, the
  oldest queued event is evicted to keep the newest data. Each eviction is counted as
  `dropped_queue_full` and logged as a warning at the 1st, 2nd, 4th, 8th, ... drop.

Startup failures differ by sink. For public telemetry, invalid configuration and startup failures
raise `RuntimeError` from `log_event()`, and the next call tries to start a writer again. Trust
Overlay never raises for SQL problems: if its SQL writer cannot start, `append_trust_record()`
still writes the JSONL record but nothing reaches SQL, and
`lionlock.trust_overlay.sql_sink.get_writer()` returns `None` until the `[trust_overlay.sql]`
configuration changes or `stop_writer()` is called.

Read the counters with `lionlock.logging.sql_telemetry.writer_stats()` or
`lionlock.trust_overlay.sql_sink.writer_stats()`. `stop_writer()` returns the counters when it
returns; they are final unless `pending` is non-zero, which means a write was still running at the
deadline. That write is not interrupted, and its outcome is logged as `sql_sink_late_outcome` when
it finishes. `reconciled` counts events whose COMMIT had an unknown outcome and that a later
lookup found already stored; they are also counted as `written`. `key_collisions` counts events
refused because another writer had stored a row under the same key; they are also counted as
`failed`. `writer.last_error` holds the most recent write error without data values: the error
type, its SQLite or SQLSTATE code when available, and the first line of the driver message cut at
the first quote.

### Idempotency keys

Each row a sink stores carries `(writer_id, writer_seq)`, and each sink table has a UNIQUE index
on that pair, named `<table>_writer_key`. No randomness is involved:

- `writer_id` is claimed once per writer when it starts: one above the highest id recorded in
  `lionlock_sql_writers` (`writer_id`, `sink`, `started_utc`) and in the sink's own table,
  inserted under the writers table's PRIMARY KEY, so two writers never share one. Reading the
  sink table too means a writers table that was emptied, dropped or restored from an older backup
  cannot hand out an id whose keys are already stored. In PostgreSQL the claim locks the writers
  table briefly, so writers starting together claim in turn.
- `writer_seq` counts the writer's accepted events from 1 and is assigned when an event is
  queued, so an event evicted from a full queue leaves a gap. For each writer, the stored
  sequence numbers are those of its `written` events plus any `in_doubt` events that did reach
  the table; every other sequence number is a `dropped`, `failed` or `duplicates` event. The
  one exception is a reported key collision (below), where another writer's row occupies the
  key of an event this writer counted as `failed`.

The UNIQUE index also covers a PostgreSQL COMMIT that is still finishing when its keys are looked
up: the re-insert then fails on the key instead of storing a second copy, and the keys are looked
up again.

Existing tables are upgraded when a writer starts (or `init_db` runs): the two nullable columns
are added and the index is built. Rows stored before the upgrade keep NULL keys, which a UNIQUE
index never treats as equal. Building the index reads the whole table once, so the first start
after upgrading takes longer on a large table, and it needs the database privileges to alter the
table and create the index and the writers table. A Trust Overlay table that lacks any of the
sink's own columns, or has only one of the two key columns, is refused rather than altered, as is
an existing index named `<table>_writer_key` that is not a unique index on exactly the key.

**Key collisions.** Outside reconciliation a writer has never stored the events it is writing, so
its own key can be taken only if another writer holds the same id: for example the writers table
was emptied while a writer that had not yet stored anything was running, and a new writer claimed
the same id. The database refuses the second row, so nothing is overwritten, but the refused event
is not stored. It is counted as `failed` and `key_collisions`, `last_error` starts with
`writer key collision`, and `sql_sink_writer_key_collision` is logged at ERROR level at the 1st,
2nd, 4th, 8th, ... collision. Restart the writer so it claims a fresh id.

### Going back to an earlier release

The upgrade is one-way for the native SQLite telemetry tables (`sqlite:///...`). Earlier code that
checks the telemetry schema but predates the writer key, which includes the source the README
currently pins for 1.0.0b2, refuses to start on an upgraded `lionlock_signals` with
`Incompatible SQL telemetry schema: lionlock_signals`. 1.0.0b1 does not check the schema and keeps
working. Trust Overlay tables, and telemetry tables reached through SQLAlchemy, keep working with
earlier releases: those name their columns on insert and leave the nullable key columns NULL.

To return a native SQLite telemetry database to the layout earlier code accepts, stop every
writer, back the file up, and run this (SQLite 3.35 or newer):

<!-- rollback-sql: tests/test_sql_telemetry_preservation.py runs this block as written -->
```sql
BEGIN IMMEDIATE;
DROP INDEX lionlock_signals_writer_key;
ALTER TABLE lionlock_signals DROP COLUMN writer_seq;
ALTER TABLE lionlock_signals DROP COLUMN writer_id;
COMMIT;
```

This discards the keys of rows written since the upgrade; the rows themselves are kept.
`lionlock_sql_writers` can stay: earlier code ignores it, and a later upgrade claims ids above
the ones it records.

Optional keys, accepted by both `[logging_sql]` and `[trust_overlay.sql]`:

| Key | Default | Meaning |
| --- | --- | --- |
| `max_retries` | `5` | Retries per write after a transient error. |
| `retry_backoff_ms` | `50` | First retry delay; doubles per retry, capped at 2 s. |
| `stop_timeout_s` | `2.0` | Upper bound on the flush done by `stop_writer()` and at exit. |

## Verification coverage

Tamper and truncation checks are covered by `tests/test_logger.py` and
`tests/test_logger_integrity.py` (concurrent writers, damaged last entry, truncation and rewrite
against a recorded head).

SQL sink delivery guarantees are covered by `tests/test_sql_writer_reliability.py` (both sinks,
via sqlite3 and, when installed, SQLAlchemy), `tests/test_public_telemetry_persistence.py` and
`tests/test_trust_overlay_sql.py`.
