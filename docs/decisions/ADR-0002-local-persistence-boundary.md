# ADR-0002: Local persistence boundary

- Status: Proposed
- Date: 2026-08-23

## Context

The daemon needs durable registration, sleeper, claim, receipt, lease, and
attention state. Claim-before-dispatch and replay suppression require atomic
state transitions and crash recovery. Local-first operation must not require a
hosted service.

Sandbox failures observed in coding-agent tools can involve a process trying
to open state beneath a protected application directory. That is a path and
authority failure: an append-only file, embedded analytical database, or
SQLite database would all fail in the same unwritable location.

The storage choice must therefore be separated from storage-root admission.
Startup must resolve a platform data directory, prove it writable with the
required privacy mode, and fail honestly when it is unavailable.

## Options

### Single-writer SQLite plus receipt export

SQLite provides transactions, uniqueness constraints, migrations, indexed
timeline queries, and mature crash recovery. A single daemon writer avoids
multi-process ownership. NDJSON export preserves portable receipts and
offline inspection.

### Append-only NDJSON plus snapshots

NDJSON makes the audit stream portable and easy to recover. It also requires
the product to implement locking, indexes, compaction, migrations, uniqueness,
and transactional coordination between current state and claims.

### DuckDB or Parquet as the authority

Both are valuable analytical and interchange tools. Neither is a natural
authority for frequent transactional claims, leases, and uniqueness checks.
They remain suitable downstream projections.

### Required hosted or replicated database

A hosted dependency can support later multi-host projections but weakens the
local-first path, adds authentication and outage modes, and does not solve
local sandbox admission.

## Proposed decision

Define persistence as a host-only port. For the first local implementation:

- use one daemon writer;
- place state in a platform-sanctioned, user-private data root;
- perform an explicit writable/privacy startup probe;
- use SQLite for transactional current state and claim recovery;
- provide append-only NDJSON receipt export;
- never silently fall back to a weaker durability class.

Keep DuckDB, Parquet, and hosted replication as projections or later adapters,
not the local authority.

## Consequences

- Sandbox compatibility depends on an explicit admitted data root rather than
  the filename format.
- Transactional route claims do not require a bespoke database layer.
- Portable receipts remain available without making NDJSON the query store.
- The backend remains replaceable behind the host port.
- This record requires acceptance before storage-specific implementation.
