# ADR-0002: Local persistence provider boundary

- Status: Proposed
- Date: 2026-08-23
- Updated: 2026-08-26

## Context

The daemon needs durable registration, sleeper, claim, receipt, lease,
controller-correlation, handled-cursor, and re-arm state. Claim-before-dispatch
and replay suppression require atomic state transitions, exact restart
reconstruction, and durable representation of ambiguous native effects.

Local-first operation must not require a hosted service. Sandboxed agents must
not need direct filesystem access to the authority store. A path or authority
failure beneath a protected application directory affects append-only files,
embedded databases, key-value stores, and Git repositories alike, so
storage-root admission is separate from provider selection.

The initial SQLite proposal was intentionally unaccepted. Subsequent design
work showed that Gearwit's state may be represented by several credible local
storage shapes:

- bundled SQLite transactions;
- atomic-batch embedded key-value storage;
- daemon-owned Git revisions;
- digest-chained NDJSON plus snapshots; and
- local Turso Database with sync absent.

Auditability is required, but database independence and human-readable
authority files are not goals by themselves. Hosted projection and
multi-machine ownership are separate topology decisions.

## Decision

### Sealed semantic port

Gearwit persistence remains a private, sealed host port expressed only in
Gearwit domain operations. Provider adapters cannot add SQL, key-value, file,
Git, transition, recovery, or payload escape hatches to the semantic contract.

The deterministic fake and every candidate provider run the same
backend-neutral conformance model.

### One local authority provider

One admitted Gearwit installation owns one authority store beneath Gearwit's
admitted private state root (currently `$HOME/.lanyte/gearwit/state` under
ADR-0003's no-follow path rules). Provider selection cannot relocate or weaken
that path boundary. Only `gearwitd` writes the store.

Development and conformance builds may select among compile-time/testable
providers. A production store is created with exactly one accepted provider.
It does not:

- silently fall back to another provider or durability mode;
- mirror authority writes;
- activate network or hosted authority;
- dynamically load caller-supplied storage code; or
- infer a provider change from files found on disk.

Provider identity, format/schema version, store epoch, installation identity,
and proven durability class are explicit and checked at open.

### Atomic semantic audit

Every authority-bearing mutation and the semantic audit/evidence record that
explains it share one atomic or exact replay-safe provider boundary.

The provider-independent evidence record carries a monotonic sequence, prior
revision, operation identity, producer/evidence class, and safe/private
classification. Missing, gapped, rolled-back, or conflicting evidence refuses
recovery.

Redacted export may lag behind authority and resume from a durable cursor. It
is never the only audit copy and never becomes controller authority.

### Private state and encryption

Provider bodies, private native references, verifier material, and equivalent
recovery secrets are confined to the smallest private records or opaque
retained payload references required for exact recovery.

The private recovery partition is encrypted before live Gate-1 proof.
Encryption keys do not live beside the store, in repository configuration,
audit-safe output, diagnostics, snapshots, or backups. Missing or wrong key
material fails closed and cannot create, migrate, or export plaintext state.

Sandboxed agents, projectors, and recovery tools never open the live authority
root directly. They consume daemon-minted bounded responses or frozen views.

### Provider qualification and selection

Bundled SQLite is the mature transactional baseline, not an automatic default.
A transactional embedded KV and a time-boxed Forgeprims Git revision store are
required comparison shapes. NDJSON and local Turso remain independently
time-boxed candidates.

Every attempted provider publishes a scoped parity report covering:

- semantic and ambiguous-effect recovery;
- idempotency and conflict detection;
- audit atomicity and rollback detection;
- corruption, migration, locking, and durability barriers;
- encryption, private retention, and safe projection;
- admitted path and disabled-network behavior;
- post-retention steady-state size and maintenance amplification; and
- supported-platform packaging and operations.

Every non-baseline candidate declares a feasibility screen and maximum
engineering cap before adapter work begins. A cap produces pass, fail, or
inconclusive evidence; it does not hold the managed-controller lane.

Backend-specific production authority begins only after an accepted amendment
to this record, or an accepted superseding record, names the selected provider
and its qualified platform/durability scope.

### Portability and multiple machines

A verified frozen view, sealed Git epoch, backup, or redacted/encrypted export
may be copied or published through another system. That portability does not
transfer authority.

A copied store, forge remote, object-store replica, Turso sync target, or
second host cannot resume claims or controller ownership without a separately
accepted fencing and ownership-transfer design.

## Consequences

- Gearwit can develop the semantic port, deterministic fake, conformance model,
  and SQLite baseline without waiting for every candidate.
- Multiple storage shapes expose accidental provider leakage before production
  selection.
- Production startup remains simple: one provider, one writer, one admitted
  root, and one declared durability class.
- Audit semantics survive provider selection without requiring NDJSON or Git
  to be the authority format.
- Storage growth is evaluated after retention, compaction/packing, and sealed
  rollover rather than by insertion throughput alone.
- Encryption is an application/provider boundary requirement, not a claim that
  filesystem encryption is sufficient.
- Portability supports verification and recovery without becoming an
  accidental distributed-controller protocol.
- A later shared Lanyte principle may be extracted only after another product
  demonstrates the same invariant; this record remains Gearwit-local.

## Rejected alternatives

### Select SQLite before parity evidence

SQLite is credible and mature, but familiarity and implementation speed are not
selection evidence. It remains the baseline while the bounded alternatives are
screened.

### Make NDJSON or Git auditability the authority requirement

Both offer inspectable revision history. Neither removes the need to prove
atomic semantic updates, encryption, retention, compaction, migration,
capacity, and crash recovery.

### Select Turso for hypothetical future cloud authority

Optional remote projection does not justify changing local authority semantics.
Multi-host wake ownership requires explicit fencing and conflict decisions
regardless of the local engine.

### Allow runtime fallback or mirrored writes

Fallback hides the actual durability class. Mirrored authority introduces
cross-provider partial-commit and disagreement states. Both are forbidden.

### Let recovery tooling open or repair live authority

That would create a second controller. Recovery tooling remains bounded and
read-only; only `gearwitd` maintenance mode may apply a verified plan under the
exclusive authority lock.
