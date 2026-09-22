# Gearwit simulator

`gearwit-sim` is a development-only deterministic runner. Production crates do
not depend on it. It combines an independent abstract state oracle with the
admitted fake and bundled SQLite fixture bridge.

The host bridge is behind the non-default `gearwit-host/simulator` feature.
An ordinary CLI build does not select it; verify the boundary with:

```sh
cargo check -p gearwit-cli --locked
cargo tree -p gearwit-cli -e features --locked
cargo tree -p gearwit-sim -e features --locked
```

Run a fixed scenario and save its replay bundle:

```sh
cargo run -p gearwit-sim -- scenario --id SIM-CHAIN-01 --store sqlite \
  --seed 17 --root target/gearwit-sim/chain
```

Run a bounded seeded campaign, replay one result, or compare two results:

```sh
cargo run -p gearwit-sim -- campaign --seed 23 --runs 16 \
  --root target/gearwit-sim/campaign
cargo run -p gearwit-sim -- replay \
  --bundle target/gearwit-sim/chain/sim-chain-01-17-sqlite.json
cargo run -p gearwit-sim -- compare --left result-a.json --right result-b.json
```

`SIM-PROC-01` launches a child process, waits for a named SQLite commit
milestone, kills the child, and verifies the media in the parent process. The
artifact labels the exact OS, architecture, simulator version, seed, store,
resolved stimuli, queue accounting, host checks, and semantic fingerprint.
Seeded campaigns use the in-process catalog; run `SIM-PROC-01` explicitly so a
campaign cannot hide the cost or platform boundary of a real process kill.

The stable readiness catalog is:

| IDs | Coverage |
| --- | --- |
| `SIM-CHAIN-01` | Full helper chain through rearm and admission of the next event |
| `SIM-CHAIN-02` | Exact retrieve and acknowledgment retry before and after restart |
| `SIM-CHAIN-03` | Changed-content operation identity reuse conflicts across restart |
| `SIM-CHAIN-04` | Revocation survives restart and refuses a fresh retrieve |
| `SIM-CHAIN-05` | Stale authority cannot regain access after restart |
| `SIM-CHAIN-06` | An event arrives while rearm waits for terminal state |
| `SIM-CHAIN-07` | A child is killed after acknowledgment; a fresh process reopens its own SQLite media |
| `SIM-CHAIN-08` | Omitted rearm produces the recorded inactive outcome |
| `SIM-QUEUE-01` | Independent offered arrivals, bounded queue growth, completion, and visible rejection |
| `SIM-REPLAY-01` | A named early-rearm failure reproduces the same semantic fingerprint |
| `SIM-PROC-01` | Pre-commit and post-commit killed child with fresh-process SQLite reopen |
| `SIM-ORACLE-01`–`SIM-ORACLE-04` | Detection of duplicate admission, lost committed acknowledgment, revoked-grant resurrection, and false durable-publication success |

Artifacts use `gearwit.sim/v1`. Unknown versions are refused. Failed runs keep
the full bounded stimulus list and observations. Manual reduction removes
stimuli while retaining causal parents, reruns the reduced envelope, and keeps
the smallest artifact with the same oracle finding and semantic failure.

The runner caps scheduled work at 1,024 events, virtual time at 10,000 ticks,
and each JSON replay bundle at 1 MiB. Hitting a runner cap yields `incomplete`;
it cannot become a successful system result. Queue capacity and rejection are
separate scenario facts and are reported in offered, admitted, rejected,
completed, delivered, duplicated, dropped, and maximum-depth counters. Source,
actor, scheduler, and fault seeds are derived into separate recorded streams.

The current host bridge covers arm and claim admission, helper grant and
revocation, retrieve, scoped materialization, acknowledgment, authority
recovery, and the handled-plus-terminal rearm join. Controller native-write
coordination, production key resolution, migration, compaction, live private
material, and stores other than the fake and bundled SQLite baseline remain
unsupported by this simulator package.

Artifacts report correctness and replay evidence only. They do not report or
imply wall-clock performance qualification; performance runs use a separate
profile in the later comparison work.

Successful routine bundles may be deleted after the review window. Named
failures, selection evidence, and the smallest reproduction stay with the
review evidence. Bundles contain synthetic identifiers and payload-free host
check results only.
