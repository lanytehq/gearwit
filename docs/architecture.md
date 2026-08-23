# Gearwit architecture

Gearwit is one local-first product with one daemon state machine and multiple
faces. The CLI, attached console, MCP surface, and sibling products consume the
same protocol and capability model.

## Runtime boundary

```text
console / CLI / MCP / sibling products
                    ↓
           schema-backed protocol
                    ↓
               gearwit host
       ↙ domain             platform ↘
 registry · router · policy · adapters · persistence port
```

The first release keeps registry, router, policy, adapters, and persistence as
host modules. They become crates only when their dependency or release
boundaries genuinely diverge.

## Source-of-truth rules

- Crucible schemas precede public file and wire bindings.
- Domain state contains no transport, provider, storage, or UI dependencies.
- The host is the only persistence writer and controller-lease owner.
- Native providers normalize into a common event envelope before routing.
- Every projected fact preserves its own evidence class.
- Unknown state is represented directly rather than inferred away.

## Control safety

Presence and controller authority are separate bindings. Native control
requires a host-minted attachment proof, matching generation, supported
capability, and unexpired lease.

Authority-bearing routes claim durably before dispatch. Only a proven
pre-dispatch failure permits a new attempt. A failure after send or acceptance
is ambiguous and suppresses automatic replay.

## Product boundaries

Gearwit does not own the harness inference loop, launch squads, remotely
continue arbitrary sessions, or supervise autonomous missions. It may compose
with products that perform those jobs through explicit contracts.

The daemon does not embed Wasmtime or load agent-authored code. Future
power-ups execute in fresh capability-limited workers and call a narrow API.
