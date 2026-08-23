# gearwit

**Everyone performs better with good kit.**

gearwit is local-first kit for coding-agent seats that already exist. A seat
can say who it is, register, arm a wait, and declare a blocker. A human or
squad can watch an attention timeline and a roster that labels
controller-proven, self-declared, and inferred facts without disguising
unknown state.

The harness keeps the model loop. gearwit is the kit.

**Lifecycle:** architecture scaffold / pre-alpha.

## What it is

- Self-help for a seat: identify, register, wait, inspect, and ask for help
- Squad-help for an operator: attention events, sleepers, and honest status
- One local daemon with CLI and console projections over the same state
- A local-first control plane with explicit degraded behavior

## What it is not

- An agent, harness, REPL, or tool-use loop
- A remote-session continuation product
- A squad launcher or terminal studio
- The Lanyte autonomy supervisor
- A reason to infer that an unregistered process is healthy or idle

## Repository shape

This is an intentional Rust and TypeScript pseudo-monorepo:

```text
crates/gearwit-domain/  platform-free facts and evidence semantics
crates/gearwit-protocol/ schema-backed daemon/client boundary
crates/gearwit-platform/ host census, paths, and process abstractions
crates/gearwit-host/    daemon, registry, routing, policy, and persistence port
crates/gearwit-cli/     thin seat and operator command surface
apps/console/           attached console projection; no second daemon
docs/decisions/         architecture and product decision records
```

`gearwit-domain` and `gearwit-cli` exist. Other packages are added with their
first working slice, rather than as empty roadmap directories.

Cargo and Bun remain authoritative for their own dependency graphs. The root
`Makefile` is the stable human and CI entry point.

## Quick start

```bash
make check
cargo run -p gearwit-cli -- self who
```

The first command surface is `gearwit self who`: a census-safe local card with
per-field evidence. It is not a public wire protocol. No daemon is implemented
yet.
