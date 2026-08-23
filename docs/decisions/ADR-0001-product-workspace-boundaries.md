# ADR-0001: Product workspace boundaries

- Status: Proposed
- Date: 2026-08-23

## Context

Gearwit ships a local daemon, command-line interface, and attached console
that must evolve as one compatible release. It also integrates with
independently released harness, launch, remote-access, schema, and platform
libraries.

A repository per face would permit protocol drift and duplicate controller
state. An estate-wide monorepo would couple unrelated products and release
cadences. Creating a crate for every conceptual module before behavior exists
would add coordination without an actual dependency boundary.

## Decision

Use one product pseudo-monorepo:

- Cargo owns Rust packages.
- Bun owns the console web package.
- The root Makefile is the stable integrated entry point.
- The daemon is the only registry, routing, policy, lease, and persistence
  authority.
- CLI, console, and future faces consume one schema-backed protocol.
- Independently released products and foundation libraries remain external
  versioned dependencies.

Begin with five Rust boundaries:

1. platform-free domain
2. schema-backed protocol
3. host-platform abstractions
4. daemon host
5. thin CLI

Registry, router, policy, persistence, and provider adapters begin as daemon
modules. Split them only when independent dependency or release boundaries
are demonstrated. Add applications and packages with their first working
slice rather than creating empty roadmap trees.

## Consequences

- Atomic changes across daemon, CLI, console, and contracts are possible.
- One release gate can verify Rust and TypeScript graphs.
- UI code cannot become a second controller.
- Internal host modules may grow before a measured split is warranted.
- Sibling integrations require explicit versioned contracts.
