# AI Agent Guide — gearwit

This repository is the public-bound pseudo-monorepo for gearwit. Treat every
tracked file and every durable git surface as world-readable.

Read `REPOSITORY_SAFETY_PROTOCOLS.md` before making changes.

## Product boundary

gearwit is local-first kit for coding-agent seats that already exist.

- A seat can identify itself, register, arm a wait, and declare a blocker.
- A squad or operator can inspect an attention timeline and honestly labeled
  observations.
- The native harness retains inference, tools, approvals, context management,
  and its normal user experience.
- Unknown state remains unknown. Presence is not controller authority.

gearwit is not an agent harness, a remote-session continuation product, a
squad launcher, or the Lanyte autonomy supervisor.

## Architecture rules

- **Schemas before code.** Public file and wire contracts land in the
  designated Crucible schema source before Rust or TypeScript bindings.
- **One daemon, many faces.** CLI, console, MCP, and sibling products consume
  one host state machine and protocol. No face creates a parallel controller.
- **Evidence belongs to each fact.** Never promote an entire seat row to a
  stronger evidence class because one field is controller-proven.
- **Unknown is first-class.** Process presence, a terminal title, or a native
  identifier does not prove model state or control authority.
- **Authority is explicit.** Native control requires a host-minted attachment,
  current generation, and unexpired lease.
- **Claims precede dispatch.** Authority-bearing routes durably claim before
  sending. Ambiguous post-send outcomes suppress automatic replay.
- **Persistence is a port.** Do not couple domain, protocol, or policy code to
  a storage engine or cloud service.
- **No embedded skill runtime.** Wasmtime and agent power-ups belong outside
  the controller-bearing daemon.
- **Runtime state stays outside git.** Registries, receipts, sockets, leases,
  and native identifiers never use a project working tree as storage.

## Workspace discipline

Cargo owns Rust. Bun owns TypeScript when the console exists. The root
`Makefile` is the stable human and CI entry point.

Start with the smallest real crate set. Registry, router, policy, and adapters
begin as host modules and split into crates only when independent dependency or
release boundaries are demonstrated. Do not create empty application or
package trees to advertise a roadmap.

Do not add Nx, Turborepo, Bazel, Pants, git submodules, or another workspace
manager without an accepted architecture decision.

## Decisions

Decision records live under `docs/decisions/` and use the canonical `*DR`
families:

- `ADR-####-...`
- `DDR-####-...`
- `SecDR-####-...`
- `PDR-####-...`
- `EPR-####-...`

New records start Proposed. Accepted decisions are superseded, not silently
rewritten.

Record filenames use `<TYPE>-<NNNN>-<kebab-slug>.md`. Numbers are four-digit,
monotonic, never reused, and repo-global per type. Storage folders do not start
independent sequences.

## Quality gate

```bash
make check
```

The release-oriented gate is:

```bash
make gate
```

## Durable public surfaces

Commit subjects and bodies, PR titles and bodies, branch names, docs, schemas,
and fixtures must not contain private task identifiers, coordination details,
local filesystem paths, credentials, or session narrative.

Agent-generated commits use:

```text
Co-Authored-By: <Model Name> <noreply@lanytehq.dev>
Role: <bare-role-slug>
Committer-of-Record: @3leapsdave
```

PR bodies use:

```text
---
Drafted-By: <Model Name> (<Agentic Tool>)
Role: <bare-role-slug>
PR-of-Record: @3leapsdave
```
