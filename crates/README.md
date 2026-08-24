# Rust crates

Add a crate with its first real slice. Do not create empty packages to reserve
names.

The intended dependency direction is:

```text
gearwit-cli ──────▶ gearwit-protocol ◀──── gearwit-host
console / MCP ────▶ gearwit-protocol       ├──▶ gearwit-domain
                                           └──▶ gearwit-platform
```

Initial boundaries:

- `gearwit-domain`: platform-free facts, evidence, and state transitions.
- `gearwit-protocol`: schema-backed daemon/client types. First slice: waiter-link
  typed JSON payloads pinned to Crucible `d121642`. ipcprims owns length-prefixed
  framing on the local socket.
- `gearwit-platform`: host paths, process census, and OS capability traits.
- `gearwit-host`: daemon plus internal registry, router, policy, adapter, and
  persistence modules. First slice: canonical `~/.lanyte/gearwit` home,
  ipcprims waiter-link socket, and one-link admission.
- `gearwit-cli`: thin client and explicit in-process degraded wait path.
  First slice: `gearwit self who`, in-process `gearwit self wait-on`, and
  `gearwit self check`.

Split host modules into crates only when their dependencies or release
boundaries diverge.
