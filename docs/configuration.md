# Gearwit configuration

Gearwit v0 uses a single per-user home. Production resolution is deterministic
from the user home. There is no environment-selected socket path.

## Canonical layout

```text
$HOME/.lanyte/gearwit/           # 0700  Gearwit home
  run/gearwit.sock               # 0600  waiter-link Unix socket
  state/                         # 0700  daemon receipts / projection
```

`config.toml` is reserved for a later explicit configuration file and is not
read in this slice.

Parent `$HOME/.lanyte` may be `0755`. Privacy is the `gearwit/` tree, not the
parent. Do not rely on parent-directory mode.

## Resolution

| Caller | Root |
| --- | --- |
| Daemon / CLI (production) | `$HOME/.lanyte/gearwit` |
| Tests | explicit `PathBuf` passed to `GearwitPaths::from_root` |

`$HOME` identifies the user. It is not a socket or config-file override.
Environment variables are not a discovery mechanism. An override, if added
later, must be an explicit CLI flag whose resolved path is printed and
permission-checked.

Founder v0 admits **one live waiter link** at the daemon boundary. Admission
is still checked against `(arm_id, generation)`. The same `request_id` for
that active pair returns the cached accept.

## Permissions and bind policy

- Create `gearwit/`, `run/`, and `state/` as `0700`.
- Socket mode is `0600` where the platform supports it.
- Refuse a component that is a symlink or not a directory. See
  [ADR-0003](decisions/ADR-0003-no-follow-private-paths.md).
- Require each private path to be owned by the process effective user.
- Bind fails closed if the socket path exists and is not a Unix socket.
- Bind refuses when a listener is already live (connect probe succeeds).
- A leftover **owned** socket file with no listener (`ConnectionRefused`) may
  be replaced. Arbitrary files are never unlinked.

## Sandbox grants

Coding-agent sandboxes often cannot see `$HOME` unless granted. One grant
covers CLI, daemon, and console:

```text
~/.lanyte/gearwit
```

Codex example: `codex --add-dir ~/.lanyte/gearwit`.

If the process cannot create or connect to that tree, fail honestly. Do not
fall back to the project working tree or `/tmp`.

## Socket path length

Unix domain socket paths are bounded (104 bytes on macOS, 108 on Linux). The
canonical home stays well under that limit. A bind error for path length is
fatal; do not silently shorten the path.

## Transport

The waiter-link socket uses ipcprims framing (`COMMAND` channel, 256 KiB
payload cap). Typed waiter-link JSON is validated before send and after
receive. The daemon does not use the ipcprims Peer 16 MiB default.
