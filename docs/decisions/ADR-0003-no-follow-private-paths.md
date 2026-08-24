# ADR-0003: No-follow private paths

- Status: Proposed
- Date: 2026-08-24

## Context

The waiter-link socket and daemon state live under a user-private Gearwit
home. Symlink components on that tree can redirect bind, connect, or state
writes onto a path the process did not intend to admit. Environment-selected
socket or state paths are similarly non-durable: they change with the calling
shell and are a poor fit for sandbox path grants. `create_dir_all` can follow
an intermediate symlink, so checking only the leaf is not enough.

## Decision

Critical Gearwit paths do not follow symlinks and are not chosen by
environment variables:

- Production discovery is `$HOME/.lanyte/gearwit` only. `$HOME` identifies the
  user; it is not a config-file or socket override.
- Tests inject an explicit `PathBuf` (`from_root` / `from_user_home`). They do
  not read `GEARWIT_*` path variables.
- Verify `HOME` and `.lanyte` are owned real directories (no symlink). Create
  `.lanyte`, `gearwit/`, `run/`, and `state/` one component at a time with
  `create_dir`, never `create_dir_all`.
- Inspect every component with `symlink_metadata`. A symlink, wrong type, or
  wrong owner (effective UID) fails closed.
- An existing owned directory with a broader mode is tightened to `0700`. Mode
  repair is not a substitute for type/owner checks.
- An existing socket file is replaced only when it is an owned Unix socket
  with no live listener, and only while holding the exclusive listener lock
  directory. Non-sockets are never unlinked.

## Consequences

- Sandbox grants target one stable subtree.
- Bind cannot steal another user's leftover socket via a redirected path.
- A later CLI override, if any, must be an explicit flag whose resolved path
  is printed and permission-checked.
