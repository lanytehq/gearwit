# ADR-0003: No-follow private paths

- Status: Proposed
- Date: 2026-08-24

## Context

The waiter-link socket and daemon state live under a user-private Gearwit
home. Symlink components on that tree can redirect bind, connect, or state
writes onto a path the process did not intend to admit. Environment-selected
socket or state paths are similarly non-durable: they change with the calling
shell and are a poor fit for sandbox path grants.

## Decision

Critical Gearwit paths do not follow symlinks and are not chosen by
environment variables:

- Production discovery is `$HOME/.lanyte/gearwit` only. `$HOME` identifies the
  user; it is not a config-file or socket override.
- Tests inject an explicit `PathBuf`. They do not read `GEARWIT_*` path
  variables.
- Every component of `gearwit/`, `run/`, `state/`, and the socket path is
  inspected with `symlink_metadata`. A symlink, wrong type, wrong owner
  (effective UID), or insufficient mode fails closed.
- An existing socket file is replaced only when it is an owned Unix socket
  with no live listener. Non-sockets are never unlinked.

## Consequences

- Sandbox grants target one stable subtree.
- Bind cannot steal another user's leftover socket via a redirected path.
- A later CLI override, if any, must be an explicit flag whose resolved path
  is printed and permission-checked.
