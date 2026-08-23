# Applications

Applications are projections over the Gearwit daemon protocol. They do not
own a second registry, router, policy engine, or persistence writer.

`apps/console/` is added with its first working slice. Its Tauri host attaches
to or starts the same daemon used by headless and CLI operation. Closing a
window must not destroy registered waits.

Cargo owns any Tauri Rust host. Bun owns the web client. The repository root
Makefile remains the advertised integrated entry point.
