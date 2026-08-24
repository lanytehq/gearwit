//! Owner-only state directory and Unix socket.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

/// Socket file name inside the state directory.
pub const SOCKET_NAME: &str = "waiter-link.sock";

/// Create or reuse a `0o700` state directory.
///
/// # Errors
///
/// Returns I/O errors from create or chmod.
pub fn ensure_state_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    let mut permissions = fs::metadata(dir)?.permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(dir, permissions)?;
    Ok(())
}

/// Bind `waiter-link.sock` with owner-only mode.
///
/// # Errors
///
/// Returns I/O errors from bind or chmod.
pub fn bind_private_socket(dir: &Path) -> io::Result<UnixListener> {
    ensure_state_dir(dir)?;
    let path = socket_path(dir);
    let _ = fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;
    let mut permissions = fs::metadata(&path)?.permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(&path, permissions)?;
    Ok(listener)
}

/// Socket path for a state directory.
#[must_use]
pub fn socket_path(dir: &Path) -> PathBuf {
    dir.join(SOCKET_NAME)
}
