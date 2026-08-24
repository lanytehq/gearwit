//! `self check` — last in-process wait receipt.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

const LAST_RECEIPT_FILE: &str = "last-wait.txt";

/// Directory for local last-wait state. Override with `GEARWIT_STATE_DIR`.
#[must_use]
pub fn state_dir() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("GEARWIT_STATE_DIR")
        && !explicit.is_empty()
    {
        return Some(PathBuf::from(explicit));
    }
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state/gearwit"))
}

/// Persist a paste-safe receipt for `self check`.
///
/// # Errors
///
/// Returns I/O errors from creating the state directory or writing the file.
pub fn store_last_receipt(text: &str) -> io::Result<()> {
    let Some(dir) = state_dir() else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no GEARWIT_STATE_DIR or HOME",
        ));
    };
    store_last_receipt_in(&dir, text)
}

fn store_last_receipt_in(dir: &std::path::Path, text: &str) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        let mut permissions = fs::metadata(dir)?.permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(dir, permissions)?;
    }
    let path = dir.join(LAST_RECEIPT_FILE);
    let mut options = OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path)?;
    file.write_all(text.as_bytes())?;
    Ok(())
}

/// Render the last stored receipt, or unknown.
#[must_use]
pub fn render_check() -> String {
    render_check_from(state_dir().as_deref())
}

fn render_check_from(dir: Option<&std::path::Path>) -> String {
    let Some(dir) = dir else {
        return "gearwit self check\nlast_receipt: unknown\n".to_owned();
    };
    let path = dir.join(LAST_RECEIPT_FILE);
    match fs::read_to_string(path) {
        Ok(text) if !text.is_empty() => format!("gearwit self check\n{text}"),
        _ => "gearwit self check\nlast_receipt: unknown\n".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::{render_check_from, store_last_receipt_in};

    #[test]
    fn check_unknown_without_receipt() {
        let dir = std::env::temp_dir().join(format!("gearwit-check-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let text = render_check_from(Some(&dir));
        assert!(text.contains("last_receipt: unknown"));
    }

    #[test]
    fn check_prints_stored_receipt() {
        let dir = std::env::temp_dir().join(format!("gearwit-check-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        store_last_receipt_in(&dir, "turn_started: unknown\n").expect("store");
        let text = render_check_from(Some(&dir));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(text.contains("gearwit self check"));
        assert!(text.contains("turn_started: unknown"));
    }
}
