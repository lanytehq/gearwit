//! Canonical Gearwit home, private directories, and waiter-link bind.

use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use ipcprims::transport::{TransportError, UnixDomainSocket};
use rsfulmen::logging::{Severity, new_cli};

/// Socket file name under `run/`.
pub const SOCKET_FILE: &str = "gearwit.sock";

/// Failure to resolve, create, or bind the local waiter-link endpoint.
#[derive(Debug)]
pub enum BindError {
    /// `HOME` is unset; production resolution cannot proceed.
    HomeUnset,
    /// Path exists and is a symlink.
    Symlink(PathBuf),
    /// Path exists and is not a directory.
    NotADirectory(PathBuf),
    /// Path exists and is not a Unix socket.
    NotASocket(PathBuf),
    /// A listener is already accepting on this socket.
    LiveListener(PathBuf),
    /// Path is not owned by this process's effective user.
    WrongOwner(PathBuf),
    /// Filesystem I/O failed.
    Io(io::Error),
    /// ipcprims transport failed.
    Transport(TransportError),
}

impl std::fmt::Display for BindError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HomeUnset => formatter.write_str("HOME is unset"),
            Self::Symlink(path) => write!(formatter, "refusing symlink {}", path.display()),
            Self::NotADirectory(path) => {
                write!(formatter, "not a directory: {}", path.display())
            }
            Self::NotASocket(path) => {
                write!(formatter, "not a unix socket: {}", path.display())
            }
            Self::LiveListener(path) => {
                write!(formatter, "listener already live at {}", path.display())
            }
            Self::WrongOwner(path) => {
                write!(formatter, "path not owned by this user: {}", path.display())
            }
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Transport(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for BindError {}

impl From<io::Error> for BindError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<TransportError> for BindError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

/// Production Gearwit home: `$HOME/.lanyte/gearwit`.
///
/// # Errors
///
/// Returns [`BindError::HomeUnset`] when `HOME` is missing.
pub fn canonical_root() -> Result<PathBuf, BindError> {
    let home = std::env::var_os("HOME").ok_or(BindError::HomeUnset)?;
    Ok(PathBuf::from(home).join(".lanyte").join("gearwit"))
}

/// Resolved Gearwit directories. Tests inject `from_root`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GearwitPaths {
    root: PathBuf,
}

impl GearwitPaths {
    /// Create `root`, `run/`, and `state/` as owner-only directories.
    ///
    /// # Errors
    ///
    /// Returns [`BindError`] when a component is a symlink or not a directory.
    pub fn from_root(root: PathBuf) -> Result<Self, BindError> {
        ensure_private_dir(&root)?;
        ensure_private_dir(&root.join("run"))?;
        ensure_private_dir(&root.join("state"))?;
        Ok(Self { root })
    }

    /// Resolve and create the per-user canonical home.
    ///
    /// # Errors
    ///
    /// Same as [`from_root`] plus [`BindError::HomeUnset`].
    pub fn user_default() -> Result<Self, BindError> {
        Self::from_root(canonical_root()?)
    }

    /// Gearwit home root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Waiter-link socket path.
    #[must_use]
    pub fn socket_path(&self) -> PathBuf {
        self.root.join("run").join(SOCKET_FILE)
    }

    /// Private state directory.
    #[must_use]
    pub fn state_dir(&self) -> PathBuf {
        self.root.join("state")
    }

    /// Bind the waiter-link socket with live-listener protection.
    ///
    /// # Errors
    ///
    /// Returns [`BindError`] for live listeners, non-sockets, or transport failure.
    pub fn bind(&self) -> Result<UnixDomainSocket, BindError> {
        bind_private_socket(&self.socket_path())
    }
}

/// Create or reuse a `0o700` directory. Rejects symlinks and non-directories.
///
/// # Errors
///
/// Returns [`BindError`] when the path cannot be a private directory.
pub fn ensure_private_dir(dir: &Path) -> Result<(), BindError> {
    if let Ok(metadata) = fs::symlink_metadata(dir) {
        if metadata.file_type().is_symlink() {
            return Err(BindError::Symlink(dir.to_path_buf()));
        }
        if !metadata.file_type().is_dir() {
            return Err(BindError::NotADirectory(dir.to_path_buf()));
        }
    } else {
        fs::create_dir_all(dir)?;
    }
    let metadata = fs::symlink_metadata(dir)?;
    if metadata.file_type().is_symlink() {
        return Err(BindError::Symlink(dir.to_path_buf()));
    }
    if !metadata.file_type().is_dir() {
        return Err(BindError::NotADirectory(dir.to_path_buf()));
    }
    require_owned(&metadata, dir)?;
    let mut permissions = fs::metadata(dir)?.permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(dir, permissions)?;
    Ok(())
}

/// Bind `path` as an owner-only Unix socket without stealing a live listener.
///
/// Preflight: reject non-sockets; refuse when `connect` succeeds; only then
/// allow ipcprims to replace a stale socket file (`ConnectionRefused`).
///
/// # Errors
///
/// Returns [`BindError::LiveListener`], [`BindError::NotASocket`], or a
/// transport error.
pub fn bind_private_socket(path: &Path) -> Result<UnixDomainSocket, BindError> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return Err(BindError::Symlink(path.to_path_buf()));
        }
        if !metadata.file_type().is_socket() {
            return Err(BindError::NotASocket(path.to_path_buf()));
        }
        require_owned(&metadata, path)?;
        match UnixDomainSocket::connect(path) {
            Ok(_live) => {
                let displayed = path.display().to_string();
                let log = new_cli("gearwitd", Severity::Warn);
                log.warn(
                    "refusing bind; listener is live",
                    &[("path", displayed.as_str())],
                );
                return Err(BindError::LiveListener(path.to_path_buf()));
            }
            Err(TransportError::Connect { source, .. })
                if source.kind() == io::ErrorKind::ConnectionRefused =>
            {
                // Stale socket file. ipcprims bind removes socket files only.
            }
            Err(error) => return Err(BindError::Transport(error)),
        }
    }
    Ok(UnixDomainSocket::bind(path)?)
}

fn require_owned(metadata: &fs::Metadata, path: &Path) -> Result<(), BindError> {
    if metadata.uid() == nix::unistd::Uid::effective().as_raw() {
        Ok(())
    } else {
        Err(BindError::WrongOwner(path.to_path_buf()))
    }
}
