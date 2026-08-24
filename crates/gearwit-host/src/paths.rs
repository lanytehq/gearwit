//! Canonical Gearwit home, private directories, and waiter-link bind.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use nix::errno::Errno;
use nix::fcntl::{Flock, FlockArg};

use ipcprims::transport::{IpcStream, TransportError, UnixDomainSocket};
use rsfulmen::logging::{Severity, new_cli};

/// Socket file name under `run/`.
pub const SOCKET_FILE: &str = "gearwit.sock";

const LOCK_FILE: &str = "gearwit.lock";

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

struct PathClaim {
    path: PathBuf,
}

impl Drop for PathClaim {
    fn drop(&mut self) {
        INPROC_CLAIMS
            .get_or_init(|| Mutex::new(HashSet::new()))
            .lock()
            .expect("in-process bind claims")
            .remove(&self.path);
    }
}

fn claim_lock_path(path: &Path) -> Result<PathClaim, BindError> {
    let mut claims = INPROC_CLAIMS
        .get_or_init(|| Mutex::new(HashSet::new()))
        .lock()
        .expect("in-process bind claims");
    if !claims.insert(path.to_path_buf()) {
        return Err(BindError::LiveListener(path.to_path_buf()));
    }
    Ok(PathClaim {
        path: path.to_path_buf(),
    })
}

static INPROC_CLAIMS: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();

/// Bound waiter-link listener. Holds the advisory lock fd until drop.
pub struct BoundListener {
    _lock: Flock<File>,
    _claim: PathClaim,
    listener: UnixDomainSocket,
}

impl BoundListener {
    /// Accept one connection.
    ///
    /// # Errors
    ///
    /// Returns transport errors from ipcprims.
    pub fn accept(&self) -> Result<IpcStream, BindError> {
        Ok(self.listener.accept()?)
    }

    /// Bound socket path.
    #[must_use]
    pub fn path(&self) -> &Path {
        self.listener.path()
    }
}

/// Resolved Gearwit directories. Tests inject `from_root`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GearwitPaths {
    root: PathBuf,
}

impl GearwitPaths {
    /// Create `root`, `run/`, and `state/` as owner-only directories.
    ///
    /// The parent of `root` must already exist as an owned real directory.
    ///
    /// # Errors
    ///
    /// Returns [`BindError`] when a component is a symlink or not a directory.
    pub fn from_root(root: PathBuf) -> Result<Self, BindError> {
        let parent = root
            .parent()
            .ok_or_else(|| BindError::NotADirectory(root.clone()))?;
        inspect_existing_dir(parent)?;
        ensure_private_dir(&root)?;
        ensure_private_dir(&root.join("run"))?;
        ensure_private_dir(&root.join("state"))?;
        Ok(Self { root })
    }

    /// Resolve from an explicit user home (`$HOME` equivalent).
    ///
    /// # Errors
    ///
    /// Fails if `home` or `.lanyte` is a symlink, wrong type, or wrong owner.
    pub fn from_user_home(home: &Path) -> Result<Self, BindError> {
        inspect_existing_dir(home)?;
        let lanyte = home.join(".lanyte");
        ensure_shared_lanyte(&lanyte)?;
        Self::from_root(lanyte.join("gearwit"))
    }

    /// Resolve and create the per-user canonical home.
    ///
    /// # Errors
    ///
    /// Same as [`Self::from_user_home`] plus [`BindError::HomeUnset`].
    pub fn user_default() -> Result<Self, BindError> {
        let home = std::env::var_os("HOME").ok_or(BindError::HomeUnset)?;
        Self::from_user_home(Path::new(&home))
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

    /// Bind the waiter-link socket while holding the exclusive listener lock.
    ///
    /// # Errors
    ///
    /// Returns [`BindError`] for live listeners, non-sockets, or transport failure.
    pub fn bind(&self) -> Result<BoundListener, BindError> {
        let lock_path = self.root.join("run").join(LOCK_FILE);
        let claim = claim_lock_path(&lock_path)?;
        let lock = acquire_listener_lock(&lock_path)?;
        let listener = bind_private_socket(&self.socket_path())?;
        Ok(BoundListener {
            _lock: lock,
            _claim: claim,
            listener,
        })
    }
}

fn inspect_existing_dir(dir: &Path) -> Result<(), BindError> {
    let metadata = fs::symlink_metadata(dir)?;
    if metadata.file_type().is_symlink() {
        return Err(BindError::Symlink(dir.to_path_buf()));
    }
    if !metadata.file_type().is_dir() {
        return Err(BindError::NotADirectory(dir.to_path_buf()));
    }
    require_owned(&metadata, dir)
}

/// Create or reuse a `0o700` directory. Rejects symlinks and non-directories.
///
/// Existing owned directories with a broader mode are tightened to `0o700`.
///
/// # Errors
///
/// Returns [`BindError`] when the path cannot be a private directory.
pub fn ensure_private_dir(dir: &Path) -> Result<(), BindError> {
    match fs::symlink_metadata(dir) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(BindError::Symlink(dir.to_path_buf()));
            }
            if !metadata.file_type().is_dir() {
                return Err(BindError::NotADirectory(dir.to_path_buf()));
            }
            require_owned(&metadata, dir)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(dir)?;
        }
        Err(error) => return Err(BindError::Io(error)),
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

fn ensure_shared_lanyte(dir: &Path) -> Result<(), BindError> {
    match fs::symlink_metadata(dir) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(BindError::Symlink(dir.to_path_buf()));
            }
            if !metadata.file_type().is_dir() {
                return Err(BindError::NotADirectory(dir.to_path_buf()));
            }
            require_owned(&metadata, dir)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir(dir)?;
            let metadata = fs::symlink_metadata(dir)?;
            if metadata.file_type().is_symlink() {
                return Err(BindError::Symlink(dir.to_path_buf()));
            }
            require_owned(&metadata, dir)
        }
        Err(error) => Err(BindError::Io(error)),
    }
}

fn acquire_listener_lock(path: &Path) -> Result<Flock<File>, BindError> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return Err(BindError::Symlink(path.to_path_buf()));
        }
        require_owned(&metadata, path)?;
    }
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| {
            if error.raw_os_error() == Some(nix::libc::ELOOP) {
                BindError::Symlink(path.to_path_buf())
            } else {
                BindError::Io(error)
            }
        })?;
    match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
        Ok(lock) => Ok(lock),
        Err((_, Errno::EAGAIN)) => {
            warn_live(path);
            Err(BindError::LiveListener(path.to_path_buf()))
        }
        Err((_, error)) => Err(BindError::Io(io::Error::other(error))),
    }
}

fn warn_live(path: &Path) {
    let displayed = path.display().to_string();
    let log = new_cli("gearwitd", Severity::Warn);
    log.warn(
        "refusing bind; listener is live",
        &[("path", displayed.as_str())],
    );
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
                warn_live(path);
                return Err(BindError::LiveListener(path.to_path_buf()));
            }
            Err(TransportError::Connect { source, .. })
                if source.kind() == io::ErrorKind::ConnectionRefused => {}
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
