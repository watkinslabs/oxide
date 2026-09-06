//! Per-user Windows launch paths.
//!
//! Path selection is deliberately separate from registry initialization.  The
//! registry owner creates or opens its database under its lifetime lock; this
//! module only selects and validates the paths that an existing launch record
//! will use.

use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};

const OXIDE_DIR: &str = "oxide";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserPathInput {
    pub prefix: Option<PathBuf>,
    pub database: Option<PathBuf>,
    pub socket: Option<PathBuf>,
    pub home: PathBuf,
    pub xdg_data_home: Option<PathBuf>,
    pub xdg_state_home: Option<PathBuf>,
    pub xdg_runtime_dir: Option<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserRuntimePaths {
    pub prefix: PathBuf,
    pub database: PathBuf,
    pub socket: PathBuf,
}

#[derive(Debug)]
pub enum UserPathError {
    MissingHome,
    MissingRuntimeDir,
    RelativePath(&'static str),
    EmptyPath(&'static str),
    NulPath(&'static str),
    Io { path: PathBuf, error: io::Error },
    RuntimeNotDirectory(PathBuf),
    RuntimeSymlink(PathBuf),
    RuntimeOwner { path: PathBuf, expected: u32, actual: u32 },
    RuntimePermissions { path: PathBuf, mode: u32 },
    PrivilegeMismatch { real: u32, effective: u32 },
}

impl UserRuntimePaths {
    /// Select one launch's paths without reading or writing persistent state.
    /// Relative XDG values are ignored as required by the runtime contract.
    pub fn select(input: &UserPathInput) -> Result<Self, UserPathError> {
        let prefix = match input.prefix.clone() {
            Some(path) => selected(path, "prefix")?,
            None => {
                absolute_xdg(input.xdg_data_home.as_deref(), &input.home, ".local/share", "XDG_DATA_HOME")?
                    .join(OXIDE_DIR).join("windows-prefix")
            }
        };
        let database = match input.database.clone() {
            Some(path) => selected(path, "database")?,
            None => {
                absolute_xdg(input.xdg_state_home.as_deref(), &input.home, ".local/state", "XDG_STATE_HOME")?
                    .join(OXIDE_DIR).join("registry.db")
            }
        };
        let socket = match input.socket.clone() {
            Some(path) => selected(path, "socket")?,
            None => {
                let runtime = input.xdg_runtime_dir.as_deref().ok_or(UserPathError::MissingRuntimeDir)?;
                absolute(runtime.to_path_buf(), "XDG_RUNTIME_DIR")?.join(OXIDE_DIR).join("registry.sock")
            }
        };
        Ok(Self { prefix, database, socket })
    }
}

fn absolute_home(path: &Path) -> Result<PathBuf, UserPathError> {
    if path.as_os_str().is_empty() { return Err(UserPathError::MissingHome); }
    absolute(path.to_path_buf(), "HOME")
}

fn absolute_xdg(value: Option<&Path>, home: &Path, fallback: &str, field: &'static str) -> Result<PathBuf, UserPathError> {
    match value.filter(|path| path.is_absolute()) {
        Some(path) => absolute(path.to_path_buf(), field),
        None => Ok(absolute_home(home)?.join(fallback)),
    }
}

fn selected(path: PathBuf, field: &'static str) -> Result<PathBuf, UserPathError> {
    absolute(path, field)
}

fn absolute(path: PathBuf, field: &'static str) -> Result<PathBuf, UserPathError> {
    if path.as_os_str().is_empty() { return Err(UserPathError::EmptyPath(field)); }
    if path.as_os_str().as_bytes().contains(&0) { return Err(UserPathError::NulPath(field)); }
    if !path.is_absolute() { return Err(UserPathError::RelativePath(field)); }
    Ok(path)
}

/// Validate the already-existing XDG runtime directory.  This never changes
/// permissions and rejects symlinks, foreign ownership, and non-private modes.
pub fn validate_runtime_dir(path: &Path) -> Result<(), UserPathError> {
    validate_private_existing(path, true)
}

/// Create one private directory, or validate it if it already exists.
/// Existing directories are never chmod'ed; only a directory created by this
/// call receives mode 0700.
pub fn ensure_private_dir(path: &Path) -> Result<(), UserPathError> {
    absolute(path.to_path_buf(), "private directory")?;
    let (real, _) = current_identity()?;
    match fs::symlink_metadata(path) {
        Ok(_) => validate_private_existing(path, false),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            match builder.create(path) {
                Ok(()) => {
                    let metadata = fs::symlink_metadata(path).map_err(|error| UserPathError::Io { path: path.to_path_buf(), error })?;
                    if !metadata.file_type().is_dir() { return Err(UserPathError::RuntimeNotDirectory(path.to_path_buf())); }
                    if metadata.uid() != real { return Err(UserPathError::RuntimeOwner { path: path.to_path_buf(), expected: real, actual: metadata.uid() }); }
                    if metadata.mode() & 0o7777 != 0o700 { return Err(UserPathError::RuntimePermissions { path: path.to_path_buf(), mode: metadata.mode() & 0o7777 }); }
                    Ok(())
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => validate_private_existing(path, false),
                Err(error) => Err(UserPathError::Io { path: path.to_path_buf(), error }),
            }
        }
        Err(error) => Err(UserPathError::Io { path: path.to_path_buf(), error }),
    }
}

fn validate_private_existing(path: &Path, runtime: bool) -> Result<(), UserPathError> {
    absolute(path.to_path_buf(), if runtime { "XDG_RUNTIME_DIR" } else { "private directory" })?;
    let metadata = fs::symlink_metadata(path).map_err(|error| UserPathError::Io { path: path.to_path_buf(), error })?;
    if metadata.file_type().is_symlink() { return Err(UserPathError::RuntimeSymlink(path.to_path_buf())); }
    if !metadata.file_type().is_dir() { return Err(UserPathError::RuntimeNotDirectory(path.to_path_buf())); }
    let (expected, _) = current_identity()?;
    if metadata.uid() != expected { return Err(UserPathError::RuntimeOwner { path: path.to_path_buf(), expected, actual: metadata.uid() }); }
    let mode = metadata.mode() & 0o7777;
    if mode != 0o700 { return Err(UserPathError::RuntimePermissions { path: path.to_path_buf(), mode }); }
    Ok(())
}

fn current_identity() -> Result<(u32, u32), UserPathError> {
    let real = unsafe { libc::getuid() };
    let effective = unsafe { libc::geteuid() };
    if real != effective { return Err(UserPathError::PrivilegeMismatch { real, effective }); }
    Ok((real, effective))
}

impl UserPathInput {
    /// Read one launch's path selection from the process environment.
    /// `HOME` is consulted only where a default is actually needed.
    pub fn from_environment() -> Self {
        let path = |name: &str| std::env::var_os(name).map(PathBuf::from);
        Self {
            prefix: path("OXIDE_WINDOWS_PREFIX"),
            database: path("OXIDE_WINDOWS_REGISTRY_DATABASE"),
            socket: path("OXIDE_WINDOWS_REGISTRY_SOCKET"),
            home: path("HOME").unwrap_or_default(),
            xdg_data_home: path("XDG_DATA_HOME"),
            xdg_state_home: path("XDG_STATE_HOME"),
            xdg_runtime_dir: path("XDG_RUNTIME_DIR"),
        }
    }
}

impl UserRuntimePaths {
    /// Select this user's paths and create the private directories that hold
    /// them. The runtime directory itself is validated, never created: it is
    /// the session manager's to own, and creating it would mask a session
    /// that never set one up.
    pub fn prepare(input: &UserPathInput) -> Result<Self, UserPathError> {
        let paths = Self::select(input)?;
        if let Some(runtime) = input.xdg_runtime_dir.as_deref().filter(|path| path.is_absolute()) {
            validate_runtime_dir(runtime)?;
        }
        for path in [&paths.prefix, &paths.database, &paths.socket] {
            if let Some(parent) = path.parent() { ensure_private_dir(parent)?; }
        }
        Ok(paths)
    }
}
