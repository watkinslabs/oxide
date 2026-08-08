extern crate alloc;

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::file::File;
use crate::types::VfsError;

pub type KResult<T> = core::result::Result<T, VfsError>;

/// Linux `AT_FDCWD`, used by internal pathname parameters without an explicit
/// directory file descriptor.  User-originated `FSCONFIG_SET_PATH*` carries
/// its supplied dirfd through [`FsParameter::path_at`].
pub const AT_FDCWD: i32 = -100;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FsContextPurpose { Mount, Submount, Reconfigure }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FsContextPhase {
    CreateParams,
    Creating,
    AwaitingMount,
    AwaitingReconf,
    ReconfParams,
    Reconfiguring,
    Failed,
}

/// `fsconfig(2)` parameter payload variants. `File` carries BOTH the pinned
/// file reference (taken at parse time from the caller's fd) and the fd
/// number the caller passed, because different filesystem parsers consume
/// one or the other. Carrying only the number would force a second fd-table
/// lookup after the caller could have closed the fd, so both travel together.
#[derive(Clone)]
pub enum FsValue {
    Flag,
    String(String),
    File { fd: i32, file: Arc<File> },
    Filename { path: String, dirfd: i32, empty: bool },
    Blob(Vec<u8>),
}

impl core::fmt::Debug for FsValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FsValue::Flag => f.write_str("Flag"),
            FsValue::String(s) => f.debug_tuple("String").field(s).finish(),
            FsValue::File { fd, .. } => f.debug_struct("File").field("fd", fd).finish(),
            FsValue::Filename { path, dirfd, empty } => f.debug_struct("Filename").field("path", path).field("dirfd", dirfd).field("empty", empty).finish(),
            FsValue::Blob(b) => f.debug_tuple("Blob").field(b).finish(),
        }
    }
}

impl PartialEq for FsValue {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (FsValue::Flag, FsValue::Flag) => true,
            (FsValue::String(a), FsValue::String(b)) => a == b,
            (FsValue::File { fd: a, file: fa }, FsValue::File { fd: b, file: fb }) => a == b && Arc::ptr_eq(fa, fb),
            (FsValue::Filename { path: pa, dirfd: da, empty: ea }, FsValue::Filename { path: pb, dirfd: db, empty: eb }) => pa == pb && da == db && ea == eb,
            (FsValue::Blob(a), FsValue::Blob(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for FsValue {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FsParameter {
    pub key:   String,
    pub value: FsValue,
}

impl FsParameter {
    /// # C: O(len key)
    pub fn flag(key: &str) -> Self { Self { key: key.to_string(), value: FsValue::Flag } }
    /// # C: O(len key+value)
    pub fn string(key: &str, value: &str) -> Self { Self { key: key.to_string(), value: FsValue::String(value.to_string()) } }
    /// `FSCONFIG_SET_FD`: `fd` is the caller's passed descriptor, `file`
    /// the reference pinned for the duration of the parse.
    /// # C: O(len key)
    pub fn fd(key: &str, fd: i32, file: Arc<File>) -> Self { Self { key: key.to_string(), value: FsValue::File { fd, file } } }
    /// # C: O(len key+path)
    pub fn path_at(key: &str, path: &str, dirfd: i32, empty: bool) -> Self {
        Self { key: key.to_string(), value: FsValue::Filename { path: path.to_string(), dirfd, empty } }
    }
    /// # C: O(len key+path)
    pub fn path(key: &str, path: &str) -> Self { Self::path_at(key, path, AT_FDCWD, false) }
    /// # C: O(len key+path)
    pub fn path_empty(key: &str, path: &str) -> Self { Self::path_at(key, path, AT_FDCWD, true) }
    /// # C: O(len key+blob)
    pub fn blob(key: &str, blob: &[u8]) -> Self { Self { key: key.to_string(), value: FsValue::Blob(blob.to_vec()) } }
    /// # C: O(1)
    pub fn as_str(&self) -> Option<&str> { match &self.value { FsValue::String(s) => Some(s), _ => None } }
    /// `param->dirfd` for an `fs_value_is_file` parameter (`fs_param_is_fd`).
    /// # C: O(1)
    pub fn as_fd(&self) -> Option<i32> { match &self.value { FsValue::File { fd, .. } => Some(*fd), _ => None } }
    /// `param->file` — the pinned open file the fd named.
    /// # C: O(1)
    pub fn as_file(&self) -> Option<&Arc<File>> { match &self.value { FsValue::File { file, .. } => Some(file), _ => None } }
    /// # C: O(1)
    pub fn as_path(&self) -> Option<(&str, i32, bool)> {
        match &self.value { FsValue::Filename { path, dirfd, empty } => Some((path, *dirfd, *empty)), _ => None }
    }
    /// # C: O(1)
    pub fn as_blob(&self) -> Option<&[u8]> { match &self.value { FsValue::Blob(b) => Some(b), _ => None } }
}
