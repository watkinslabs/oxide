//! Reading and writing the overlay's own markers on a layer object.
//!
//! Every marker is an extended attribute on the real object in a real layer,
//! so all of this is a thin, named wrapper over the layer's own attribute
//! operations. It exists as its own module because the failure handling is
//! not thin: a layer that supports no attributes at all has to be distinguished
//! from one that refused a particular write, and the difference decides whether
//! the mount continues without a feature or fails outright.

extern crate alloc;

use alloc::vec::Vec;
use syscall::errno::Errno;
use vfs::xattr::XattrError;
use vfs::{Inode, InodeRef};

use crate::config::Config;
use crate::uapi::{Marker, MARKER_YES};
use crate::xattr::name;

/// Read a marker. `None` covers both "not set" and "this layer stores no
/// attributes", because neither says anything about the object. # C: O(log n)
pub fn get(config: &Config, inode: &Inode, m: Marker) -> Option<Vec<u8>> {
    match inode.getxattr(&name(config, m)) {
        Ok(v) => Some(v),
        Err(_) => None,
    }
}

/// Is a marker present at all, whatever its value? # C: O(log n)
pub fn present(config: &Config, inode: &Inode, m: Marker) -> bool {
    get(config, inode, m).is_some()
}

/// First byte of a marker on a DIRECTORY, which is how the opaque and impure
/// markers are read: `y` means set, `x` means the directory holds regular-file
/// whiteouts, anything else means unset. Zero when absent or not a directory.
/// # C: O(log n)
pub fn dir_val(config: &Config, inode: &Inode, m: Marker) -> u8 {
    if inode.file_type() != vfs::types::FileType::Directory { return 0; }
    match get(config, inode, m) {
        Some(v) if v.len() == 1 => v[0],
        _ => 0,
    }
}

/// Write a marker.
///
/// `xerr` is what a layer with no attribute support reports instead. It is not
/// always an error: an origin marker that cannot be stored merely costs the
/// object its recorded identity, while an opaque marker that cannot be stored
/// would make a deleted lower directory reappear, so the two callers pass
/// different values.
/// # C: O(log n)
pub fn set(config: &Config, inode: &InodeRef, m: Marker, value: &[u8], xerr: Errno)
    -> Result<(), Errno> {
    match inode.setxattr(&name(config, m), value.to_vec(), false, false) {
        Ok(()) => Ok(()),
        Err(XattrError::NotSup) => Err(xerr),
        Err(e) => Err(errno(e)),
    }
}

/// Write a marker whose value is only its presence. # C: O(log n)
pub fn set_yes(config: &Config, inode: &InodeRef, m: Marker, xerr: Errno) -> Result<(), Errno> {
    set(config, inode, m, MARKER_YES, xerr)
}

/// Remove a marker. An absent one is not an error — the caller is asserting
/// the end state, not the transition. # C: O(log n)
pub fn remove(config: &Config, inode: &InodeRef, m: Marker) -> Result<(), Errno> {
    match inode.removexattr(&name(config, m)) {
        Ok(()) | Err(XattrError::NotFound) | Err(XattrError::NotSup) => Ok(()),
        Err(e) => Err(errno(e)),
    }
}

/// The attribute layer's failures as errno. # C: O(1)
pub fn errno(e: XattrError) -> Errno {
    match e {
        XattrError::NotFound => Errno::Enodata,
        XattrError::Exists => Errno::Eexist,
        XattrError::NotSup => Errno::Eopnotsupp,
        XattrError::Fs(_) => Errno::Eio,
    }
}
