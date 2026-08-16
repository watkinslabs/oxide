//! The attributes carried across a copy-up, and the ones that must not be.
//!
//! Two failure directions, both silent. Copying the overlay's own markers
//! across would make the copy claim to be a copy of something else — an
//! `origin` record naming a third object, or an `opaque` marker hiding a
//! directory that should still merge. Failing to copy an access-control list
//! or a security label would change what the object permits, in whichever
//! direction the destination filesystem's defaults happen to fall.
//!
//! So the split is explicit: the overlay's own markers are dropped, the
//! attributes that carry protection MUST arrive or the copy fails, and
//! anything else is copied when it can be and skipped when the destination
//! layer does not understand it.

extern crate alloc;

use syscall::errno::Errno;
use vfs::xattr::XattrError;
use vfs::setattr::{Iattr, ATTR_ATIME, ATTR_ATIME_SET, ATTR_CTIME, ATTR_FORCE, ATTR_GID,
                   ATTR_MODE, ATTR_MTIME, ATTR_MTIME_SET, ATTR_SIZE, ATTR_UID};
use vfs::{Idmap, InodeRef};

use crate::config::Config;
use crate::marker;
use crate::xattr;

/// Copy every attribute of `from` onto `to` that belongs to the object.
///
/// A destination that supports no attributes at all is not an error — a
/// filesystem may legitimately have none, and refusing the copy-up would make
/// the overlay unusable on it. A destination that refuses ONE attribute is
/// only tolerated when that attribute carries no protection.
/// # C: O(attributes)
pub fn copy_xattrs(config: &Config, from: &InodeRef, to: &InodeRef) -> Result<(), Errno> {
    let names = match from.listxattr() {
        Ok(n) => n,
        Err(XattrError::NotSup) => return Ok(()),
        Err(e) => return Err(marker::errno(e)),
    };
    for name in names {
        if xattr::is_private(config, &name) { continue; }
        let value = match from.getxattr(&name) {
            Ok(v) => v,
            Err(XattrError::NotFound) => continue,
            Err(XattrError::NotSup) => return Ok(()),
            Err(e) => return Err(marker::errno(e)),
        };
        match to.setxattr(&name, value, false, false) {
            Ok(()) => {}
            Err(XattrError::NotSup) if !xattr::must_copy(&name) => {}
            Err(XattrError::NotSup) => return Err(Errno::Eopnotsupp),
            Err(e) => return Err(marker::errno(e)),
        }
    }
    Ok(())
}

/// Copy mode, owner and timestamps from `from` onto `to`.
///
/// The mode is not set on a symbolic link: its permission bits mean nothing,
/// and a filesystem that stores them still refuses to change them.
/// Timestamps go LAST, because every other change here moves them.
/// # C: O(1)
pub fn copy_attrs(from: &InodeRef, to: &InodeRef) -> Result<(), Errno> {
    let idmap = Idmap::identity();
    let st = from.getattr(&idmap);
    let mut valid = ATTR_UID | ATTR_GID | ATTR_ATIME | ATTR_ATIME_SET | ATTR_MTIME
                    | ATTR_MTIME_SET | ATTR_CTIME | ATTR_FORCE;
    if from.file_type() != vfs::types::FileType::Symlink { valid |= ATTR_MODE; }
    let ia = Iattr {
        valid,
        mode: (st.mode & MODE_BITS) as u16,
        uid: st.uid, gid: st.gid, size: 0,
        atime: st.atime, mtime: st.mtime, ctime: st.ctime,
    };
    to.setattr(&idmap, &ia).map_err(crate::err::to_errno)
}

/// Permission, set-id and sticky bits — everything of the mode word except the
/// object's type, which was fixed when the copy was created.
pub const MODE_BITS: u32 = 0o7777;

/// Copy the size, so a copy that stopped short is visible as a short file
/// rather than silently padded. # C: O(1)
pub fn copy_size(from: &InodeRef, to: &InodeRef) -> Result<(), Errno> {
    let idmap = Idmap::identity();
    let ia = Iattr { valid: ATTR_SIZE | ATTR_FORCE, mode: 0, uid: 0, gid: 0,
                     size: from.size(), atime: Default::default(), mtime: Default::default(),
                     ctime: Default::default() };
    to.setattr(&idmap, &ia).map_err(crate::err::to_errno)
}

/// The inode flags a copy-up carries: the ones that describe how the object is
/// written, not the ones that forbid writing it.
///
/// Immutable and append-only are deliberately NOT carried onto the object
/// itself. Setting either on the copy while it is still being built would stop
/// the copy-up finishing — the object could not be linked into place, and no
/// further attribute could be set on it. They are recorded in a marker
/// instead, and applied to the overlay object rather than to the layer's.
/// # C: O(1)
pub const CARRIED_FLAGS: u32 = vfs::inode::FS_SYNC_FL | vfs::inode::FS_NOATIME_FL;

/// The flags that are diverted into a marker instead.
pub const DIVERTED_FLAGS: u32 =
    vfs::inode::FS_APPEND_FL | vfs::inode::FS_IMMUTABLE_FL;

/// Encode the diverted flags as the marker's value. The spelling is a
/// character per flag so that a layer inspected by hand says what it means.
/// # C: O(1)
pub fn protattr_value(flags: u32) -> alloc::vec::Vec<u8> {
    let mut v = alloc::vec::Vec::new();
    if flags & vfs::inode::FS_APPEND_FL != 0 { v.push(b'a'); }
    if flags & vfs::inode::FS_IMMUTABLE_FL != 0 { v.push(b'i'); }
    v
}

/// Read a marker's value back into flags. An unknown character is ignored
/// rather than refused: a newer kernel may have recorded a flag this one does
/// not have, and the object is still perfectly usable without it. # C: O(len)
pub fn protattr_flags(value: &[u8]) -> u32 {
    let mut f = 0;
    for c in value {
        match c {
            b'a' => f |= vfs::inode::FS_APPEND_FL,
            b'i' => f |= vfs::inode::FS_IMMUTABLE_FL,
            _ => {}
        }
    }
    f
}
