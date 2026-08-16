//! The stored mode word, and what it says about an inode.
//!
//! Unlike the removable-media filesystems, this one STORES a full mode: the
//! owner, the permission bits and the type all come off the medium, and a
//! mount does not get to decide any of them. What is decided here is only the
//! translation into the interface's own type enum, and the device number,
//! which is stored in the address array rather than in a field of its own.

use vfs::FileType;

use crate::uapi::le32;

/// The type field of a mode word, and the values it takes.
pub const S_IFMT: u16 = 0o170_000;
pub const S_IFSOCK: u16 = 0o140_000;
pub const S_IFLNK: u16 = 0o120_000;
pub const S_IFREG: u16 = 0o100_000;
pub const S_IFBLK: u16 = 0o060_000;
pub const S_IFDIR: u16 = 0o040_000;
pub const S_IFCHR: u16 = 0o020_000;
pub const S_IFIFO: u16 = 0o010_000;
/// Everything below the type field: permission, set-id and sticky bits.
pub const PERM_MASK: u16 = 0o7777;

/// The interface's type for a stored mode. # C: O(1)
pub fn file_type(mode: u16) -> FileType {
    match mode & S_IFMT {
        S_IFDIR => FileType::Directory,
        S_IFLNK => FileType::Symlink,
        S_IFCHR => FileType::CharDev,
        S_IFBLK => FileType::BlockDev,
        S_IFIFO => FileType::Fifo,
        S_IFSOCK => FileType::Socket,
        _ => FileType::Regular,
    }
}

/// Whether a mode names something that carries a device number. # C: O(1)
pub fn has_rdev(mode: u16) -> bool {
    matches!(mode & S_IFMT, S_IFCHR | S_IFBLK | S_IFIFO | S_IFSOCK)
}

/// The permission bits alone. # C: O(1)
pub fn perm(mode: u16) -> u16 { mode & PERM_MASK }

/// The device number a special file carries.
///
/// Two encodings share one place. The FIRST address slot holds the narrow
/// sixteen-bit form; when it is zero, the SECOND holds the wide one. Reading
/// only the first returns zero for every device made since the wide form
/// arrived, and reading only the second returns nothing for older ones.
/// # C: O(1)
pub fn rdev(addr_base: usize, block: &[u8]) -> u32 {
    match le32(block, addr_base) {
        Some(0) | None => le32(block, addr_base + 4).unwrap_or(0),
        Some(old) => decode_old(old),
    }
}

/// The narrow encoding: major in the high byte, minor in the low.
///
/// The wide form stored in the second slot is already the encoding the
/// interface reports, so only this one is translated.
/// # C: O(1)
pub fn decode_old(dev: u32) -> u32 {
    vfs::getattr::encode_dev((dev >> 8) & 0xFF, dev & 0xFF)
}

#[cfg(test)]
#[path = "tests/mode.rs"]
mod tests;
