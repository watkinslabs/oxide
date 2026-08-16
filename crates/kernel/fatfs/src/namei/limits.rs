//! The ceilings a directory is bounded by.
//!
//! A FAT directory is a chain with no size field of its own, so nothing on the
//! medium stops one growing until the volume is full. The bound is the
//! reference's own: past it, a corrupt chain that loops would be followed
//! forever by every scan of the directory.

use crate::dirent::ENTRY_BYTES;

/// Most entries one directory may hold.
pub const FAT_MAX_DIR_ENTRIES: u64 = 65_536;

/// The same bound in bytes, which is what a scan compares its position with.
pub const FAT_MAX_DIR_SIZE: u64 = FAT_MAX_DIR_ENTRIES * ENTRY_BYTES as u64;
