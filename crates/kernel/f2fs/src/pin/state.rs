//! Where the pin mark and the GC-failure counter live in an inode block.
//!
//! The mark is one of the inline-layout bits, so it survives a remount — it
//! has to, because the promise it makes is about block addresses that outlive
//! this mount.
//!
//! The counter shares its four bytes with a directory's stored depth. The two
//! never coexist: only a directory has a depth and only a regular file has a
//! failure count, so the field is read as one or the other by the inode's own
//! type. Reading it without asking the type reports a directory's depth as a
//! pinning risk signal, which is what would unpin a file that was never
//! failing.

use crate::flags::PIN_FILE;
use crate::mode;
use crate::node::Inode;
use crate::uapi::{le16, I_CURRENT_DEPTH, I_INLINE};

/// Whether the inode carries the pin mark. # C: O(1)
pub fn is_pinned(inode: &Inode) -> bool { inode.inline & PIN_FILE != 0 }

/// Whether the stored type is one the counter belongs to. # C: O(1)
pub fn counts_failures(mode_word: u16) -> bool {
    mode::file_type(mode_word) == vfs::FileType::Regular
}

/// GC failures recorded against a regular file, zero for anything else.
/// # C: O(1)
pub fn gc_failures(block: &[u8], mode_word: u16) -> u16 {
    if !counts_failures(mode_word) { return 0; }
    le16(block, I_CURRENT_DEPTH).unwrap_or(0)
}

/// Record a regular file's GC-failure count.
///
/// The whole four bytes are written, not just the low two: the field's other
/// half is a directory's depth and leaving it as it was would carry a value
/// from before the inode was this file into a number nothing else clears.
/// # C: O(1)
pub fn set_gc_failures(block: &mut [u8], mode_word: u16, n: u16) {
    if !counts_failures(mode_word) { return; }
    block[I_CURRENT_DEPTH..I_CURRENT_DEPTH + 4].copy_from_slice(&u32::from(n).to_le_bytes());
}

/// Set or clear the pin mark in an inode block. # C: O(1)
pub fn set_pin(block: &mut [u8], on: bool) {
    if on { block[I_INLINE] |= PIN_FILE; } else { block[I_INLINE] &= !PIN_FILE; }
}

/// Whether an inode block carries the pin mark. # C: O(1)
pub fn block_is_pinned(block: &[u8]) -> bool {
    block.get(I_INLINE).is_some_and(|b| b & PIN_FILE != 0)
}
