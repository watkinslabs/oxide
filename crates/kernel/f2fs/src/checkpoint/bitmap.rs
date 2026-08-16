//! Where the NAT and SIT version bitmaps live inside a checkpoint.
//!
//! Three layouts, chosen by one flag and one length, and none of them fails
//! loudly when read as another:
//!
//! - **Large-NAT-bitmap set.** A four-byte guard word sits ahead of both
//!   bitmaps so the checksum can cover them; NAT starts after that word, SIT
//!   after NAT. Ignoring the guard word shifts every bit by four bytes.
//! - **Flag clear, payload blocks present.** NAT starts at the bitmap area and
//!   runs on into the payload blocks; SIT starts at the second block.
//! - **Flag clear, no payload.** SIT comes FIRST and NAT follows it — the
//!   opposite order to the first case.
//!
//! A bit read from the wrong bitmap selects the other copy of a NAT or SIT
//! block, which reads cleanly and returns stale addresses.

use crate::flags::CP_LARGE_NAT_BITMAP_FLAG;
use crate::uapi::{BLKSIZE, CP_SIT_NAT_VERSION_BITMAP};

use super::Checkpoint;

/// Bytes of guard the large-bitmap layout puts ahead of the two bitmaps.
const GUARD: usize = 4;

/// The NAT version bitmap, out of the joined checkpoint buffer.
///
/// `payload` is the checkpoint payload block count the superblock states.
/// # C: O(1)
pub fn nat_bitmap<'a>(cp: &Checkpoint, joined: &'a [u8], payload: u32) -> Option<&'a [u8]> {
    let len = cp.nat_ver_bitmap_bytesize as usize;
    let at = nat_offset(cp, payload);
    joined.get(at..at.checked_add(len)?)
}

/// The SIT version bitmap, out of the same buffer. # C: O(1)
pub fn sit_bitmap<'a>(cp: &Checkpoint, joined: &'a [u8], payload: u32) -> Option<&'a [u8]> {
    let len = cp.sit_ver_bitmap_bytesize as usize;
    let at = sit_offset(cp, payload);
    joined.get(at..at.checked_add(len)?)
}

/// Byte offset of the NAT bitmap. # C: O(1)
pub fn nat_offset(cp: &Checkpoint, payload: u32) -> usize {
    let base = CP_SIT_NAT_VERSION_BITMAP;
    if cp.has(CP_LARGE_NAT_BITMAP_FLAG) { return base + GUARD; }
    if payload > 0 { return base; }
    base + cp.sit_ver_bitmap_bytesize as usize
}

/// Byte offset of the SIT bitmap. # C: O(1)
pub fn sit_offset(cp: &Checkpoint, payload: u32) -> usize {
    let base = CP_SIT_NAT_VERSION_BITMAP;
    if cp.has(CP_LARGE_NAT_BITMAP_FLAG) {
        return base + GUARD + cp.nat_ver_bitmap_bytesize as usize;
    }
    if payload > 0 { return BLKSIZE; }
    base
}

/// Whether bit `n` of `map` is set, counting from the low bit of byte zero.
///
/// A bit past the end reads as clear rather than as an error: a bitmap
/// narrower than the table it indexes means the tail was never versioned, and
/// the first copy is where those entries are.
/// # C: O(1)
pub fn test_bit(map: &[u8], n: usize) -> bool {
    match map.get(n / 8) { Some(b) => b & (1 << (n % 8)) != 0, None => false }
}

#[cfg(test)]
#[path = "../tests/cp_bitmap.rs"]
mod tests;
