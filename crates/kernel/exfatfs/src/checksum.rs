//! The three checksums exFAT carries, which are one rotate-and-add over
//! different widths and different skipped bytes.
//!
//! A checksum that is subtly wrong produces plausible-looking data: a
//! directory entry set reads back with the right name and the right size and
//! is silently rejected — or worse, accepted — by the next reader. The skipped
//! bytes are the whole difference between the three, so they are named rather
//! than open-coded at each call.

use crate::uapi::{BOOT_CHECKSUM_SKIP, CHECKSUM_SKIP};

/// A 16-bit rotate-right-and-add over `data`, continuing from `seed`.
///
/// `skip` names byte offsets, RELATIVE TO THE START OF THIS CALL, that do not
/// contribute. A directory entry set skips the two bytes of the file entry
/// that hold the answer; nothing else does.
/// # C: O(data.len())
pub fn sum16_skipping(data: &[u8], seed: u16, skip: &[usize]) -> u16 {
    let mut sum = seed;
    for (i, byte) in data.iter().enumerate() {
        if skip.contains(&i) { continue; }
        sum = ((sum << 15) | (sum >> 1)).wrapping_add(u16::from(*byte));
    }
    sum
}

/// The plain 16-bit form, with nothing skipped. # C: O(data.len())
pub fn sum16(data: &[u8], seed: u16) -> u16 { sum16_skipping(data, seed, &[]) }

/// A 32-bit rotate-right-and-add over `data`, continuing from `seed`.
/// # C: O(data.len())
pub fn sum32_skipping(data: &[u8], seed: u32, skip: &[usize]) -> u32 {
    let mut sum = seed;
    for (i, byte) in data.iter().enumerate() {
        if skip.contains(&i) { continue; }
        sum = ((sum << 31) | (sum >> 1)).wrapping_add(u32::from(*byte));
    }
    sum
}

/// The plain 32-bit form. # C: O(data.len())
pub fn sum32(data: &[u8], seed: u32) -> u32 { sum32_skipping(data, seed, &[]) }

/// The checksum of a whole directory entry set.
///
/// `entries` is the set's bytes, file entry first. The two bytes that hold the
/// answer are skipped, and only in the FIRST entry — the same offsets in a
/// later entry are ordinary name characters and do contribute.
/// # C: O(entries.len())
pub fn entry_set(entries: &[u8]) -> u16 {
    let mut sum = 0u16;
    for (index, entry) in entries.chunks(crate::uapi::DENTRY_BYTES).enumerate() {
        sum = if index == 0 { sum16_skipping(entry, sum, &CHECKSUM_SKIP) } else { sum16(entry, sum) };
    }
    sum
}

/// The checksum of a name, for the hash a stream entry carries.
///
/// The name is up-cased first — that is what makes the hash match between a
/// lookup and the entry it must find, whatever case either was spelled in —
/// and hashed as little-endian UTF-16 units.
/// # C: O(name.len())
pub fn name_hash(upcased: &[u16]) -> u16 {
    let mut sum = 0u16;
    for unit in upcased {
        sum = sum16(&unit.to_le_bytes(), sum);
    }
    sum
}

/// Fold one boot-region sector into the region's running checksum.
///
/// The first sector of the region skips the three bytes a mount changes
/// without recomputing anything: the two volume-flag bytes and the in-use
/// percentage. Every later sector contributes whole.
/// # C: O(sector.len())
pub fn boot_region(sector: &[u8], seed: u32, first: bool) -> u32 {
    if first { sum32_skipping(sector, seed, &BOOT_CHECKSUM_SKIP) } else { sum32(sector, seed) }
}

#[cfg(test)]
#[path = "tests/checksum.rs"]
mod tests;
