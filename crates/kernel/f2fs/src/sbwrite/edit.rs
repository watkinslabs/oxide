//! The field changes a running volume makes to its own superblock.
//!
//! Each is a patch to the copy that was read, so every field this build does
//! not know about survives untouched. None of them reaches the medium by
//! itself: a change is in memory until `commit` puts both copies down, which
//! is what lets a caller undo the change when the write fails.

use alloc::string::String;
use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::uapi::*;
use crate::volume::dnode::{put32, put64};

use super::raw::RawSuper;

/// Correct a segment count that runs past the main area's end.
///
/// A formatter that rounded the main area down leaves the volume claiming more
/// segments than the areas account for. The count is what every address bound
/// is computed against, so it is corrected in memory whether or not the
/// correction can be written; the caller decides whether to write it, and owes
/// the write when the medium refuses.
/// # C: O(1)
pub fn realign(raw: &mut RawSuper) {
    let b = raw.bytes();
    let (Some(seg0), Some(count), Some(main), Some(main_count), Some(log)) = (
        le32(b, SB_SEGMENT0_BLKADDR), le32(b, SB_SEGMENT_COUNT), le32(b, SB_MAIN_BLKADDR),
        le32(b, SB_SEGMENT_COUNT_MAIN), le32(b, SB_LOG_BLOCKS_PER_SEG),
    ) else { return };
    let main_end = u64::from(main) + (u64::from(main_count) << log);
    let seg_end = u64::from(seg0) + (u64::from(count) << log);
    if main_end >= seg_end { return; }
    let fixed = (main_end - u64::from(seg0)) >> log;
    let Ok(fixed) = u32::try_from(fixed) else { return };
    put32(raw.bytes_mut(), SB_SEGMENT_COUNT, fixed);
    raw.mark_realigned();
}

/// Set the volume's label.
///
/// The whole array is cleared first: a shorter name written over a longer one
/// would otherwise leave the old tail behind, and the label stops at its first
/// zero unit.
/// # C: O(name)
pub fn set_volume_name(raw: &mut RawSuper, name: &str) -> Result<(), Errno> {
    let units: Vec<u16> = name.encode_utf16().collect();
    if units.len() > SB_VOLUME_NAME_UNITS { return Err(Errno::Einval); }
    let b = raw.bytes_mut();
    b[SB_VOLUME_NAME..SB_VOLUME_NAME + SB_VOLUME_NAME_UNITS * 2].fill(0);
    for (i, u) in units.iter().enumerate() {
        b[SB_VOLUME_NAME + i * 2..SB_VOLUME_NAME + i * 2 + 2].copy_from_slice(&u.to_le_bytes());
    }
    Ok(())
}

/// The label as it stands. # C: O(SB_VOLUME_NAME_UNITS)
pub fn volume_name(raw: &RawSuper) -> String {
    raw.parse().map(|sb| sb.volume_name).unwrap_or_default()
}

/// Add or remove one extension, in the hot list or the cold one.
///
/// The two lists share one array — the cold entries first, the hot ones after
/// them — so neither can be changed without moving the other, and the counts
/// are what say where the boundary is. A name may be in one list or the other
/// and never both: an extension that is at once hot and cold would place the
/// same file in two logs depending on which list was consulted first.
/// # C: O(MAX_EXTENSION)
pub fn update_extension_list(raw: &mut RawSuper, name: &str, hot: bool, set: bool)
    -> Result<(), Errno> {
    if name.is_empty() || name.len() >= EXTENSION_LEN { return Err(Errno::Einval); }
    let b = raw.bytes_mut();
    let cold = le32(b, SB_EXTENSION_COUNT).ok_or(Errno::Einval)? as usize;
    let hot_n = usize::from(*b.get(SB_HOT_EXT_COUNT).ok_or(Errno::Einval)?);
    let total = cold + hot_n;
    if total > MAX_EXTENSION as usize { return Err(Errno::Einval); }
    if set {
        if total == MAX_EXTENSION as usize { return Err(Errno::Einval); }
        let (from, to) = if hot { (0, cold) } else { (cold, total) };
        if find(b, name, from, to).is_some() { return Err(Errno::Einval); }
    } else if (hot && hot_n == 0) || (!hot && cold == 0) {
        return Err(Errno::Einval);
    }
    let (from, to) = if hot { (cold, total) } else { (0, cold) };
    if let Some(i) = find(b, name, from, to) {
        if set { return Err(Errno::Einval); }
        remove(b, i, total);
        if hot { b[SB_HOT_EXT_COUNT] = (hot_n - 1) as u8; }
        else { put32(b, SB_EXTENSION_COUNT, (cold - 1) as u32); }
        return Ok(());
    }
    if !set { return Err(Errno::Einval); }
    if hot {
        write_entry(b, total, name);
        b[SB_HOT_EXT_COUNT] = (hot_n + 1) as u8;
    } else {
        // The hot entries sit directly after the cold ones, so making room for
        // a cold entry moves every hot entry up by one slot.
        let at = SB_EXTENSION_LIST + cold * EXTENSION_LEN;
        b.copy_within(at..at + hot_n * EXTENSION_LEN, at + EXTENSION_LEN);
        write_entry(b, cold, name);
        put32(b, SB_EXTENSION_COUNT, (cold + 1) as u32);
    }
    Ok(())
}

/// Grow or shrink the volume by `secs` sections.
///
/// Only the superblock's own account of the volume's size changes here. The
/// segments being given up have to be emptied first and the checkpoint's
/// counts have to follow, both of which are the caller's; a superblock that
/// claimed space the checkpoint did not would be caught by the next mount's
/// cross-checks.
/// # C: O(1)
pub fn resize(raw: &mut RawSuper, secs: i64) -> Result<(), Errno> {
    let b = raw.bytes();
    let per_sec = i64::from(le32(b, SB_SEGS_PER_SEC).ok_or(Errno::Einval)?);
    let log = le32(b, SB_LOG_BLOCKS_PER_SEG).ok_or(Errno::Einval)?;
    let segs = secs.checked_mul(per_sec).ok_or(Errno::Einval)?;
    let blks = segs.checked_mul(1i64 << log).ok_or(Errno::Einval)?;
    let sections = add32(le32(b, SB_SECTION_COUNT).ok_or(Errno::Einval)?, secs)?;
    let count = add32(le32(b, SB_SEGMENT_COUNT).ok_or(Errno::Einval)?, segs)?;
    let main = add32(le32(b, SB_SEGMENT_COUNT_MAIN).ok_or(Errno::Einval)?, segs)?;
    let blocks = add64(le64(b, SB_BLOCK_COUNT).ok_or(Errno::Einval)?, blks)?;
    let devs = device_count(b);
    let last = if devs > 1 {
        let at = SB_DEVS + (devs - 1) * DEV_ENTRY_SIZE + DEV_PATH_LEN;
        Some((at, add32(le32(b, at).ok_or(Errno::Einval)?, segs)?))
    } else {
        None
    };
    let b = raw.bytes_mut();
    put32(b, SB_SECTION_COUNT, sections);
    put32(b, SB_SEGMENT_COUNT, count);
    put32(b, SB_SEGMENT_COUNT_MAIN, main);
    put64(b, SB_BLOCK_COUNT, blocks);
    if let Some((at, segments)) = last { put32(b, at, segments); }
    Ok(())
}

/// The salt a password-derived key is stretched with, zero until one is set.
/// # C: O(1)
pub fn pw_salt(raw: &RawSuper) -> [u8; PW_SALT_LEN] {
    let mut out = [0u8; PW_SALT_LEN];
    let b = raw.bytes();
    if let Some(s) = b.get(SB_ENCRYPT_PW_SALT..SB_ENCRYPT_PW_SALT + PW_SALT_LEN) {
        out.copy_from_slice(s);
    }
    out
}

/// Set that salt, unless one is already set.
///
/// A salt that changed would strand every key derived from the old one, so the
/// first write wins and every later caller is handed what is already there.
/// # C: O(1)
pub fn set_pw_salt(raw: &mut RawSuper, salt: &[u8; PW_SALT_LEN]) -> bool {
    if pw_salt(raw) != [0u8; PW_SALT_LEN] { return false; }
    raw.bytes_mut()[SB_ENCRYPT_PW_SALT..SB_ENCRYPT_PW_SALT + PW_SALT_LEN].copy_from_slice(salt);
    true
}

/// Where `name` sits in `[from, to)`, comparing each entry up to its first
/// zero byte. # C: O(to - from)
fn find(b: &[u8], name: &str, from: usize, to: usize) -> Option<usize> {
    (from..to).find(|&i| entry(b, i) == name.as_bytes())
}

/// One entry's bytes, trimmed. # C: O(EXTENSION_LEN)
fn entry(b: &[u8], i: usize) -> &[u8] {
    let at = SB_EXTENSION_LIST + i * EXTENSION_LEN;
    let raw = &b[at..at + EXTENSION_LEN];
    let end = raw.iter().position(|&c| c == 0).unwrap_or(EXTENSION_LEN);
    &raw[..end]
}

/// Put `name` in slot `i`, clearing whatever was there. # C: O(EXTENSION_LEN)
fn write_entry(b: &mut [u8], i: usize, name: &str) {
    let at = SB_EXTENSION_LIST + i * EXTENSION_LEN;
    b[at..at + EXTENSION_LEN].fill(0);
    b[at..at + name.len()].copy_from_slice(name.as_bytes());
}

/// Take slot `i` out, closing the gap and clearing the slot that falls empty.
/// # C: O(MAX_EXTENSION)
fn remove(b: &mut [u8], i: usize, total: usize) {
    let at = SB_EXTENSION_LIST + i * EXTENSION_LEN;
    let end = SB_EXTENSION_LIST + total * EXTENSION_LEN;
    b.copy_within(at + EXTENSION_LEN..end, at);
    b[end - EXTENSION_LEN..end].fill(0);
}

/// Devices the volume lists, which is one when the list is empty.
/// # C: O(MAX_DEVICES)
fn device_count(b: &[u8]) -> usize {
    (0..MAX_DEVICES).take_while(|i| b[SB_DEVS + i * DEV_ENTRY_SIZE] != 0).count()
}

/// # C: O(1)
fn add32(base: u32, delta: i64) -> Result<u32, Errno> {
    let sum = i64::from(base).checked_add(delta).ok_or(Errno::Einval)?;
    u32::try_from(sum).map_err(|_| Errno::Einval)
}

/// # C: O(1)
fn add64(base: u64, delta: i64) -> Result<u64, Errno> {
    let sum = i128::from(base).checked_add(i128::from(delta)).ok_or(Errno::Einval)?;
    u64::try_from(sum).map_err(|_| Errno::Einval)
}

#[cfg(test)]
#[path = "../tests/sbwrite/edit.rs"]
mod tests;
