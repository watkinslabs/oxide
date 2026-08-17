//! `/sys/fs/f2fs/<dev>/` — the controls over WHERE a write lands.
//!
//! Its own group rather than a corner of the volume's tunables, because these
//! four are read by one decision pair (`crate::place`) and nothing else, and
//! because they are the only controls a mount cannot be given on its mount
//! line: three of the four are derived from the volume's SIZE and reserve at
//! mount, so a tool that wants anything else has no way to ask for it but this.
//!
//! Bounds stay with the decision module that acts on the value — the armed set
//! is checked by `place::ipu::store_policy` and the three thresholds by
//! `place::tunables::store_threshold` — so the published surface cannot come to
//! accept a set the placement machinery would ignore.

use alloc::sync::Arc;
use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::fsattr::Attr;
use crate::mount::F2fs;

use super::volume::{num_rw, Vol};

/// Every placement control one mount publishes. # C: O(1)
pub(crate) fn attrs(fs: &Arc<F2fs>, dev: &str) -> Vec<Attr> {
    alloc::vec![
        num_rw(fs, dev, "ipu_policy", |v| u64::from(v.ipu_policy()), set_ipu_policy),
        num_rw(fs, dev, "min_ipu_util", |v| u64::from(v.min_ipu_util()), set_min_ipu_util),
        num_rw(fs, dev, "min_fsync_blocks",
               |v| u64::from(v.min_fsync_blocks()), set_min_fsync_blocks),
        num_rw(fs, dev, "min_ssr_sections",
               |v| u64::from(v.min_ssr_sections()), set_min_ssr_sections),
    ]
}

/// The in-place-update policies armed for this mount.
///
/// A word, not a name: the eight policies are independent and a mount arms a
/// SET of them, which is what the volume's own store rule checks.
/// # C: O(1)
fn set_ipu_policy(v: &mut Vol, n: u64) -> Result<(), Errno> {
    if n > u64::from(u32::MAX) { return Err(Errno::Einval); }
    v.set_ipu_policy(n as u32)
}

/// Occupancy above which the two utilisation arms fire. # C: O(1)
fn set_min_ipu_util(v: &mut Vol, n: u64) -> Result<(), Errno> { v.set_min_ipu_util(n) }

/// Dirty pages at or below which an `fsync` asks for its pages to be rewritten
/// in place rather than moved. # C: O(1)
fn set_min_fsync_blocks(v: &mut Vol, n: u64) -> Result<(), Errno> { v.set_min_fsync_blocks(n) }

/// Free sections a mount keeps above its reserve before it starts recycling
/// segments. # C: O(1)
fn set_min_ssr_sections(v: &mut Vol, n: u64) -> Result<(), Errno> { v.set_min_ssr_sections(n) }

#[cfg(test)]
#[path = "../tests/sysfs/place.rs"]
mod tests;
