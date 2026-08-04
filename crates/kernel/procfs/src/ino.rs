//! procfs inode-number allocation: the runtime counter and the per-pid encoder.
//!
//! The counter was seeded at the base of the range the FIXED procfs identities
//! occupy (`/proc/self/status`, `/proc/mounts`, `/proc/meminfo`, …). After
//! roughly 3300 allocations it began minting numbers that were already
//! somebody's `/proc` file, so a sysctl inode and `/proc/mounts` reported the
//! same `(st_dev, st_ino)` to anything that keys on it. Dynamic entries now
//! draw from their own reserved range and wrap inside it; the fixed identities
//! keep the range they always had.
//!
//! Ungated on purpose: the decision this module makes is testable, and a
//! `#[cfg(test)]` block inside `live/` (which is `cfg(target_os =
//! "oxide-kernel")`) would compile out entirely.

use vfs::pseudo_ino::{RegionAllocator, PROCFS_DYNAMIC};
use vfs::Ino;

static NEXT_DYNAMIC_INO: RegionAllocator = RegionAllocator::new(&PROCFS_DYNAMIC);

/// Per-pid inode tags for entries whose identity is shared across modules.
pub(crate) const PID_INO_TAG_PERSONALITY: u64 = 0x2e;
pub(crate) const PID_INO_TAG_PROJID_MAP: u64 = 0x30;

/// Next inode number for a procfs entry built at runtime — sysctl files and
/// directories, per-task attr files. # C: O(1)
pub fn next_ino() -> Ino { NEXT_DYNAMIC_INO.alloc() }

/// Inode number for a per-pid/per-tid `/proc` file: the file kind in the high
/// half, the task id in the low half. # C: O(1)
pub(crate) fn pid_ino(tag: u64, id: u32) -> Ino {
    crate::ids::LIVE_INO_TAG | (tag << 32) | id as u64
}

#[cfg(test)]
#[path = "ino/tests.rs"]
mod tests;
