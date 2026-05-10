// Per-inode atime/mtime/ctime overlay for `utimensat` family.
//
// The Inode trait doesn't carry timestamps yet (most kernel-side
// inodes are pseudo: devfs/procfs/tmpfs entries). Rather than changing
// every Inode impl, we keep an out-of-line BTreeMap keyed by inode
// data-pointer identity. utimensat writes here; statx reads here and
// falls back to 0.
//
// Identity = `Arc::as_ptr(&inode) as *const u8 as usize`. Stable for
// the inode's lifetime; pointer reuse after free is theoretically
// possible but rare on a kernel-uptime timeline.

#![cfg(target_os = "oxide-kernel")]

extern crate alloc;
use alloc::collections::BTreeMap;
use sync::{Spinlock, TaskList as TaskListClass};

use crate::InodeRef;

/// Per-inode metadata overlay: timestamps + mode + owner. Tracks
/// real values for inodes whose backing FS doesn't carry them yet
/// (devfs/procfs/tmpfs pseudo entries). statx merges the override
/// onto its computed defaults.
#[derive(Default, Copy, Clone)]
pub struct InodeTimes {
    pub atime_ns: u64,
    pub mtime_ns: u64,
    pub ctime_ns: u64,
    /// Lower 12 bits = permission bits (rwxrwxrwx + suid/sgid/sticky);
    /// 0 = "use default mode 0o600 from statx". Mode TYPE bits are
    /// set by the inode's file_type and not touched here.
    pub mode_bits: u16,
    pub uid: u32,
    pub gid: u32,
    /// True once any of mode_bits/uid/gid was set explicitly. statx
    /// reads from override only when this is true; otherwise default.
    pub owner_set: bool,
}

static TIMES: Spinlock<BTreeMap<usize, InodeTimes>, TaskListClass> =
    Spinlock::new(BTreeMap::new());

/// Pointer-identity key for an inode reference.
/// # C: O(1)
pub fn key(inode: &InodeRef) -> usize {
    let raw: *const dyn crate::Inode = alloc::sync::Arc::as_ptr(inode);
    raw as *const u8 as usize
}

/// Fetch the stored times for `inode`, or `None` if never set.
/// # C: O(log N)
pub fn get(inode: &InodeRef) -> Option<InodeTimes> {
    let g = TIMES.lock();
    g.get(&key(inode)).copied()
}

/// Update atime/mtime; ctime always advances to `now_ns` on any update.
/// `None` for a field means "leave existing alone" (utimensat UTIME_OMIT).
/// # C: O(log N)
pub fn set(inode: &InodeRef, atime_ns: Option<u64>, mtime_ns: Option<u64>, now_ns: u64) {
    let k = key(inode);
    let mut g = TIMES.lock();
    let entry = g.entry(k).or_insert(InodeTimes::default());
    if let Some(t) = atime_ns { entry.atime_ns = t; }
    if let Some(t) = mtime_ns { entry.mtime_ns = t; }
    entry.ctime_ns = now_ns;
}

/// Set mode bits (low 12 — perm + suid/sgid/sticky). Used by chmod/
/// fchmod/fchmodat. Bumps ctime.
/// # C: O(log N)
pub fn set_mode(inode: &InodeRef, mode_bits: u16, now_ns: u64) {
    let k = key(inode);
    let mut g = TIMES.lock();
    let entry = g.entry(k).or_insert(InodeTimes::default());
    entry.mode_bits = mode_bits & 0o7777;
    entry.owner_set = true;
    entry.ctime_ns = now_ns;
}

/// Set owner uid/gid. `u32::MAX` (i.e. `(uid_t)-1`) means leave alone.
/// # C: O(log N)
pub fn set_owner(inode: &InodeRef, uid: u32, gid: u32, now_ns: u64) {
    let k = key(inode);
    let mut g = TIMES.lock();
    let entry = g.entry(k).or_insert(InodeTimes::default());
    if uid != u32::MAX { entry.uid = uid; }
    if gid != u32::MAX { entry.gid = gid; }
    entry.owner_set = true;
    entry.ctime_ns = now_ns;
}
