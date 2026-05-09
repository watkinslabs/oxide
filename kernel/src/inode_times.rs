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

use vfs::InodeRef;

/// Per-inode timestamp triple in monotonic-ns units. Mtime defaults
/// to 0 (no recorded modification); statx zeros the slot when absent.
#[derive(Default, Copy, Clone)]
pub struct InodeTimes {
    pub atime_ns: u64,
    pub mtime_ns: u64,
    pub ctime_ns: u64,
}

static TIMES: Spinlock<BTreeMap<usize, InodeTimes>, TaskListClass> =
    Spinlock::new(BTreeMap::new());

/// Pointer-identity key for an inode reference.
/// # C: O(1)
pub fn key(inode: &InodeRef) -> usize {
    let raw: *const dyn vfs::Inode = alloc::sync::Arc::as_ptr(inode);
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
