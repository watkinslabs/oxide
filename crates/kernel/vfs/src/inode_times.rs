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

extern crate alloc;

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

use crate::mount::{MNT_NOATIME, MNT_NODIRATIME, MNT_RELATIME};
use crate::superblock::{NSEC_PER_SEC, SB_NOATIME, SB_NODIRATIME, SB_RDONLY};

/// `24*60*60` seconds in nanoseconds — the relatime staleness window (Linux
/// fs/inode.c `relatime_need_update`: an atime older than a day forces an
/// update even when mtime/ctime have not advanced past it). # C: O(1)
pub const RELATIME_MAX_AGE_NS: u64 = 24 * 60 * 60 * NSEC_PER_SEC;

/// Value snapshot feeding the atime-update policy (Linux fs/inode.c
/// `atime_needs_update`). Pure inputs so the decision is testable hosted
/// without an inode/mount/superblock in hand. All times are ns since epoch.
#[derive(Copy, Clone)]
pub struct AtimeCtx {
    /// Per-mount `MNT_*` flags (Linux `mnt->mnt_flags`): NOATIME / NODIRATIME /
    /// RELATIME. Absence of RELATIME+NOATIME == strictatime (always update).
    pub mnt_flags: u64,
    /// Owning superblock `s_flags`: `SB_RDONLY`/`SB_NOATIME`/`SB_NODIRATIME`.
    pub sb_flags: u64,
    /// Per-inode `S_NOATIME` (chattr-level, e.g. a kernel pseudo inode that
    /// never tracks access time) — short-circuits to no-update.
    pub inode_noatime: bool,
    /// `S_ISDIR(i_mode)` — gates the NODIRATIME branches.
    pub is_dir: bool,
    /// Current `i_atime`.
    pub atime_ns: u64,
    /// Current `i_mtime`.
    pub mtime_ns: u64,
    /// Current `i_ctime`.
    pub ctime_ns: u64,
}

/// `relatime_need_update` (Linux fs/inode.c): under `MNT_RELATIME`, update
/// atime only if mtime≥atime, ctime≥atime, or atime is older than 24h. With
/// strictatime (no `MNT_RELATIME`) this is unconditionally true — the noatime
/// gates and the equality test in [`atime_needs_update`] still apply.
/// `now_ns` is the candidate replacement atime. # C: O(1)
pub fn relatime_need_update(mnt_flags: u64, atime_ns: u64, mtime_ns: u64,
                            ctime_ns: u64, now_ns: u64) -> bool {
    if mnt_flags & MNT_RELATIME == 0 { return true; }
    if mtime_ns >= atime_ns { return true; }
    if ctime_ns >= atime_ns { return true; }
    // Signed in Linux: a backwards clock (now < atime) yields a negative delta
    // and skips the update; saturating_sub gives 0 → below the window → skip.
    now_ns.saturating_sub(atime_ns) >= RELATIME_MAX_AGE_NS
}

/// `atime_needs_update` (Linux fs/inode.c) — decide whether a read access bumps
/// inode atime, honoring per-inode noatime, RO/noatime/nodiratime superblocks,
/// per-mount noatime/nodiratime, and the relatime vs strictatime policy.
/// `now_ns` is the candidate timestamp (`current_time`). # C: O(1)
pub fn atime_needs_update(c: &AtimeCtx, now_ns: u64) -> bool {
    if c.inode_noatime { return false; }
    // A read-only or noatime superblock never advances atime (Linux IS_NOATIME
    // == SB_RDONLY|SB_NOATIME).
    if c.sb_flags & (SB_RDONLY | SB_NOATIME) != 0 { return false; }
    if c.sb_flags & SB_NODIRATIME != 0 && c.is_dir { return false; }
    if c.mnt_flags & MNT_NOATIME != 0 { return false; }
    if c.mnt_flags & MNT_NODIRATIME != 0 && c.is_dir { return false; }
    if !relatime_need_update(c.mnt_flags, c.atime_ns, c.mtime_ns, c.ctime_ns, now_ns) { return false; }
    // No-op write avoidance: atime already at the candidate value.
    if c.atime_ns == now_ns { return false; }
    true
}

#[cfg(target_os = "oxide-kernel")]
use alloc::collections::BTreeMap;
#[cfg(target_os = "oxide-kernel")]
use sync::{Spinlock, TaskList as TaskListClass};
#[cfg(target_os = "oxide-kernel")]
use crate::InodeRef;

#[cfg(target_os = "oxide-kernel")]
static TIMES: Spinlock<BTreeMap<usize, InodeTimes>, TaskListClass> =
    Spinlock::new(BTreeMap::new());

/// Pointer-identity key for an inode reference.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn key(inode: &InodeRef) -> usize {
    let raw: *const dyn crate::Inode = alloc::sync::Arc::as_ptr(inode);
    raw as *const u8 as usize
}

/// Fetch the stored times for `inode`, or `None` if never set.
/// # C: O(log N)
#[cfg(target_os = "oxide-kernel")]
pub fn get(inode: &InodeRef) -> Option<InodeTimes> {
    let g = TIMES.lock();
    g.get(&key(inode)).copied()
}

#[cfg(not(target_os = "oxide-kernel"))]
pub fn get(_inode: &crate::InodeRef) -> Option<InodeTimes> { None }

/// Update atime/mtime; ctime always advances to `now_ns` on any update.
/// `None` for a field means "leave existing alone" (utimensat UTIME_OMIT).
/// # C: O(log N)
#[cfg(target_os = "oxide-kernel")]
pub fn set(inode: &InodeRef, atime_ns: Option<u64>, mtime_ns: Option<u64>, now_ns: u64) {
    let k = key(inode);
    let mut g = TIMES.lock();
    let entry = g.entry(k).or_insert(InodeTimes::default());
    if let Some(t) = atime_ns { entry.atime_ns = t; }
    if let Some(t) = mtime_ns { entry.mtime_ns = t; }
    entry.ctime_ns = now_ns;
}

#[cfg(not(target_os = "oxide-kernel"))]
pub fn set(_inode: &crate::InodeRef, _atime_ns: Option<u64>, _mtime_ns: Option<u64>, _now_ns: u64) {}

/// Set mode bits (low 12 — perm + suid/sgid/sticky). Used by chmod/
/// fchmod/fchmodat. Bumps ctime.
/// # C: O(log N)
#[cfg(target_os = "oxide-kernel")]
pub fn set_mode(inode: &InodeRef, mode_bits: u16, now_ns: u64) {
    let k = key(inode);
    let mut g = TIMES.lock();
    let entry = g.entry(k).or_insert(InodeTimes::default());
    entry.mode_bits = mode_bits & 0o7777;
    entry.owner_set = true;
    entry.ctime_ns = now_ns;
}

#[cfg(not(target_os = "oxide-kernel"))]
pub fn set_mode(_inode: &crate::InodeRef, _mode_bits: u16, _now_ns: u64) {}

/// Set owner uid/gid. `u32::MAX` (i.e. `(uid_t)-1`) means leave alone.
/// # C: O(log N)
#[cfg(target_os = "oxide-kernel")]
pub fn set_owner(inode: &InodeRef, uid: u32, gid: u32, now_ns: u64) {
    let k = key(inode);
    let mut g = TIMES.lock();
    let entry = g.entry(k).or_insert(InodeTimes::default());
    if uid != u32::MAX { entry.uid = uid; }
    if gid != u32::MAX { entry.gid = gid; }
    entry.owner_set = true;
    entry.ctime_ns = now_ns;
}

#[cfg(not(target_os = "oxide-kernel"))]
pub fn set_owner(_inode: &crate::InodeRef, _uid: u32, _gid: u32, _now_ns: u64) {}
