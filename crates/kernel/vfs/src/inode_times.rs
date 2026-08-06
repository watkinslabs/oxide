// Atime-update policy (relatime/noatime) + `current_time` granularity flooring
// for the `utimensat`/stat family. The concrete `struct Inode` is the sole
// owner of mode, uid, gid, and timestamps.

use crate::mount::{MNT_NOATIME, MNT_NODIRATIME, MNT_RELATIME};
use crate::superblock::{SB_NOATIME, SB_NODIRATIME, SB_RDONLY};
use crate::timespec::{Timespec64, SECS_PER_DAY};
use core::sync::atomic::{AtomicUsize, Ordering};

/// Wall-clock (`CLOCK_REALTIME`) provider, installed at boot by the syscall
/// layer — `vfs` owns no time source. Readers run from filesystem paths and
/// NET_RX softirq packet timestamping, so publication must be lock-free: an
/// IRQ can interrupt the installing/reading task and must never spin on that
/// task's clock-provider lock. Zero is the pre-install sentinel.
static REALTIME_PROVIDER: AtomicUsize = AtomicUsize::new(0);

/// Install the wall-clock provider (kernel boot). Idempotent, last-writer-wins.
/// # C: O(1)
pub fn set_realtime_provider(f: fn() -> u64) {
    REALTIME_PROVIDER.store(f as usize, Ordering::Release);
}

/// Current `CLOCK_REALTIME` in ns since the Unix epoch via the installed
/// provider, or 0 when none is installed yet (pre-userspace — matching a
/// `CLOCK_REALTIME` read before `settimeofday` seeds the offset). # C: O(1)
pub fn realtime_now_ns() -> u64 {
    let raw = REALTIME_PROVIDER.load(Ordering::Acquire);
    if raw == 0 { return 0; }
    // SAFETY: every non-zero value in this private atomic is published by
    // `set_realtime_provider` from this exact function-pointer type; both
    // supported kernel architectures represent it in one usize.
    let f = unsafe { core::mem::transmute::<usize, fn() -> u64>(raw) };
    f()
}

/// `24*60*60` seconds — the relatime staleness window (Linux fs/inode.c
/// `relatime_need_update`: an atime older than a day forces an update even when
/// mtime/ctime have not advanced past it). Linux compares whole SECONDS
/// (`(long)(now.tv_sec - atime.tv_sec) >= 24*60*60`), not nanoseconds. # C: O(1)
pub const RELATIME_MAX_AGE_SECS: i64 = SECS_PER_DAY;

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
    pub atime: Timespec64,
    /// Current `i_mtime`.
    pub mtime: Timespec64,
    /// Current `i_ctime`.
    pub ctime: Timespec64,
}

/// `relatime_need_update` (Linux fs/inode.c): under `MNT_RELATIME`, update
/// atime only if mtime≥atime, ctime≥atime, or atime is older than 24h. With
/// strictatime (no `MNT_RELATIME`) this is unconditionally true — the noatime
/// gates and the equality test in [`atime_needs_update`] still apply.
/// `now` is the candidate replacement atime. # C: O(1)
pub fn relatime_need_update(mnt_flags: u64, atime: Timespec64, mtime: Timespec64,
                            ctime: Timespec64, now: Timespec64) -> bool {
    if mnt_flags & MNT_RELATIME == 0 { return true; }
    // `timespec64_compare(&mtime, &atime) >= 0` — the derived `Ord` on
    // `Timespec64` IS that comparison (signed seconds, then sub-second).
    if mtime >= atime { return true; }
    if ctime >= atime { return true; }
    // Linux: `(long)(now.tv_sec - atime.tv_sec) >= 24*60*60`. Signed, so a
    // backwards clock (now < atime) yields a negative delta and skips the
    // update — the unsigned model could only approximate this with a
    // `saturating_sub` floor at 0.
    now.secs_since(atime) >= RELATIME_MAX_AGE_SECS
}

/// `atime_needs_update` (Linux fs/inode.c) — decide whether a read access bumps
/// inode atime, honoring per-inode noatime, RO/noatime/nodiratime superblocks,
/// per-mount noatime/nodiratime, and the relatime vs strictatime policy.
/// `now` is the candidate timestamp (`current_time`). # C: O(1)
pub fn atime_needs_update(c: &AtimeCtx, now: Timespec64) -> bool {
    if c.inode_noatime { return false; }
    // A read-only or noatime superblock never advances atime (Linux IS_NOATIME
    // == SB_RDONLY|SB_NOATIME).
    if c.sb_flags & (SB_RDONLY | SB_NOATIME) != 0 { return false; }
    if c.sb_flags & SB_NODIRATIME != 0 && c.is_dir { return false; }
    if c.mnt_flags & MNT_NOATIME != 0 { return false; }
    if c.mnt_flags & MNT_NODIRATIME != 0 && c.is_dir { return false; }
    if !relatime_need_update(c.mnt_flags, c.atime, c.mtime, c.ctime, now) { return false; }
    // No-op write avoidance: atime already at the candidate value.
    if c.atime == now { return false; }
    true
}

/// `current_time` (Linux fs/inode.c) — the wall-clock timestamp `now_ns`
/// (nanoseconds since the epoch; the syscall layer reads the clock, `vfs` owns
/// no time source) floored to the inode's superblock `s_time_gran` via
/// [`crate::superblock::SuperBlock::timestamp_truncate`], so a stamped
/// atime/mtime/ctime never carries sub-granularity precision the backend cannot
/// persist. An SB-less inode (anon pidfd/pipe/socket) gets the raw `now_ns`
/// (ns precision). # C: O(1)
pub fn current_time(inode: &crate::inode::Inode, now_ns: u64) -> Timespec64 {
    let now = Timespec64::from_clock_ns(now_ns);
    inode.i_sb().map(|sb| sb.timestamp_truncate(now)).unwrap_or(now)
}

/// `inode_set_ctime_current` (Linux fs/inode.c) — floor `now_ns` to the inode's
/// granularity ([`current_time`]) and return it, so a metadata mutator both
/// reports and (via the inode's own `set_times`) records the change time.
/// D17: no longer writes any out-of-line overlay — the concrete inode owns its
/// `i_ctime` field. # C: O(1)
pub fn inode_set_ctime_current(inode: &crate::InodeRef, now_ns: u64) -> Timespec64 {
    current_time(&**inode, now_ns)
}
