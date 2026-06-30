// Atime-update policy (relatime/noatime) + `current_time` granularity flooring
// for the `utimensat`/stat family.
//
// D17: the legacy pointer-keyed `TIMES` overlay (a `BTreeMap` keyed by
// `Arc::as_ptr`) is GONE — the concrete `struct Inode` now stores real
// `i_atime`/`i_mtime`/`i_ctime`/`i_mode`/`i_uid`/`i_gid` fields, so `getattr`
// reads them directly and the overlay store+merge is dead. The accessor shims
// below (`get`/`set`/`set_mode`/`set_owner`) remain as no-ops only so the
// cross-lane fallback call sites (syscalls `perms_common`, `fs::xattr`) still
// compile; they take effect nowhere because the concrete inode's own
// `set_perm`/`set_owner`/`set_times` always succeed. Removing those call sites
// (and then these shims) is a cross-lane follow-up. The [`InodeTimes`] struct is
// retained as the (now inert) `overlay` argument type of `getattr`.

/// Per-inode metadata overlay (LEGACY, inert): timestamps + mode + owner. Once
/// the fallback store for pseudo-fs inodes without native fields; the concrete
/// `struct Inode` now always carries its own, so this is retained only as the
/// `getattr`/`generic_fillattr` `overlay` parameter type and is never consulted.
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

/// `current_time` (Linux fs/inode.c) — the wall-clock timestamp `now_ns`
/// (nanoseconds since the epoch; the syscall layer reads the clock, `vfs` owns
/// no time source) floored to the inode's superblock `s_time_gran` via
/// [`crate::superblock::SuperBlock::timestamp_truncate`], so a stamped
/// atime/mtime/ctime never carries sub-granularity precision the backend cannot
/// persist. An SB-less inode (anon pidfd/pipe/socket) gets the raw `now_ns`
/// (ns precision). # C: O(1)
pub fn current_time(inode: &crate::inode::Inode, now_ns: u64) -> u64 {
    inode.i_sb().map(|sb| sb.timestamp_truncate(now_ns)).unwrap_or(now_ns)
}

/// `inode_set_ctime_current` (Linux fs/inode.c) — floor `now_ns` to the inode's
/// granularity ([`current_time`]) and return it, so a metadata mutator both
/// reports and (via the inode's own `set_times`) records the change time.
/// D17: no longer writes any out-of-line overlay — the concrete inode owns its
/// `i_ctime` field. # C: O(1)
pub fn inode_set_ctime_current(inode: &crate::InodeRef, now_ns: u64) -> u64 {
    current_time(&**inode, now_ns)
}

// D17 LEGACY no-op shims. The concrete `struct Inode` owns mode/owner/times, so
// these fallbacks take effect nowhere; they remain only so the cross-lane
// callers (`syscalls::perms_common`, `fs::xattr`) that still reference the old
// overlay continue to compile. Removing those call sites + these shims is a
// cross-lane follow-up.

/// Always `None` (the overlay store is gone). # C: O(1)
pub fn get(_inode: &crate::InodeRef) -> Option<InodeTimes> { None }

/// No-op (the overlay store is gone; the inode's own `set_times` records times).
/// # C: O(1)
pub fn set(_inode: &crate::InodeRef, _atime_ns: Option<u64>, _mtime_ns: Option<u64>, _now_ns: u64) {}

/// No-op (the inode's own `set_perm` records the mode). # C: O(1)
pub fn set_mode(_inode: &crate::InodeRef, _mode_bits: u16, _now_ns: u64) {}

/// No-op (the inode's own `set_owner` records the owner ids). # C: O(1)
pub fn set_owner(_inode: &crate::InodeRef, _uid: u32, _gid: u32, _now_ns: u64) {}
