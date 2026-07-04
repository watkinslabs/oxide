// --- [D10] Per-mount mnt_flags OPTION bits — the REAL Linux kernel-internal
// `mnt->mnt_flags` values (`include/linux/mount.h`), a DISJOINT space from the
// MS_* mount(2) request flags below. `ms_to_mnt` maps a request mask into this
// space at mount/remount time. `/proc/mounts` + statvfs `ST_*` read these by
// NAME, so the value change is transparent to those renderers. ---
pub const MNT_NOSUID: u64 = 0x01;
pub const MNT_NODEV: u64 = 0x02;
pub const MNT_NOEXEC: u64 = 0x04;
pub const MNT_NOATIME: u64 = 0x08;
pub const MNT_NODIRATIME: u64 = 0x10;
pub const MNT_RELATIME: u64 = 0x20;
/// Linux `MNT_READONLY` (the per-mount RO bit, distinct from `SB_RDONLY`).
pub const MNT_RDONLY: u64 = 0x40;
/// Linux `MNT_NOSYMFOLLOW` (symlinks on this mount are not followed).
pub const MNT_NOSYMFOLLOW: u64 = 0x80;
/// Synthetic strictatime marker. Linux has NO per-mount strictatime bit —
/// strictatime is the ABSENCE of NOATIME+RELATIME — but `atime_policy` and
/// `inode_times` model it as one disjoint bit so an explicit MS_STRICTATIME
/// request stays representable and the policy resolver stays branch-simple.
/// Above the real `u32` mnt_flags range, disjoint from every Linux value.
pub const MNT_STRICTATIME: u64 = 1 << 33;
pub const MNT_OPTION_MASK: u64 = MNT_RDONLY | MNT_NOSUID | MNT_NODEV | MNT_NOEXEC
    | MNT_NOATIME | MNT_NODIRATIME | MNT_RELATIME | MNT_NOSYMFOLLOW | MNT_STRICTATIME;

// --- [D10] mount(2) MS_* OPTION request flags (`linux/mount.h`) — the
// USER-FACING request space the syscall passes in, mapped to MNT_* by
// `ms_to_mnt`. SYNCHRONOUS/MANDLOCK/DIRSYNC/LAZYTIME are SUPERBLOCK (`SB_*`)
// flags, not per-mount, and are NOT represented in the mnt_flags space. ---
pub const MS_RDONLY: u64 = 0x1;
pub const MS_NOSUID: u64 = 0x2;
pub const MS_NODEV: u64 = 0x4;
pub const MS_NOEXEC: u64 = 0x8;
pub const MS_NOATIME: u64 = 0x400;
pub const MS_NODIRATIME: u64 = 0x800;
pub const MS_RELATIME: u64 = 1 << 21;
pub const MS_STRICTATIME: u64 = 1 << 24;

/// Map a mount(2) MS_* OPTION request mask to the per-mount MNT_* flag space
/// (Linux `do_mount`/`reconfigure`: derive `mnt_flags` from the request). The
/// atime policy follows Linux precedence — NOATIME wins, then explicit
/// STRICTATIME, else RELATIME (the kernel default since 2.6.30 when neither
/// STRICTATIME nor NOATIME is asked for). SB-level options
/// (SYNCHRONOUS/MANDLOCK/DIRSYNC/LAZYTIME) live on the superblock and are
/// dropped here. # C: O(1)
pub fn ms_to_mnt(ms: u64) -> u64 {
    let mut f = 0u64;
    if ms & MS_RDONLY     != 0 { f |= MNT_RDONLY; }
    if ms & MS_NOSUID     != 0 { f |= MNT_NOSUID; }
    if ms & MS_NODEV      != 0 { f |= MNT_NODEV; }
    if ms & MS_NOEXEC     != 0 { f |= MNT_NOEXEC; }
    if ms & MS_NODIRATIME != 0 { f |= MNT_NODIRATIME; }
    if ms & MS_NOATIME != 0 { f |= MNT_NOATIME; }
    else if ms & MS_STRICTATIME != 0 { f |= MNT_STRICTATIME; }
    else { f |= MNT_RELATIME; }
    f
}
