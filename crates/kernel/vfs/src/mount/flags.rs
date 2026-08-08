// --- [D10] Per-mount mnt_flags OPTION bits — the REAL Linux kernel-internal
// `mnt->mnt_flags` values, a DISJOINT space from the
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

/// Linux `MNT_ATIME_MASK`: the whole atime policy
/// field, NODIRATIME included. The unit `do_remount`/`can_change_locked_flags`/
/// `mount_too_revealing` compare and preserve. Carries our synthetic
/// `MNT_STRICTATIME` because Linux spells strictatime as the ABSENCE of
/// NOATIME+RELATIME, which is not representable as a bit here. # C: const
pub const MNT_ATIME_MASK: u64 = MNT_NOATIME | MNT_NODIRATIME | MNT_RELATIME | MNT_STRICTATIME;

/// The atime MODE bits only — a mount carries exactly one. NODIRATIME is an
/// INDEPENDENT bit in `mount_setattr(2)`'s request space (`MOUNT_ATTR_NODIRATIME`
/// sits outside `MOUNT_ATTR__ATIME`), so the sub-field clear/set ladder must not
/// sweep it. # C: const
pub const MNT_ATIME_MODE_MASK: u64 = MNT_NOATIME | MNT_RELATIME | MNT_STRICTATIME;

// --- [D10] mount(2) MS_* OPTION request flags — the
// USER-FACING request space the syscall passes in, mapped to MNT_* by
// `ms_to_mnt`. SYNCHRONOUS/MANDLOCK/DIRSYNC/LAZYTIME are SUPERBLOCK (`SB_*`)
// flags, not per-mount, and are NOT represented in the mnt_flags space. ---
pub const MS_RDONLY: u64 = 0x1;
pub const MS_NOSUID: u64 = 0x2;
pub const MS_NODEV: u64 = 0x4;
pub const MS_NOEXEC: u64 = 0x8;
pub const MS_SYNCHRONOUS: u64 = 0x10;
pub const MS_MANDLOCK: u64 = 0x40;
pub const MS_DIRSYNC: u64 = 0x80;
/// `MS_NOSYMFOLLOW` — the request counterpart of
/// `MNT_NOSYMFOLLOW`. `path_mount` maps it; without the constant the request bit
/// was silently dropped and the mount followed symlinks it was told not to.
pub const MS_NOSYMFOLLOW: u64 = 256;
pub const MS_NOATIME: u64 = 0x400;
pub const MS_NODIRATIME: u64 = 0x800;
pub const MS_RELATIME: u64 = 1 << 21;
pub const MS_STRICTATIME: u64 = 1 << 24;
pub const MS_LAZYTIME: u64 = 1 << 25;
/// `MS_SILENT` — suppress the backend's fill-super
/// console chatter. Not an option bit anything enforces here, but
/// `flags_to_propagation_type` STRIPS it alongside `MS_REC`, so a
/// `mount(NULL, t, NULL, MS_SHARED|MS_SILENT)` must not be read as malformed.
pub const MS_SILENT: u64 = 1 << 15;

// --- mount(2) OPERATION selectors. Not option bits:
// `path_mount` dispatches on these to do_reconfigure_mnt / do_remount /
// do_loopback / do_change_type / do_move_mount_old / do_new_mount. Owned here
// with the option bits so the mount(2) request contract has ONE definition. ---
pub const MS_REMOUNT: u64 = 0x20;
pub const MS_BIND: u64 = 0x1000;
pub const MS_MOVE: u64 = 0x2000;
pub const MS_REC: u64 = 0x4000;
pub const MS_UNBINDABLE: u64 = 1 << 17;
pub const MS_PRIVATE: u64 = 1 << 18;
pub const MS_SLAVE: u64 = 1 << 19;
pub const MS_SHARED: u64 = 1 << 20;
/// The four propagation-retune selectors (`path_mount`'s `do_change_type` arm).
/// # C: const
pub const MS_PROPAGATION: u64 = MS_UNBINDABLE | MS_PRIVATE | MS_SLAVE | MS_SHARED;

/// Every MS_* bit a remount request may carry (option bits + the SB-level ones
/// `do_remount` forwards to `reconfigure_super`). # C: const
pub const MS_REMOUNTABLE: u64 = MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_SYNCHRONOUS
    | MS_MANDLOCK | MS_DIRSYNC | MS_NOATIME | MS_NODIRATIME | MS_RELATIME | MS_STRICTATIME
    | MS_LAZYTIME | MS_NOSYMFOLLOW;

/// Every MS_* bit whose presence counts as "the caller asked for an atime mode"
/// (Linux `path_mount`'s remount-preservation test). # C: const
pub const MS_ATIME_REQUEST: u64 = MS_NOATIME | MS_NODIRATIME | MS_RELATIME | MS_STRICTATIME;

/// Map a mount(2) MS_* OPTION request mask to the per-mount MNT_* flag space.
/// Mirrors Linux `path_mount`'s per-mountpoint flag derivation exactly,
/// because the atime rules are order-sensitive:
/// relatime is stamped unless MS_NOATIME is present, and MS_STRICTATIME then
/// CLEARS both RELATIME and NOATIME — so `MS_NOATIME|MS_STRICTATIME` resolves to
/// strictatime, not noatime. (Linux encodes strictatime as the ABSENCE of both;
/// our disjoint `MNT_STRICTATIME` marker stands in for that state, so the clear
/// is followed by an explicit set.) SB-level options
/// (SYNCHRONOUS/MANDLOCK/DIRSYNC/LAZYTIME) live on the superblock and are
/// dropped here. # C: O(1)
pub fn ms_to_mnt(ms: u64) -> u64 {
    let mut f = 0u64;
    if ms & MS_NOATIME    == 0 { f |= MNT_RELATIME; }   // "Default to relatime unless overriden"
    if ms & MS_NOSUID     != 0 { f |= MNT_NOSUID; }
    if ms & MS_NODEV      != 0 { f |= MNT_NODEV; }
    if ms & MS_NOEXEC     != 0 { f |= MNT_NOEXEC; }
    if ms & MS_NOATIME    != 0 { f |= MNT_NOATIME; }
    if ms & MS_NODIRATIME != 0 { f |= MNT_NODIRATIME; }
    if ms & MS_STRICTATIME != 0 { f &= !(MNT_RELATIME | MNT_NOATIME); f |= MNT_STRICTATIME; }
    if ms & MS_RDONLY     != 0 { f |= MNT_RDONLY; }
    if ms & MS_NOSYMFOLLOW != 0 { f |= MNT_NOSYMFOLLOW; }
    f
}

/// [`ms_to_mnt`] for an `MS_REMOUNT` request: Linux `path_mount` — "The default
/// atime for remount is preservation" — so a remount naming NO atime bit keeps
/// the mount's CURRENT atime mode instead of silently resetting it to relatime.
/// `cur` is the mount's live MNT_* word. # C: O(1)
pub fn ms_to_mnt_remount(ms: u64, cur: u64) -> u64 {
    let f = ms_to_mnt(ms);
    if ms & MS_ATIME_REQUEST != 0 { return f; }
    (f & !MNT_ATIME_MASK) | (cur & MNT_ATIME_MASK)
}
