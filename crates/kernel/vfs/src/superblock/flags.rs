
// range. `MS_*` (mount syscall) flags map onto these one-to-one in the low bits.
pub const SB_RDONLY:      u64 = 1;
pub const SB_NOSUID:      u64 = 1 << 1;
pub const SB_NODEV:       u64 = 1 << 2;
pub const SB_NOEXEC:      u64 = 1 << 3;
pub const SB_SYNCHRONOUS: u64 = 1 << 4;
pub const SB_MANDLOCK:    u64 = 1 << 6;
pub const SB_DIRSYNC:     u64 = 1 << 7;
pub const SB_NOATIME:     u64 = 1 << 10;
pub const SB_NODIRATIME:  u64 = 1 << 11;
pub const SB_SILENT:      u64 = 1 << 15;
pub const SB_POSIXACL:    u64 = 1 << 16;
pub const SB_KERNMOUNT:   u64 = 1 << 22;
pub const SB_I_VERSION:   u64 = 1 << 23;
pub const SB_LAZYTIME:    u64 = 1 << 25;
/// Internal lifecycle bits: `SB_BORN` (fill_super done), `SB_ACTIVE` (mounted).
pub const SB_BORN:   u64 = 1 << 29;
pub const SB_ACTIVE: u64 = 1 << 30;
/// "This superblock may not be mounted by a user request." Set by the
/// filesystem while filling the superblock, so it can only be tested AFTER the
/// instance exists — which is where both `mount(2)` and `fsmount(2)` test it.
pub const SB_NOUSER: u64 = 1 << 31;

// `s_writers.frozen` freeze levels. `freeze_super`
// ratchets UNFROZEN → WRITE (block new write(2)) → PAGEFAULT (block mmap
// faults) → FS (on-disk `freeze_fs`) → COMPLETE; `thaw_super` resets to
// UNFROZEN. `sb_start_write` admits a writer only at UNFROZEN. Drives FIFREEZE
// + consistent-snapshot quiesce.
pub const SB_UNFROZEN:         u32 = 0;
pub const SB_FREEZE_WRITE:     u32 = 1;
pub const SB_FREEZE_PAGEFAULT: u32 = 2;
pub const SB_FREEZE_FS:        u32 = 3;
pub const SB_FREEZE_COMPLETE:  u32 = 4;

// --- `sb->s_iflags` — the
// KERNEL-INTERNAL superblock flag word, a space DISJOINT from the user-visible
// `SB_*` bits in `s_flags` above. Set by each filesystem's `fill_super` (procfs,
// kernfs, and generic pseudo-fs instances all set it); read by the noexec and
// device-open checks and — the reason this word exists here — the
// already-visible-instance revealing check on new mounts. ---
/// `SB_I_NOEXEC` — nothing on this filesystem is ever executable, whatever the
/// per-mount `MNT_NOEXEC` says (Linux `path_noexec`).
pub const SB_I_NOEXEC: u64 = 0x0000_0002;
/// `SB_I_NODEV` — device nodes on this filesystem never function, whatever the
/// per-mount `MNT_NODEV` says (Linux `may_open_dev`).
pub const SB_I_NODEV: u64 = 0x0000_0004;
/// `SB_I_RESTRICTED_VARIANT` — this instance exposes only a SUBSET of what the
/// filesystem can show (procfs `-o subset=pid`), so `mount_too_revealing` both
/// exempts it from needing an already-visible instance AND refuses to let it
/// serve as the already-visible instance for anything else.
pub const SB_I_RESTRICTED_VARIANT: u64 = 0x0000_0010;
/// `SB_I_NOIDMAP` — this filesystem instance disabled idmapped mounts even
/// though its type generally advertises `FS_ALLOW_IDMAP`.
pub const SB_I_NOIDMAP: u64 = 0x0000_2000;
/// The `s_iflags` pair `mount_too_revealing` REQUIRES on any filesystem marked
/// `FS_USERNS_MOUNT_RESTRICTED` (Linux `required_iflags`). # C: const
pub const SB_I_USERNS_REQUIRED: u64 = SB_I_NOEXEC | SB_I_NODEV;

/// `MAX_LFS_FILESIZE` on a 64-bit kernel — the
/// default `s_maxbytes` a large-file backend reports. # C: O(1)
pub const MAX_LFS_FILESIZE: u64 = i64::MAX as u64;

/// `NSEC_PER_SEC` — nanoseconds in one second,
/// the per-second denominator [`SuperBlock::timestamp_truncate`] floors the
/// sub-second field against. # C: O(1)
pub const NSEC_PER_SEC: u64 = 1_000_000_000;

/// `TIME64_MIN`/`TIME64_MAX` — the widest
/// representable `time64_t` seconds-since-epoch range, the default
/// `s_time_min`/`s_time_max` `alloc_super` installs before a backend narrows it
/// to its on-disk timestamp field width (ext4 32-bit: 1901..2446). With these
/// defaults [`SuperBlock::timestamp_truncate`]'s clamp is a no-op. # C: O(1)
pub const TIME64_MIN: i64 = i64::MIN;
/// See [`TIME64_MIN`]. # C: O(1)
pub const TIME64_MAX: i64 = i64::MAX;
