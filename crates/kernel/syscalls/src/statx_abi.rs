// `statx(2)` ABI: `struct statx` wire layout, the mask/flag constants, the
// input-validation ladder, and `cp_statx`.
//
// Compiled into the kernel AND the hosted test build (no target gate) because
// the byte offsets and the EINVAL ORDER are the whole observable contract, and
// a `#[cfg(test)]` block inside the `oxide-kernel`-gated slot file would
// silently compile out.

use syscall::errno::Errno;
use vfs::Timespec64;
use vfs::getattr::Kstat;

/// `sizeof(struct statx)` — 256 bytes, byte-identical on x86_64 and aarch64
/// (every member is a fixed-width `__u*`/`__s64` with natural alignment; there
/// is no per-arch override and no compat variant).
pub const STATX_SIZE: usize = 256;

/// Field byte offsets. Named rather than
/// inlined so the encoder and its tests cite ONE table.
pub mod off {
    pub const MASK:              usize = 0;
    pub const BLKSIZE:           usize = 4;
    pub const ATTRIBUTES:        usize = 8;
    pub const NLINK:             usize = 16;
    pub const UID:               usize = 20;
    pub const GID:               usize = 24;
    pub const MODE:              usize = 28;
    pub const INO:               usize = 32;
    pub const SIZE:              usize = 40;
    pub const BLOCKS:            usize = 48;
    pub const ATTRIBUTES_MASK:   usize = 56;
    pub const ATIME:             usize = 64;
    pub const BTIME:             usize = 80;
    pub const CTIME:             usize = 96;
    pub const MTIME:             usize = 112;
    pub const RDEV_MAJOR:        usize = 128;
    pub const RDEV_MINOR:        usize = 132;
    pub const DEV_MAJOR:         usize = 136;
    pub const DEV_MINOR:         usize = 140;
    pub const MNT_ID:            usize = 144;
    pub const DIO_MEM_ALIGN:     usize = 152;
    pub const DIO_OFFSET_ALIGN:  usize = 156;
    pub const SUBVOL:            usize = 160;
    pub const ATOMIC_WRITE_UNIT_MIN: usize = 168;
    pub const ATOMIC_WRITE_UNIT_MAX: usize = 172;
    pub const ATOMIC_WRITE_SEGMENTS_MAX: usize = 176;
    pub const DIO_READ_OFFSET_ALIGN: usize = 180;
    pub const ATOMIC_WRITE_UNIT_MAX_OPT: usize = 184;
    /// `__spare2[1]` @188, `__spare3[8]` @192..256 — memset-zero, never written.
    pub const SPARE3:            usize = 192;
}

/// `AT_*` bits `statx` understands.
pub const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
pub const AT_NO_AUTOMOUNT:     u32 = 0x800;
pub const AT_EMPTY_PATH:       u32 = 0x1000;
pub const AT_STATX_FORCE_SYNC: u32 = 0x2000;
pub const AT_STATX_DONT_SYNC:  u32 = 0x4000;
/// `AT_STATX_SYNC_TYPE` — the two-bit sync selector; BOTH bits set is EINVAL.
pub const AT_STATX_SYNC_TYPE:  u32 = AT_STATX_FORCE_SYNC | AT_STATX_DONT_SYNC;
/// The complete set `vfs_statx` accepts.
pub const STATX_VALID_FLAGS: u32 =
    AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_EMPTY_PATH | AT_STATX_SYNC_TYPE;

/// `STATX__RESERVED` — the ONE mask bit whose
/// use is rejected. Note the double underscore: there is no `STATX_RESERVED`.
pub const STATX__RESERVED: u32 = 0x8000_0000;
/// `STATX_MNT_ID` (`:216`) — `stx_mnt_id` holds the legacy reusable mount id.
pub const STATX_MNT_ID: u32 = 0x0000_1000;
/// `STATX_MNT_ID_UNIQUE` (`:218`) — `stx_mnt_id` holds the never-recycled id.
/// Mutually exclusive with [`STATX_MNT_ID`] in the RESULT mask.
pub const STATX_MNT_ID_UNIQUE: u32 = 0x0000_4000;
/// `STATX_CHANGE_COOKIE` — kernel-internal (nfsd).
/// Stripped from the REQUEST mask on entry and from `stx_mask` on the way out.
pub const STATX_CHANGE_COOKIE: u32 = 0x4000_0000;
/// `STATX_ATTR_MOUNT_ROOT` (`:254`) — the resolved path is its mount's root.
pub const STATX_ATTR_MOUNT_ROOT: u64 = 0x0000_2000;
/// `STATX_ATTR_CHANGE_MONOTONIC` — kernel-internal;
/// `cp_statx` strips it from `stx_attributes`.
pub const STATX_ATTR_CHANGE_MONOTONIC: u64 = 0x8000_0000_0000_0000;

/// Which `statx` entry path a call takes. Linux picks this in
/// `SYSCALL_DEFINE5(statx)` BEFORE any validation: with
/// `AT_EMPTY_PATH` and a NULL/empty pathname and a non-negative `dfd`, the call
/// becomes `fstat`-on-`dfd` and never walks a path.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum StatxEntry {
    /// `do_statx_fd(dfd, flags & ~AT_NO_AUTOMOUNT, ...)` — `AT_NO_AUTOMOUNT` is
    /// stripped, and NO unknown-flag rejection happens on this path.
    Fd,
    /// `do_statx(dfd, name, ...)` — the full ladder including the unknown-flag
    /// check in `vfs_statx`.
    Path,
}

/// Entry-path selection. `name_is_empty` is true when the
/// pathname pointer is NULL, or `AT_EMPTY_PATH` is set and the first byte is
/// `'\0'` (Linux `__getname_maybe_null`). # C: O(1)
pub fn statx_entry(dfd: i32, name_is_empty: bool) -> StatxEntry {
    if name_is_empty && dfd >= 0 { StatxEntry::Fd } else { StatxEntry::Path }
}

/// The `statx` input ladder in Linux's exact order, returning the effective
/// request mask on success.
///
/// `do_statx`/`do_statx_fd`:
///   1. `mask & STATX__RESERVED` → EINVAL
///   2. `(flags & AT_STATX_SYNC_TYPE) == AT_STATX_SYNC_TYPE` → EINVAL
///   3. `mask &= ~STATX_CHANGE_COOKIE` (silent, no error)
/// then, on the PATH entry only, `vfs_statx`:
///   4. `flags & ~STATX_VALID_FLAGS` → EINVAL
///
/// Step 4 is deliberately absent from the fd entry: `vfs_statx_fd` →
/// `vfs_statx_path` has no flag check, so `statx(fd, "", AT_EMPTY_PATH|0x40, …)`
/// SUCCEEDS on Linux. Rejecting it unconditionally — as the pre-fix slot did —
/// breaks the `fstat` emulation for any caller that passes a flag bit we have
/// not heard of yet. # C: O(1)
pub fn statx_validate(entry: StatxEntry, flags: u32, mask: u32) -> Result<u32, Errno> {
    if mask & STATX__RESERVED != 0 { return Err(Errno::Einval); }
    if flags & AT_STATX_SYNC_TYPE == AT_STATX_SYNC_TYPE { return Err(Errno::Einval); }
    if entry == StatxEntry::Path && flags & !STATX_VALID_FLAGS != 0 {
        return Err(Errno::Einval);
    }
    Ok(mask & !STATX_CHANGE_COOKIE)
}

/// Everything the encoder needs beyond the backend `Kstat`: the resolved mount
/// identity and the two path-scoped attribute facts `vfs_statx_path` adds.
#[derive(Copy, Clone, Debug, Default)]
pub struct StatxPathInfo {
    /// `real_mount(path->mnt)->mnt_id{,_unique}`. Oxide's `mnt_id` counter is
    /// monotonic and never recycled, so it satisfies BOTH Linux ids.
    pub mnt_id: u64,
    /// `path_mounted(path)` — the dentry is its mount's root.
    pub mount_root: bool,
    /// `MAJOR(stat->dev)` / `MINOR(stat->dev)` — the owning filesystem's
    /// `st_dev`, already split by the caller (the split lives in the gated
    /// namei helpers; keeping it out of here keeps this module hosted-testable).
    pub dev_major: u32,
    pub dev_minor: u32,
    /// `MAJOR(stat->rdev)` / `MINOR(stat->rdev)` — 0 for non-device inodes.
    pub rdev_major: u32,
    pub rdev_minor: u32,
}

/// `cp_statx`: render the resolved attributes into
/// the 256-byte wire struct. Every byte not assigned here is zero, matching
/// Linux's `memset(&tmp, 0, sizeof(tmp))` — including the four
/// `statx_timestamp.__reserved` words and the three `__spare` arrays.
///
/// `request_mask` selects between `STATX_MNT_ID` and `STATX_MNT_ID_UNIQUE`;
/// exactly one of them appears in `stx_mask`, never both. `STATX_CHANGE_COOKIE`
/// is stripped from `stx_mask` and `STATX_ATTR_CHANGE_MONOTONIC` from
/// `stx_attributes`, the only two filters Linux applies on the way out.
/// # C: O(1)
pub fn cp_statx(st: &Kstat, p: &StatxPathInfo, request_mask: u32) -> [u8; STATX_SIZE] {
    let mut b = [0u8; STATX_SIZE];
    let mnt_bit = if request_mask & STATX_MNT_ID_UNIQUE != 0 { STATX_MNT_ID_UNIQUE } else { STATX_MNT_ID };
    let mask = (st.result_mask | mnt_bit) & !STATX_CHANGE_COOKIE;
    put_u32(&mut b, off::MASK, mask);
    put_u32(&mut b, off::BLKSIZE, st.blksize);
    put_u64(&mut b, off::ATTRIBUTES,
        (st.attributes | if p.mount_root { STATX_ATTR_MOUNT_ROOT } else { 0 })
            & !STATX_ATTR_CHANGE_MONOTONIC);
    put_u32(&mut b, off::NLINK, st.nlink);
    put_u32(&mut b, off::UID, st.uid);
    put_u32(&mut b, off::GID, st.gid);
    put_u16(&mut b, off::MODE, st.mode as u16);
    put_u64(&mut b, off::INO, st.ino);
    put_u64(&mut b, off::SIZE, st.size);
    put_u64(&mut b, off::BLOCKS, st.blocks);
    put_u64(&mut b, off::ATTRIBUTES_MASK, st.attributes_mask | STATX_ATTR_MOUNT_ROOT);
    put_ts(&mut b, off::ATIME, st.atime);
    // `btime` is `None` when the backend stores no creation time. Linux leaves
    // `stx_btime` at its memset zero and clears `STATX_BTIME` in `stx_mask`
    // (the VFS already did the latter) — the zero is NOT an "absent" sentinel,
    // because epoch second 0 is a legal birth time that a `Some` may carry.
    put_ts(&mut b, off::BTIME, st.btime.unwrap_or(Timespec64::ZERO));
    put_ts(&mut b, off::CTIME, st.ctime);
    put_ts(&mut b, off::MTIME, st.mtime);
    put_u32(&mut b, off::RDEV_MAJOR, p.rdev_major);
    put_u32(&mut b, off::RDEV_MINOR, p.rdev_minor);
    put_u32(&mut b, off::DEV_MAJOR, p.dev_major);
    put_u32(&mut b, off::DEV_MINOR, p.dev_minor);
    put_u64(&mut b, off::MNT_ID, p.mnt_id);
    b
}

fn put_u16(b: &mut [u8; STATX_SIZE], o: usize, v: u16) { b[o..o + 2].copy_from_slice(&v.to_ne_bytes()); }
fn put_u32(b: &mut [u8; STATX_SIZE], o: usize, v: u32) { b[o..o + 4].copy_from_slice(&v.to_ne_bytes()); }
fn put_u64(b: &mut [u8; STATX_SIZE], o: usize, v: u64) { b[o..o + 8].copy_from_slice(&v.to_ne_bytes()); }

/// One `struct statx_timestamp`: `__s64 tv_sec; __u32 tv_nsec; __s32 __reserved`.
/// The reserved word stays zero.
///
/// Written straight from the `timespec64` fields. The pre-fix form derived both
/// halves from an unsigned ns scalar, so a pre-1970 stamp read back as
/// `tv_nsec ~= 4.29e9` — outside the `[0, 1e9)` the field is defined over — and
/// no stamp before 1677 or after 2262 was representable at all. # C: O(1)
fn put_ts(b: &mut [u8; STATX_SIZE], o: usize, t: Timespec64) {
    b[o..o + 8].copy_from_slice(&t.sec.to_ne_bytes());
    b[o + 8..o + 12].copy_from_slice(&t.nsec.to_ne_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use vfs::getattr::{STATX_ATIME, STATX_ATTR_APPEND, STATX_ATTR_AUTOMOUNT, STATX_ATTR_DAX,
        STATX_ATTR_IMMUTABLE, STATX_BASIC_STATS, STATX_BTIME};

    fn rd_u32(b: &[u8; STATX_SIZE], o: usize) -> u32 { u32::from_ne_bytes(b[o..o + 4].try_into().unwrap()) }
    fn rd_u64(b: &[u8; STATX_SIZE], o: usize) -> u64 { u64::from_ne_bytes(b[o..o + 8].try_into().unwrap()) }
    fn rd_u16(b: &[u8; STATX_SIZE], o: usize) -> u16 { u16::from_ne_bytes(b[o..o + 2].try_into().unwrap()) }
    fn rd_i64(b: &[u8; STATX_SIZE], o: usize) -> i64 { i64::from_ne_bytes(b[o..o + 8].try_into().unwrap()) }

    fn sample() -> Kstat {
        Kstat {
            ino: 0x1122_3344_5566_7788, mode: 0o100_644, nlink: 3, uid: 1000, gid: 1001,
            rdev: 0, size: 0xdead_beef, blksize: 4096, blocks: 24,
            atime: Timespec64 { sec: 1_500_000_000, nsec: 123_456_789 },
            mtime: Timespec64 { sec: 1_600_000_000, nsec: 1 },
            ctime: Timespec64 { sec: 1_700_000_000, nsec: 999_999_999 },
            btime: Some(Timespec64::from_secs(1_400_000_000)),
            fsid: 7, change_cookie: 0,
            result_mask: STATX_BASIC_STATS | STATX_BTIME,
            attributes: STATX_ATTR_IMMUTABLE,
            attributes_mask: STATX_ATTR_IMMUTABLE | STATX_ATTR_APPEND | STATX_ATTR_AUTOMOUNT | STATX_ATTR_DAX,
        }
    }

    /// The wire layout is 256 bytes with the exact `struct statx` UAPI
    /// offsets, and the offsets are the SAME on both arches. A shifted
    /// timestamp block silently clobbers `stx_rdev_major`, which is how the
    /// pre-fix layout bug presented. # C: O(1)
    #[test]
    fn wire_layout_offsets_and_size() {
        assert_eq!(STATX_SIZE, 256);
        assert_eq!((off::MASK, off::BLKSIZE, off::ATTRIBUTES), (0, 4, 8));
        assert_eq!((off::NLINK, off::UID, off::GID, off::MODE), (16, 20, 24, 28));
        assert_eq!((off::INO, off::SIZE, off::BLOCKS, off::ATTRIBUTES_MASK), (32, 40, 48, 56));
        assert_eq!((off::ATIME, off::BTIME, off::CTIME, off::MTIME), (64, 80, 96, 112));
        assert_eq!((off::RDEV_MAJOR, off::RDEV_MINOR), (128, 132));
        assert_eq!((off::DEV_MAJOR, off::DEV_MINOR, off::MNT_ID), (136, 140, 144));
        assert_eq!((off::DIO_MEM_ALIGN, off::DIO_OFFSET_ALIGN, off::SUBVOL), (152, 156, 160));
        assert_eq!(off::SPARE3, 192);
        // Every offset must leave its field inside the struct.
        assert!(off::SPARE3 + 64 == STATX_SIZE);
    }

    /// Field-by-field round trip, plus the invariant that every byte Linux
    /// leaves to its `memset` is zero here: `__spare0`@30, the four timestamp
    /// `__reserved` words, `__spare2`@188 and `__spare3`@192..256. # C: O(1)
    #[test]
    fn cp_statx_fields_and_zeroed_spares() {
        let st = sample();
        let p = StatxPathInfo { mnt_id: 42, mount_root: false, dev_major: 3, dev_minor: 0, ..StatxPathInfo::default() };
        let b = cp_statx(&st, &p, STATX_BASIC_STATS);
        assert_eq!(rd_u32(&b, off::MASK), STATX_BASIC_STATS | STATX_BTIME | STATX_MNT_ID);
        assert_eq!(rd_u32(&b, off::BLKSIZE), 4096);
        assert_eq!(rd_u32(&b, off::NLINK), 3);
        assert_eq!(rd_u32(&b, off::UID), 1000);
        assert_eq!(rd_u32(&b, off::GID), 1001);
        assert_eq!(rd_u16(&b, off::MODE), 0o100_644);
        assert_eq!(rd_u64(&b, off::INO), 0x1122_3344_5566_7788);
        assert_eq!(rd_u64(&b, off::SIZE), 0xdead_beef);
        assert_eq!(rd_u64(&b, off::BLOCKS), 24);
        assert_eq!(rd_u64(&b, off::MNT_ID), 42);
        assert_eq!(rd_i64(&b, off::ATIME), 1_500_000_000);
        assert_eq!(rd_u32(&b, off::ATIME + 8), 123_456_789);
        assert_eq!(rd_i64(&b, off::BTIME), 1_400_000_000);
        assert_eq!(rd_i64(&b, off::CTIME), 1_700_000_000);
        assert_eq!(rd_u32(&b, off::CTIME + 8), 999_999_999);
        assert_eq!(rd_i64(&b, off::MTIME), 1_600_000_000);
        // __spare0 (2 B @30), timestamp __reserved (4 B each), __spare2, __spare3.
        assert_eq!(&b[30..32], &[0, 0]);
        for ts in [off::ATIME, off::BTIME, off::CTIME, off::MTIME] {
            assert_eq!(&b[ts + 12..ts + 16], &[0, 0, 0, 0], "ts __reserved @{ts}");
        }
        assert_eq!(&b[188..192], &[0, 0, 0, 0]);
        assert!(b[off::SPARE3..STATX_SIZE].iter().all(|&x| x == 0));
        // Nothing we do not fill is nonzero: dio/subvol/atomic-write stay 0.
        assert_eq!(rd_u32(&b, off::DIO_MEM_ALIGN), 0);
        assert_eq!(rd_u64(&b, off::SUBVOL), 0);
    }

    /// `stx_mask` reports exactly what was FILLED, never what was requested.
    /// A caller asking for only `STATX_INO` still gets the whole basic set;
    /// a caller asking for `STATX_BTIME` on an inode with no creation time
    /// gets the bit CLEAR, not a fabricated 1970 birth time. # C: O(1)
    #[test]
    fn result_mask_is_what_was_filled_not_what_was_asked() {
        let p = StatxPathInfo::default();
        let full = cp_statx(&sample(), &p, 0x100 /* STATX_INO only */);
        assert_eq!(rd_u32(&full, off::MASK) & STATX_BASIC_STATS, STATX_BASIC_STATS,
            "basic stats are unconditional");
        let mut no_btime = sample();
        no_btime.result_mask = STATX_BASIC_STATS;
        no_btime.btime = None;
        let b = cp_statx(&no_btime, &p, STATX_BTIME | STATX_BASIC_STATS);
        assert_eq!(rd_u32(&b, off::MASK) & STATX_BTIME, 0, "unknown btime must not be claimed");
        assert_eq!(rd_i64(&b, off::BTIME), 0);
        assert_eq!(rd_u32(&b, off::BTIME + 8), 0);
        // A noatime mount clears ATIME from the mask even though the field is copied.
        let mut noatime = sample();
        noatime.result_mask &= !STATX_ATIME;
        let b = cp_statx(&noatime, &p, STATX_BASIC_STATS);
        assert_eq!(rd_u32(&b, off::MASK) & STATX_ATIME, 0);
    }

    /// `STATX_MNT_ID` and `STATX_MNT_ID_UNIQUE` are mutually exclusive in the
    /// result mask, selected by the REQUEST mask.
    /// # C: O(1)
    #[test]
    fn mnt_id_bits_are_mutually_exclusive() {
        let p = StatxPathInfo { mnt_id: 9, ..StatxPathInfo::default() };
        let plain = rd_u32(&cp_statx(&sample(), &p, STATX_BASIC_STATS), off::MASK);
        assert_eq!(plain & STATX_MNT_ID, STATX_MNT_ID);
        assert_eq!(plain & STATX_MNT_ID_UNIQUE, 0);
        let uniq = rd_u32(&cp_statx(&sample(), &p, STATX_MNT_ID_UNIQUE), off::MASK);
        assert_eq!(uniq & STATX_MNT_ID_UNIQUE, STATX_MNT_ID_UNIQUE);
        assert_eq!(uniq & STATX_MNT_ID, 0);
    }

    /// `STATX_ATTR_*` are only claimed through `stx_attributes_mask`; the
    /// kernel-internal `STATX_ATTR_CHANGE_MONOTONIC` is stripped from
    /// `stx_attributes`, and `MOUNT_ROOT` is always
    /// advertised as known. # C: O(1)
    #[test]
    fn attributes_and_attribute_mask_contract() {
        let mut st = sample();
        st.attributes |= STATX_ATTR_CHANGE_MONOTONIC;
        let p = StatxPathInfo { mount_root: true, ..StatxPathInfo::default() };
        let b = cp_statx(&st, &p, STATX_BASIC_STATS);
        let attrs = rd_u64(&b, off::ATTRIBUTES);
        let amask = rd_u64(&b, off::ATTRIBUTES_MASK);
        assert_eq!(attrs & STATX_ATTR_CHANGE_MONOTONIC, 0, "kernel-internal bit must not leak");
        assert_eq!(attrs & STATX_ATTR_IMMUTABLE, STATX_ATTR_IMMUTABLE);
        assert_eq!(attrs & STATX_ATTR_MOUNT_ROOT, STATX_ATTR_MOUNT_ROOT);
        assert_eq!(amask & STATX_ATTR_MOUNT_ROOT, STATX_ATTR_MOUNT_ROOT);
        // Only attributes inside the mask are meaningful; nothing outside it is set.
        assert_eq!(attrs & !amask, 0, "every reported attribute must be inside the mask");
        // A non-mount-root path must NOT claim the bit.
        let b = cp_statx(&sample(), &StatxPathInfo::default(), STATX_BASIC_STATS);
        assert_eq!(rd_u64(&b, off::ATTRIBUTES) & STATX_ATTR_MOUNT_ROOT, 0);
    }

    /// Validation order and the fd-vs-path asymmetry.
    /// The reserved-mask check beats the sync-type check, and the
    /// unknown-flag check exists ONLY on the path entry. # C: O(1)
    #[test]
    fn validation_ladder_and_fd_path_asymmetry() {
        // Reserved mask bit → EINVAL on both entries, and it wins over a
        // simultaneously-invalid sync type.
        for e in [StatxEntry::Fd, StatxEntry::Path] {
            assert_eq!(statx_validate(e, 0, STATX__RESERVED), Err(Errno::Einval));
            assert_eq!(statx_validate(e, AT_STATX_SYNC_TYPE, STATX__RESERVED), Err(Errno::Einval));
            assert_eq!(statx_validate(e, AT_STATX_SYNC_TYPE, 0), Err(Errno::Einval));
            // Either sync bit alone is fine.
            assert!(statx_validate(e, AT_STATX_FORCE_SYNC, 0).is_ok());
            assert!(statx_validate(e, AT_STATX_DONT_SYNC, 0).is_ok());
        }
        // Unknown flag bit: EINVAL on the path entry, ACCEPTED on the fd entry.
        assert_eq!(statx_validate(StatxEntry::Path, 0x40, 0), Err(Errno::Einval));
        assert_eq!(statx_validate(StatxEntry::Fd, 0x40, 0), Ok(0));
        assert_eq!(statx_validate(StatxEntry::Fd, 0xffff_7fff & !AT_STATX_SYNC_TYPE, 0), Ok(0));
        // Every valid flag is accepted on the path entry.
        for f in [0, AT_SYMLINK_NOFOLLOW, AT_NO_AUTOMOUNT, AT_EMPTY_PATH,
                  AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_EMPTY_PATH | AT_STATX_FORCE_SYNC] {
            assert!(statx_validate(StatxEntry::Path, f, 0).is_ok(), "flags {f:#x}");
        }
        // STATX_CHANGE_COOKIE is silently cleared, never an error.
        assert_eq!(statx_validate(StatxEntry::Path, 0, STATX_CHANGE_COOKIE | 0x100), Ok(0x100));
    }

    /// The silent-corruption case the split pair fixes. `struct statx_timestamp`
    /// declares `__s64 tv_sec; __u32 tv_nsec`, so a pre-1970 stamp needs a
    /// NEGATIVE second with a NON-NEGATIVE nanosecond. Deriving both halves
    /// from an unsigned ns scalar could not do that: `%` on the wrapped value
    /// produced a `tv_nsec` near 4.29e9, far outside `[0, 1e9)`, and any stamp
    /// outside 1677..2262 was unrepresentable. # C: O(1)
    #[test]
    fn pre_1970_and_out_of_ns_range_timestamps_are_exact() {
        let mut st = sample();
        st.atime = Timespec64 { sec: -2, nsec: 500_000_000 };
        st.mtime = Timespec64 { sec: -1_000_000, nsec: 0 };
        // Year 2446 — ext4's own `s_time_max`, which overflows an i64 of ns.
        st.ctime = Timespec64 { sec: 15_032_385_535, nsec: 999_999_999 };
        st.btime = Some(Timespec64 { sec: i64::MIN, nsec: 1 });
        let b = cp_statx(&st, &StatxPathInfo::default(), STATX_BASIC_STATS);
        assert_eq!(rd_i64(&b, off::ATIME), -2);
        assert_eq!(rd_u32(&b, off::ATIME + 8), 500_000_000);
        assert_eq!(rd_i64(&b, off::MTIME), -1_000_000);
        assert_eq!(rd_u32(&b, off::MTIME + 8), 0);
        assert_eq!(rd_i64(&b, off::CTIME), 15_032_385_535);
        assert_eq!(rd_u32(&b, off::CTIME + 8), 999_999_999);
        assert_eq!(rd_i64(&b, off::BTIME), i64::MIN);
        assert_eq!(rd_u32(&b, off::BTIME + 8), 1);
        // Every `tv_nsec` stays inside the field's defined range.
        for ts in [off::ATIME, off::BTIME, off::CTIME, off::MTIME] {
            assert!(rd_u32(&b, ts + 8) < 1_000_000_000, "tv_nsec out of range @{ts}");
            assert_eq!(&b[ts + 12..ts + 16], &[0, 0, 0, 0]);
        }
    }

    /// Epoch second 0 is a LEGAL birth time, not the "no btime" sentinel — the
    /// absence signal is `btime: None` plus a clear `STATX_BTIME` in
    /// `result_mask`. A `Some(ZERO)` must still be copied and still claim the
    /// bit. # C: O(1)
    #[test]
    fn epoch_btime_is_a_real_value_not_an_absent_sentinel() {
        let mut st = sample();
        st.btime = Some(Timespec64::ZERO);
        let b = cp_statx(&st, &StatxPathInfo::default(), STATX_BTIME | STATX_BASIC_STATS);
        assert_eq!(rd_u32(&b, off::MASK) & STATX_BTIME, STATX_BTIME,
            "a 1970 birth time is still a known birth time");
        assert_eq!(rd_i64(&b, off::BTIME), 0);
        // And `None` writes the same zeros WITHOUT the bit — the mask is what
        // distinguishes them, never the value.
        st.btime = None;
        st.result_mask &= !STATX_BTIME;
        let b = cp_statx(&st, &StatxPathInfo::default(), STATX_BTIME | STATX_BASIC_STATS);
        assert_eq!(rd_u32(&b, off::MASK) & STATX_BTIME, 0);
        assert_eq!(rd_i64(&b, off::BTIME), 0);
        assert_eq!(rd_u32(&b, off::BTIME + 8), 0);
    }

    /// Entry selection: `AT_EMPTY_PATH` + empty/NULL name + `dfd >= 0` is the
    /// `fstat` emulation; `AT_FDCWD` (-100) with an empty name is NOT.
    /// # C: O(1)
    #[test]
    fn entry_selection_matches_syscall_dispatch() {
        assert_eq!(statx_entry(3, true), StatxEntry::Fd);
        assert_eq!(statx_entry(0, true), StatxEntry::Fd);
        assert_eq!(statx_entry(-100, true), StatxEntry::Path, "AT_FDCWD walks the path");
        assert_eq!(statx_entry(-1, true), StatxEntry::Path);
        assert_eq!(statx_entry(3, false), StatxEntry::Path);
    }
}
