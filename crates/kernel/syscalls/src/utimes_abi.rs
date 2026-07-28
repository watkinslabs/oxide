// `struct timeval[2]` decode + target selection for the utimes family —
// Linux `fs/utimes.c` `do_futimesat` (168-194), `do_utimes` (134-140) and
// `do_utimes_fd` (108-117).
//
// Ungated so the microsecond validation and the errno ORDER are reachable
// from the hosted suite; the slot files are `#![cfg(target_os =
// "oxide-kernel")]` and a `#[cfg(test)] mod tests` inside one compiles out
// silently (CLAUDE.md phantom-test rule).
//
// `futimesat(2)` (261) and `utimes(2)` (235) are the SAME decode: Linux
// implements `sys_utimes` as `do_futimesat(AT_FDCWD, filename, utimes)`
// (fs/utimes.c:203-207). One decode here, two thin slots — routing 261 at
// `sys_utimensat` instead read a `timeval[2]` as a `timespec[2]`, so every
// microsecond field landed in a nanosecond field (a 0.5 s atime became
// 0.0005 s) and the caller's fourth register was read as `flags`.

use syscall::errno::Errno;
use vfs::Timespec64;

/// `AT_FDCWD`.
pub const AT_FDCWD: i32 = -100;
/// `sizeof(struct __kernel_old_timeval)` on a 64-bit arch: two `i64`.
pub const TIMEVAL_BYTES: usize = 16;
/// `sizeof(struct __kernel_old_timeval[2])` — what `copy_from_user` reads.
pub const TIMEVAL_PAIR_BYTES: usize = 32;
/// `sizeof(struct utimbuf)` — `time_t actime; time_t modtime`.
pub const UTIMBUF_BYTES: usize = 16;
/// Scale constants are owned by `vfs::timespec`, the module that owns the
/// timestamp type; re-exported rather than re-declared so there is one table.
pub use vfs::timespec::{NSEC_PER_USEC, USEC_PER_SEC};

/// Decoded access/modification times, in the `timespec64` pair `vfs::Iattr`
/// carries. `sec` is SIGNED: a pre-1970 stamp is an ordinary value here.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Times {
    pub atime: Timespec64,
    pub mtime: Timespec64,
}

/// Which object `do_utimes` acts on (`fs/utimes.c:137-139`).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum UtimesTarget {
    /// `filename == NULL && dfd != AT_FDCWD` — operate on the open fd.
    Fd(i32),
    /// Everything else, including `AT_FDCWD` with a NULL filename, which goes
    /// to the path lookup and fails there with EFAULT.
    Path,
}

/// `do_utimes`' dispatch rule. A NULL filename is an fd operation ONLY when
/// `dfd` is a real descriptor: `futimesat(AT_FDCWD, NULL, t)` is a path lookup
/// of a NULL name and therefore EFAULT, not EBADF on fd -100.
/// # C: O(1)
pub const fn utimes_target(dfd: i32, path_is_null: bool) -> UtimesTarget {
    if path_is_null && dfd != AT_FDCWD { UtimesTarget::Fd(dfd) } else { UtimesTarget::Path }
}

/// `do_utimes_fd`: the fd form takes no flags at all (`fs/utimes.c:110-111`),
/// so `utimensat(fd, NULL, times, AT_SYMLINK_NOFOLLOW)` is EINVAL even though
/// the same flag is legal on the path form.
/// # C: O(1)
pub fn check_fd_form_flags(flags: u64) -> Result<(), Errno> {
    if flags != 0 { return Err(Errno::Einval); }
    Ok(())
}

/// Read one native-endian `i64` out of a copied-in payload. # C: O(1)
fn field(raw: &[u8], off: usize) -> i64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&raw[off..off + 8]);
    i64::from_ne_bytes(b)
}

/// Decode a `struct timeval[2]` payload (`do_futimesat`, `fs/utimes.c:174-191`).
///
/// Linux validates `tv_usec` against `[0, 1000000)` for BOTH slots before any
/// path lookup, precisely so a value that would be lost in the `* 1000`
/// widening is caught — and so `UTIME_NOW`/`UTIME_OMIT`, which are legal only
/// for `utimensat`, are rejected here rather than silently honoured.
///
/// `tv_sec` is NOT range-checked: `do_futimesat` copies it straight into
/// `tstimes[i].tv_sec` (`fs/utimes.c:187-190`), so a pre-1970 stamp is legal
/// and is what `tar`/`rsync`/`cp -p` replay from an old archive. An out-of-
/// window second is pinned by `timestamp_truncate` at the superblock boundary
/// (`fs/inode.c` `timestamp_truncate`), never rejected here.
/// # C: O(1)
pub fn decode_timeval_pair(raw: &[u8; TIMEVAL_PAIR_BYTES]) -> Result<Times, Errno> {
    let (asec, ausec) = (field(raw, 0), field(raw, 8));
    let (msec, musec) = (field(raw, TIMEVAL_BYTES), field(raw, TIMEVAL_BYTES + 8));
    if ausec >= USEC_PER_SEC || ausec < 0 || musec >= USEC_PER_SEC || musec < 0 {
        return Err(Errno::Einval);
    }
    Ok(Times {
        atime: Timespec64::new(asec, (ausec * NSEC_PER_USEC) as u32),
        mtime: Timespec64::new(msec, (musec * NSEC_PER_USEC) as u32),
    })
}

/// Decode `struct utimbuf { time_t actime; time_t modtime; }`
/// (`SYSCALL_DEFINE2(utime)`, `fs/utimes.c:208-221`). Both fields land in
/// `tv_sec` with `tv_nsec = 0` and NO validation whatsoever — `utime(2)` has
/// no sub-second field to get wrong and no `UTIME_*` sentinels, so a negative
/// `actime`/`modtime` is an ordinary pre-1970 request. # C: O(1)
pub fn decode_utimbuf(raw: &[u8; UTIMBUF_BYTES]) -> Times {
    Times {
        atime: Timespec64::from_secs(field(raw, 0)),
        mtime: Timespec64::from_secs(field(raw, 8)),
    }
}

/// `vfs::Iattr` for an explicit (atime, mtime) pair — both times supplied, so
/// both carry `ATTR_*_SET` and the owner/CAP_FOWNER rule applies
/// (`vfs_utimes`, `fs/utimes.c:44-53`). # C: O(1)
pub fn iattr_from_times(times: Times, now: Timespec64) -> vfs::Iattr {
    vfs::Iattr {
        valid: vfs::ATTR_ATIME | vfs::ATTR_MTIME | vfs::ATTR_ATIME_SET | vfs::ATTR_MTIME_SET,
        ctime: now,
        atime: times.atime,
        mtime: times.mtime,
        ..Default::default()
    }
}

/// `vfs::Iattr` for `times == NULL` — Linux `ATTR_TOUCH` (`fs/utimes.c:63`):
/// both times become now and write permission suffices. # C: O(1)
pub fn iattr_touch(now: Timespec64) -> vfs::Iattr {
    vfs::Iattr {
        valid: vfs::ATTR_ATIME | vfs::ATTR_MTIME,
        ctime: now,
        atime: now,
        mtime: now,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(asec: i64, ausec: i64, msec: i64, musec: i64) -> [u8; TIMEVAL_PAIR_BYTES] {
        let mut b = [0u8; TIMEVAL_PAIR_BYTES];
        b[0..8].copy_from_slice(&asec.to_ne_bytes());
        b[8..16].copy_from_slice(&ausec.to_ne_bytes());
        b[16..24].copy_from_slice(&msec.to_ne_bytes());
        b[24..32].copy_from_slice(&musec.to_ne_bytes());
        b
    }

    #[test]
    fn microseconds_widen_by_a_thousand_not_by_one() {
        // The bug routing 261 at `sys_utimensat` put tv_usec straight into
        // tv_nsec: half a second became half a millisecond.
        let t = decode_timeval_pair(&pair(1, 500_000, 2, 250_000)).unwrap();
        assert_eq!(t.atime, Timespec64 { sec: 1, nsec: 500_000_000 });
        assert_eq!(t.mtime, Timespec64 { sec: 2, nsec: 250_000_000 });
    }

    /// `do_futimesat` never range-checks `tv_sec` (`fs/utimes.c:183-190` tests
    /// `tv_usec` only), so `utimes`/`futimesat` with a pre-1970 second SUCCEED
    /// and carry the negative through. The pre-fix decode returned EINVAL
    /// because `vfs::Iattr` was unsigned nanoseconds. # C: O(1)
    #[test]
    fn negative_tv_sec_is_accepted_and_carried_signed() {
        let t = decode_timeval_pair(&pair(-1_000_000, 0, -2, 0)).unwrap();
        assert_eq!(t.atime, Timespec64 { sec: -1_000_000, nsec: 0 });
        assert_eq!(t.mtime, Timespec64 { sec: -2, nsec: 0 });
        // A negative second with a sub-second part stays a POSITIVE tv_nsec:
        // -2.5 s is `{sec:-2, nsec:500_000_000}` counting FORWARD from -2 s,
        // exactly as `tstimes[i].tv_sec = times[i].tv_sec; tv_nsec = 1000*usec`
        // builds it — NOT the euclidean floor of a signed ns scalar.
        let t = decode_timeval_pair(&pair(-2, 500_000, i64::MIN, 999_999)).unwrap();
        assert_eq!(t.atime, Timespec64 { sec: -2, nsec: 500_000_000 });
        assert_eq!(t.mtime, Timespec64 { sec: i64::MIN, nsec: 999_999_000 });
    }

    /// `utime(2)` validates nothing at all (`fs/utimes.c:212-219`): both fields
    /// are whole seconds into `tv_sec`, `tv_nsec = 0`. # C: O(1)
    #[test]
    fn utimbuf_decodes_signed_seconds_without_validation() {
        let mut b = [0u8; UTIMBUF_BYTES];
        b[0..8].copy_from_slice(&(-1_000_000i64).to_ne_bytes());
        b[8..16].copy_from_slice(&(i64::MIN).to_ne_bytes());
        let t = decode_utimbuf(&b);
        assert_eq!(t.atime, Timespec64 { sec: -1_000_000, nsec: 0 });
        assert_eq!(t.mtime, Timespec64 { sec: i64::MIN, nsec: 0 });
    }

    /// The explicit-times form carries `ATTR_*_SET` (owner/CAP_FOWNER); the
    /// NULL form does not (write permission suffices). # C: O(1)
    #[test]
    fn iattr_shape_distinguishes_explicit_times_from_touch() {
        let now = Timespec64 { sec: 1_700_000_000, nsec: 7 };
        let t = Times { atime: Timespec64 { sec: -5, nsec: 1 }, mtime: Timespec64::from_secs(-6) };
        let ia = iattr_from_times(t, now);
        assert_eq!(ia.valid,
            vfs::ATTR_ATIME | vfs::ATTR_MTIME | vfs::ATTR_ATIME_SET | vfs::ATTR_MTIME_SET);
        assert_eq!(ia.atime, t.atime);
        assert_eq!(ia.mtime, t.mtime);
        assert_eq!(ia.ctime, now);
        let ia = iattr_touch(now);
        assert_eq!(ia.valid, vfs::ATTR_ATIME | vfs::ATTR_MTIME);
        assert_eq!((ia.atime, ia.mtime, ia.ctime), (now, now, now));
    }

    #[test]
    fn usec_at_or_above_one_second_is_einval() {
        assert_eq!(decode_timeval_pair(&pair(0, 1_000_000, 0, 0)), Err(Errno::Einval));
        assert_eq!(decode_timeval_pair(&pair(0, 0, 0, 1_000_000)), Err(Errno::Einval));
        assert!(decode_timeval_pair(&pair(0, 999_999, 0, 999_999)).is_ok());
    }

    #[test]
    fn negative_usec_is_einval() {
        assert_eq!(decode_timeval_pair(&pair(0, -1, 0, 0)), Err(Errno::Einval));
        assert_eq!(decode_timeval_pair(&pair(0, 0, 0, -1)), Err(Errno::Einval));
    }

    #[test]
    fn utime_now_and_utime_omit_are_not_accepted_here() {
        // 0x3fffffff / 0x3ffffffe are `utimensat` sentinels. `do_futimesat`
        // catches them with the same range test, which is exactly why the
        // check is duplicated out of `vfs_utimes` in Linux.
        assert_eq!(decode_timeval_pair(&pair(0, 0x3fff_ffff, 0, 0)), Err(Errno::Einval));
        assert_eq!(decode_timeval_pair(&pair(0, 0, 0, 0x3fff_fffe)), Err(Errno::Einval));
    }

    #[test]
    fn a_null_name_is_an_fd_operation_only_with_a_real_dirfd() {
        assert_eq!(utimes_target(3, true), UtimesTarget::Fd(3));
        // AT_FDCWD + NULL name is a path lookup of NULL -> EFAULT, not EBADF.
        assert_eq!(utimes_target(AT_FDCWD, true), UtimesTarget::Path);
        assert_eq!(utimes_target(3, false), UtimesTarget::Path);
        assert_eq!(utimes_target(AT_FDCWD, false), UtimesTarget::Path);
    }

    #[test]
    fn the_fd_form_rejects_every_flag() {
        assert_eq!(check_fd_form_flags(0), Ok(()));
        // AT_SYMLINK_NOFOLLOW is legal on the path form and illegal here.
        assert_eq!(check_fd_form_flags(0x100), Err(Errno::Einval));
    }
}
