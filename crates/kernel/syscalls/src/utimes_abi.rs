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

/// `AT_FDCWD`.
pub const AT_FDCWD: i32 = -100;
/// `sizeof(struct __kernel_old_timeval)` on a 64-bit arch: two `i64`.
pub const TIMEVAL_BYTES: usize = 16;
/// `sizeof(struct __kernel_old_timeval[2])` — what `copy_from_user` reads.
pub const TIMEVAL_PAIR_BYTES: usize = 32;
/// Upper bound `do_futimesat` enforces on `tv_usec`.
pub const USEC_PER_SEC: i64 = 1_000_000;
const NSEC_PER_USEC: u64 = 1_000;
const NSEC_PER_SEC: u64 = 1_000_000_000;

/// Decoded access/modification times, in the unsigned nanoseconds
/// `vfs::Iattr` carries.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TimesNs {
    pub atime_ns: u64,
    pub mtime_ns: u64,
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

/// Decode a `struct timeval[2]` payload (`do_futimesat`, `fs/utimes.c:174-191`).
///
/// Linux validates `tv_usec` against `[0, 1000000)` for BOTH slots before any
/// path lookup, precisely so a value that would be lost in the `* 1000`
/// widening is caught — and so `UTIME_NOW`/`UTIME_OMIT`, which are legal only
/// for `utimensat`, are rejected here rather than silently honoured.
///
/// Divergence, deliberate and single-sourced: Linux does NOT bound `tv_sec`,
/// so a negative (pre-1970) timestamp is accepted there. `vfs::Iattr` carries
/// unsigned nanoseconds repo-wide, which cannot represent one, so a negative
/// `tv_sec` is refused with EINVAL rather than wrapped into a far-future time.
/// The whole utime/utimes/utimensat family shares this limit.
/// # C: O(1)
pub fn decode_timeval_pair(raw: &[u8; TIMEVAL_PAIR_BYTES]) -> Result<TimesNs, Errno> {
    let field = |off: usize| {
        let mut b = [0u8; 8];
        b.copy_from_slice(&raw[off..off + 8]);
        i64::from_ne_bytes(b)
    };
    let (asec, ausec) = (field(0), field(8));
    let (msec, musec) = (field(TIMEVAL_BYTES), field(TIMEVAL_BYTES + 8));
    if ausec >= USEC_PER_SEC || ausec < 0 || musec >= USEC_PER_SEC || musec < 0 {
        return Err(Errno::Einval);
    }
    if asec < 0 || msec < 0 { return Err(Errno::Einval); }
    Ok(TimesNs {
        atime_ns: (asec as u64).saturating_mul(NSEC_PER_SEC)
            .saturating_add((ausec as u64) * NSEC_PER_USEC),
        mtime_ns: (msec as u64).saturating_mul(NSEC_PER_SEC)
            .saturating_add((musec as u64) * NSEC_PER_USEC),
    })
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
        assert_eq!(t.atime_ns, 1_500_000_000);
        assert_eq!(t.mtime_ns, 2_250_000_000);
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
