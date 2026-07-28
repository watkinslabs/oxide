// `utimensat(2)` ABI: the `struct __kernel_timespec[2]` decode, the
// `UTIME_NOW`/`UTIME_OMIT` resolution, the flag ladder, and the `vfs::Iattr`
// assembly — Linux `SYSCALL_DEFINE4(utimensat)` / `do_utimes` / `vfs_utimes`
// (`fs/utimes.c:13-19, 21-80, 108-140, 141-160`).
//
// Ungated (no `target_os = "oxide-kernel"`) so the sentinel resolution and the
// errno ORDER are reachable from the hosted suite: the slot file is
// `#![cfg(target_os = "oxide-kernel")]` and a `#[cfg(test)] mod tests` inside
// one compiles out silently (CLAUDE.md phantom-test rule).

use syscall::errno::Errno;
use vfs::Timespec64;
use vfs::timespec::NSEC_PER_SEC;

/// `UTIME_NOW` (`include/uapi/linux/stat.h`) — "set this field to the current
/// time"; write permission suffices when BOTH fields carry it.
pub const UTIME_NOW: i64 = 0x3fff_ffff;
/// `UTIME_OMIT` — "leave this field alone".
pub const UTIME_OMIT: i64 = 0x3fff_fffe;
/// `sizeof(struct __kernel_timespec)` — `__s64 tv_sec; __s64 tv_nsec`.
pub const TIMESPEC_BYTES: usize = 16;
/// `sizeof(struct __kernel_timespec[2])` — what `get_timespec64` reads twice.
pub const TIMESPEC_PAIR_BYTES: usize = 32;

/// One `timespec` exactly as userspace wrote it, BEFORE sentinel resolution:
/// `tv_nsec` is still `i64` because `UTIME_NOW`/`UTIME_OMIT` live in it.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RawTimespec {
    pub sec: i64,
    pub nsec: i64,
}

/// A resolved `times[i]` slot (`vfs_utimes`, `fs/utimes.c:41-53`).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TimeSlot {
    /// `UTIME_OMIT` — clear `ATTR_ATIME`/`ATTR_MTIME`, leave the field alone.
    Omit,
    /// `UTIME_NOW` — set the field, WITHOUT `ATTR_*_SET`.
    Now,
    /// A specific instant — set the field WITH `ATTR_*_SET`, which is what
    /// makes `setattr_prepare` demand owner/CAP_FOWNER.
    Set(Timespec64),
}

/// Split a copied-in `__kernel_timespec[2]` payload into its raw fields.
/// No validation: `SYSCALL_DEFINE4(utimensat)` copies first and only then
/// tests the sentinels (`fs/utimes.c:145-156`). # C: O(1)
pub fn decode_timespec_pair(raw: &[u8; TIMESPEC_PAIR_BYTES]) -> [RawTimespec; 2] {
    let field = |off: usize| {
        let mut b = [0u8; 8];
        b.copy_from_slice(&raw[off..off + 8]);
        i64::from_ne_bytes(b)
    };
    [RawTimespec { sec: field(0), nsec: field(8) },
     RawTimespec { sec: field(TIMESPEC_BYTES), nsec: field(TIMESPEC_BYTES + 8) }]
}

/// `SYSCALL_DEFINE4(utimensat)`'s "Nothing to do, we must not even check the
/// path" short-circuit (`fs/utimes.c:153-156`): both slots `UTIME_OMIT` returns
/// 0 BEFORE `do_utimes`, so neither the flag check nor the lookup runs and a
/// nonexistent pathname still succeeds. # C: O(1)
pub fn both_omit(t: &[RawTimespec; 2]) -> bool {
    t[0].nsec == UTIME_OMIT && t[1].nsec == UTIME_OMIT
}

/// `nsec_valid` (`fs/utimes.c:13-19`) — the ONLY range check the utimensat
/// family applies. `tv_sec` is deliberately absent: a pre-1970 or far-future
/// second is legal and is pinned, if at all, by `timestamp_truncate` at the
/// superblock boundary. # C: O(1)
pub fn nsec_valid(nsec: i64) -> bool {
    if nsec == UTIME_OMIT || nsec == UTIME_NOW { return true; }
    nsec >= 0 && nsec < NSEC_PER_SEC as i64
}

/// Resolve one raw slot into its `ATTR_*` meaning, rejecting an out-of-range
/// `tv_nsec` (`vfs_utimes`, `fs/utimes.c:28-30`). # C: O(1)
pub fn resolve_slot(r: RawTimespec) -> Result<TimeSlot, Errno> {
    if !nsec_valid(r.nsec) { return Err(Errno::Einval); }
    if r.nsec == UTIME_OMIT { return Ok(TimeSlot::Omit); }
    if r.nsec == UTIME_NOW { return Ok(TimeSlot::Now); }
    Ok(TimeSlot::Set(Timespec64::new(r.sec, r.nsec as u32)))
}

/// Resolve both slots, EINVAL if either `tv_nsec` is out of range. Linux tests
/// slot 0 then slot 1 in one `if`, so the errno is the same either way.
/// # C: O(1)
pub fn resolve_pair(t: &[RawTimespec; 2]) -> Result<(TimeSlot, TimeSlot), Errno> {
    Ok((resolve_slot(t[0])?, resolve_slot(t[1])?))
}

/// `do_utimes_path`'s flag gate (`fs/utimes.c:89-90`): the path form accepts
/// `AT_SYMLINK_NOFOLLOW` and `AT_EMPTY_PATH` and nothing else. # C: O(1)
pub fn check_path_form_flags(flags: u64) -> Result<(), Errno> {
    if flags & !(syscall::at::AT_NOFOLLOW_EMPTY as u64) != 0 { return Err(Errno::Einval); }
    Ok(())
}

/// `vfs_utimes`' `newattrs` assembly (`fs/utimes.c:40-63`) for the explicit
/// `times[]` form. `UTIME_OMIT` clears the field's `ATTR_*`; `UTIME_NOW` keeps
/// it without `ATTR_*_SET`; a specific instant adds `ATTR_*_SET`, which is the
/// signal `setattr_prepare` reads to demand owner/CAP_FOWNER.
///
/// Both-`UTIME_NOW` therefore lands on exactly the shape [`crate::utimes_abi::
/// iattr_touch`] produces, matching Linux's `times = NULL` rewrite
/// (`fs/utimes.c:31-33`). Returns `None` for both-`UTIME_OMIT`, the caller's
/// no-op success. # C: O(1)
pub fn utimensat_iattr(a: TimeSlot, m: TimeSlot, now: Timespec64) -> Option<vfs::Iattr> {
    let mut ia = vfs::Iattr { ctime: now, ..Default::default() };
    match a {
        TimeSlot::Omit    => {}
        TimeSlot::Now     => { ia.valid |= vfs::ATTR_ATIME; ia.atime = now; }
        TimeSlot::Set(t)  => { ia.valid |= vfs::ATTR_ATIME | vfs::ATTR_ATIME_SET; ia.atime = t; }
    }
    match m {
        TimeSlot::Omit    => {}
        TimeSlot::Now     => { ia.valid |= vfs::ATTR_MTIME; ia.mtime = now; }
        TimeSlot::Set(t)  => { ia.valid |= vfs::ATTR_MTIME | vfs::ATTR_MTIME_SET; ia.mtime = t; }
    }
    if ia.valid & (vfs::ATTR_ATIME | vfs::ATTR_MTIME) == 0 { return None; }
    Some(ia)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utimes_abi::iattr_touch;

    fn pair(asec: i64, ansec: i64, msec: i64, mnsec: i64) -> [u8; TIMESPEC_PAIR_BYTES] {
        let mut b = [0u8; TIMESPEC_PAIR_BYTES];
        b[0..8].copy_from_slice(&asec.to_ne_bytes());
        b[8..16].copy_from_slice(&ansec.to_ne_bytes());
        b[16..24].copy_from_slice(&msec.to_ne_bytes());
        b[24..32].copy_from_slice(&mnsec.to_ne_bytes());
        b
    }

    const NOW: Timespec64 = Timespec64 { sec: 1_700_000_000, nsec: 123 };

    /// The bug this module was rebuilt for: `tv_sec` is NEVER range-checked
    /// (`nsec_valid` takes `tv_nsec` alone, `fs/utimes.c:13-19`), so a pre-1970
    /// request SUCCEEDS and carries its negative second into `Iattr`. The
    /// pre-fix slot returned EINVAL on `sec < 0` because `Iattr` held unsigned
    /// nanoseconds. # C: O(1)
    #[test]
    fn negative_tv_sec_reaches_iattr_instead_of_einval() {
        let raw = decode_timespec_pair(&pair(-1_000_000, 0, -1_000_000, 0));
        let (a, m) = resolve_pair(&raw).expect("negative tv_sec is not an error on Linux");
        assert_eq!(a, TimeSlot::Set(Timespec64 { sec: -1_000_000, nsec: 0 }));
        let ia = utimensat_iattr(a, m, NOW).unwrap();
        assert_eq!(ia.atime, Timespec64 { sec: -1_000_000, nsec: 0 });
        assert_eq!(ia.mtime, Timespec64 { sec: -1_000_000, nsec: 0 });
        assert_eq!(ia.valid,
            vfs::ATTR_ATIME | vfs::ATTR_MTIME | vfs::ATTR_ATIME_SET | vfs::ATTR_MTIME_SET);
    }

    /// A negative second WITH a sub-second part: `tv_nsec` counts FORWARD from
    /// `tv_sec`, so `{-2, 500_000_000}` is 1969-12-31T23:59:58.5 and stays a
    /// distinct value from `{-1, 500_000_000}`. Both must survive verbatim.
    /// # C: O(1)
    #[test]
    fn negative_tv_sec_with_nonzero_nsec_is_verbatim() {
        let raw = decode_timespec_pair(&pair(-2, 500_000_000, i64::MIN, 999_999_999));
        let (a, m) = resolve_pair(&raw).unwrap();
        assert_eq!(a, TimeSlot::Set(Timespec64 { sec: -2, nsec: 500_000_000 }));
        assert_eq!(m, TimeSlot::Set(Timespec64 { sec: i64::MIN, nsec: 999_999_999 }));
        let ia = utimensat_iattr(a, m, NOW).unwrap();
        assert_eq!(ia.atime, Timespec64 { sec: -2, nsec: 500_000_000 });
        assert!(ia.atime > Timespec64 { sec: -3, nsec: 999_999_999 });
        assert!(ia.atime < Timespec64::ZERO);
    }

    /// `nsec_valid` accepts `[0, 1e9)` plus the two sentinels and nothing else
    /// — including on a negative-second request, where the old combined
    /// `sec < 0 || nsec < 0 || nsec >= 1e9` test conflated the two axes.
    /// # C: O(1)
    #[test]
    fn only_tv_nsec_is_range_checked() {
        assert!(nsec_valid(0) && nsec_valid(999_999_999));
        assert!(nsec_valid(UTIME_NOW) && nsec_valid(UTIME_OMIT));
        assert!(!nsec_valid(-1) && !nsec_valid(1_000_000_000));
        // Out-of-range nsec is EINVAL whatever the second is.
        for sec in [-1_000_000i64, 0, 1_700_000_000] {
            let raw = decode_timespec_pair(&pair(sec, 1_000_000_000, sec, 0));
            assert_eq!(resolve_pair(&raw), Err(Errno::Einval), "sec {sec}");
            let raw = decode_timespec_pair(&pair(sec, 0, sec, -1));
            assert_eq!(resolve_pair(&raw), Err(Errno::Einval), "sec {sec}");
        }
    }

    /// Sentinels are matched BEFORE the range test, so `0x3fffffff` in
    /// `tv_nsec` is "now" rather than an out-of-range nanosecond, and the
    /// accompanying `tv_sec` is ignored entirely. # C: O(1)
    #[test]
    fn sentinels_win_over_the_range_test_and_ignore_tv_sec() {
        let raw = decode_timespec_pair(&pair(-999, UTIME_NOW, 12345, UTIME_OMIT));
        assert_eq!(resolve_pair(&raw), Ok((TimeSlot::Now, TimeSlot::Omit)));
        let ia = utimensat_iattr(TimeSlot::Now, TimeSlot::Omit, NOW).unwrap();
        assert_eq!(ia.valid, vfs::ATTR_ATIME, "OMIT must clear ATTR_MTIME");
        assert_eq!(ia.atime, NOW);
        assert_eq!(ia.ctime, NOW);
        // Mirror image.
        let ia = utimensat_iattr(TimeSlot::Omit, TimeSlot::Now, NOW).unwrap();
        assert_eq!(ia.valid, vfs::ATTR_MTIME);
        assert_eq!(ia.mtime, NOW);
    }

    /// Both `UTIME_OMIT` is a no-op success detected BEFORE the path is even
    /// looked at (`fs/utimes.c:153-156`), so it is a `None` `Iattr` here and a
    /// pre-lookup `return 0` in the slot. # C: O(1)
    #[test]
    fn both_omit_short_circuits() {
        let raw = decode_timespec_pair(&pair(1, UTIME_OMIT, 2, UTIME_OMIT));
        assert!(both_omit(&raw));
        assert!(utimensat_iattr(TimeSlot::Omit, TimeSlot::Omit, NOW).is_none());
        // One OMIT alone does not short-circuit.
        assert!(!both_omit(&decode_timespec_pair(&pair(1, UTIME_OMIT, 2, 0))));
        assert!(!both_omit(&decode_timespec_pair(&pair(1, UTIME_NOW, 2, UTIME_NOW))));
    }

    /// Both `UTIME_NOW` is Linux's `times = NULL` rewrite (`fs/utimes.c:31-33`)
    /// — byte-identical to the `ATTR_TOUCH` shape, i.e. no `ATTR_*_SET`, so a
    /// non-owner with write permission may do it. # C: O(1)
    #[test]
    fn both_now_is_the_touch_shape() {
        let ia = utimensat_iattr(TimeSlot::Now, TimeSlot::Now, NOW).unwrap();
        let touch = iattr_touch(NOW);
        assert_eq!(ia.valid, touch.valid);
        assert_eq!((ia.atime, ia.mtime, ia.ctime), (touch.atime, touch.mtime, touch.ctime));
        assert_eq!(ia.valid & (vfs::ATTR_ATIME_SET | vfs::ATTR_MTIME_SET), 0);
    }

    /// The path form accepts exactly `AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH`
    /// (`fs/utimes.c:89-90`); the fd form accepts no flag at all
    /// (`fs/utimes.c:110-111`). # C: O(1)
    #[test]
    fn flag_ladder_differs_between_the_path_and_fd_forms() {
        let nofollow = syscall::at::AT_SYMLINK_NOFOLLOW as u64;
        let empty = syscall::at::AT_EMPTY_PATH as u64;
        assert_eq!(check_path_form_flags(0), Ok(()));
        assert_eq!(check_path_form_flags(nofollow), Ok(()));
        assert_eq!(check_path_form_flags(empty), Ok(()));
        assert_eq!(check_path_form_flags(nofollow | empty), Ok(()));
        assert_eq!(check_path_form_flags(0x800), Err(Errno::Einval));
        assert_eq!(crate::utimes_abi::check_fd_form_flags(nofollow), Err(Errno::Einval));
    }
}
