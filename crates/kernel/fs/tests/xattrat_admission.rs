//! `*xattrat` (463-466) argument-admission ORDER, pinned against Linux
//! `fs/xattr.c`. Ordering is observable whenever two arguments are both bad:
//! whichever check Linux runs first names the errno userspace sees.
//!
//! Before F761 the four shims imported the name/value BEFORE validating
//! `at_flags`, so `setxattrat(dfd, path, /*bogus*/ 0x2, NULL_name, args, 16)`
//! answered `EFAULT` (from the name import) where Linux answers `EINVAL`.

use fs::xattr::{admit_getxattrat, admit_listxattrat, admit_removexattrat, admit_setxattrat,
                check_at_flags, XATTR_CREATE, XATTR_REPLACE};
use syscall::at::{AT_EMPTY_PATH, AT_SYMLINK_NOFOLLOW};
use syscall::errno::Errno;

fn e(x: Errno) -> i64 { -(x.as_i32() as i64) }

/// `SetCtx` carries a `Vec`, not `Debug`; every case here asserts on the error
/// arm, so collapse the ok arm to a marker.
fn set_err<T>(r: Result<T, i64>) -> i64 { r.err().unwrap_or(0) }

/// A `struct xattr_args { __u64 value; __u32 size; __u32 flags; }` image.
fn args(value: u64, size: u32, flags: u32) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&value.to_le_bytes());
    v.extend_from_slice(&size.to_le_bytes());
    v.extend_from_slice(&flags.to_le_bytes());
    v
}

/// A bit outside `AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH` — `AT_REMOVEDIR`, which
/// is legal for `unlinkat` and rejected here.
const BOGUS_AT: u32 = 0x0200;

// --- `path_*xattrat`: the accepted at_flags set ---------------------------

#[test]
fn only_nofollow_and_empty_path_are_accepted() {
    // `(at_flags & ~(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH)) != 0` → EINVAL.
    assert_eq!(check_at_flags(0), Ok(()));
    assert_eq!(check_at_flags(AT_SYMLINK_NOFOLLOW), Ok(()));
    assert_eq!(check_at_flags(AT_EMPTY_PATH), Ok(()));
    assert_eq!(check_at_flags(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH), Ok(()));
    assert_eq!(check_at_flags(BOGUS_AT), Err(e(Errno::Einval)));
    assert_eq!(check_at_flags(0x0400), Err(e(Errno::Einval)), "AT_SYMLINK_FOLLOW is not accepted");
    assert_eq!(check_at_flags(0xffff_ffff), Err(e(Errno::Einval)));
}

// --- 463 setxattrat (`fs/xattr.c:701` + `:740`) ---------------------------

#[test]
fn setxattrat_runs_the_xattr_args_handshake_before_at_flags() {
    // `SYSCALL_DEFINE6(setxattrat)` validates `usize` and copies the struct
    // BEFORE calling `path_setxattrat`, which is where `at_flags` is checked.
    let a = args(0, 0, 0);
    let p = a.as_ptr() as u64;
    assert_eq!(set_err(admit_setxattrat(BOGUS_AT, 0, p, 8)), e(Errno::Einval), "short struct");
    assert_eq!(set_err(admit_setxattrat(BOGUS_AT, 0, p, 1 << 20)), e(Errno::E2big),
               "usize > PAGE_SIZE outranks a bogus at_flags");
    assert_eq!(set_err(admit_setxattrat(BOGUS_AT, 0, 0, 16)), e(Errno::Efault),
               "an unreadable xattr_args outranks a bogus at_flags");
}

#[test]
fn setxattrat_checks_at_flags_before_importing_the_name() {
    // `path_setxattrat`: the at_flags gate precedes `setxattr_copy`.
    let a = args(0, 0, 0);
    let p = a.as_ptr() as u64;
    assert_eq!(set_err(admit_setxattrat(BOGUS_AT, 0, p, 16)), e(Errno::Einval),
               "bogus at_flags must beat the NULL name's EFAULT");
    assert_eq!(set_err(admit_setxattrat(0, 0, p, 16)), e(Errno::Efault),
               "with valid at_flags the NULL name is EFAULT");
}

#[test]
fn setxattrat_checks_at_flags_before_the_xattr_set_flags() {
    // Both are EINVAL, so pin the pair that is NOT: valid at_flags + a bogus
    // `args.flags` must still be EINVAL, and it must come from `setxattr_copy`.
    let bad = args(0, 0, 4);
    assert_eq!(set_err(admit_setxattrat(AT_EMPTY_PATH, 0, bad.as_ptr() as u64, 16)),
               e(Errno::Einval), "setxattr_copy rejects flags outside CREATE|REPLACE");
    let ok = args(0, 0, XATTR_CREATE | XATTR_REPLACE);
    assert_eq!(set_err(admit_setxattrat(AT_EMPTY_PATH, 0, ok.as_ptr() as u64, 16)),
               e(Errno::Efault), "CREATE|REPLACE together is legal; the NULL name is what fails");
}

#[test]
fn setxattrat_rejects_a_non_zero_unknown_tail() {
    let mut a = args(0, 0, XATTR_REPLACE);
    a.extend_from_slice(&[0u8, 0, 0, 9]);
    assert_eq!(set_err(admit_setxattrat(0, 0, a.as_ptr() as u64, 20)), e(Errno::E2big));
}

// --- 464 getxattrat (`fs/xattr.c:846` + `:880`) ---------------------------

#[test]
fn getxattrat_rejects_a_non_zero_args_flags_before_at_flags_and_name() {
    // `if (args.flags != 0) return -EINVAL;` lives in the syscall wrapper, so
    // it outranks everything `path_getxattrat` does.
    let bad = args(0, 0, XATTR_CREATE);
    assert_eq!(admit_getxattrat(0, 0, bad.as_ptr() as u64, 16).unwrap_err(), e(Errno::Einval));
    let ok = args(0, 0, 0);
    assert_eq!(admit_getxattrat(BOGUS_AT, 0, ok.as_ptr() as u64, 16).unwrap_err(),
               e(Errno::Einval), "bogus at_flags beats the NULL name");
    assert_eq!(admit_getxattrat(0, 0, ok.as_ptr() as u64, 16).unwrap_err(), e(Errno::Efault));
}

#[test]
fn getxattrat_carries_the_value_pointer_and_size_out_of_xattr_args() {
    let name = b"user.a\0";
    let a = args(0xdead_0000, 4096, 0);
    let (n, value_ptr, size) =
        admit_getxattrat(AT_SYMLINK_NOFOLLOW, name.as_ptr() as u64, a.as_ptr() as u64, 16).unwrap();
    assert_eq!(n, "user.a");
    assert_eq!(value_ptr, 0xdead_0000);
    assert_eq!(size, 4096);
}

// --- 466 removexattrat (`fs/xattr.c:1075`) --------------------------------

#[test]
fn removexattrat_checks_at_flags_before_importing_the_name() {
    assert_eq!(admit_removexattrat(BOGUS_AT, 0).unwrap_err(), e(Errno::Einval));
    assert_eq!(admit_removexattrat(AT_EMPTY_PATH, 0).unwrap_err(), e(Errno::Efault));
    let name = b"trusted.x\0";
    assert_eq!(admit_removexattrat(AT_SYMLINK_NOFOLLOW, name.as_ptr() as u64).unwrap(), "trusted.x");
}

// --- 465 listxattrat (`fs/xattr.c:983`) -----------------------------------

#[test]
fn listxattrat_only_validates_at_flags() {
    assert_eq!(admit_listxattrat(BOGUS_AT), Err(e(Errno::Einval)));
    assert_eq!(admit_listxattrat(AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW), Ok(()));
}
