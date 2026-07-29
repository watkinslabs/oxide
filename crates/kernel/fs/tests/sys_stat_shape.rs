// This integration test compiles production modules directly via `#[path]` to
// assert their ABI shape, and exercises only the part of each module the shape
// under test needs. dead_code here measures the test's reach, not the kernel's
// -- the real signal lives in `xtask kernel`, which is dead_code-clean.
#![allow(dead_code)]
#[path = "../../syscalls/src/stat_common/core.rs"]
mod stat_common;

use core::sync::atomic::{AtomicUsize, Ordering};

use syscall::errno::Errno;
use vfs::{Kstat, Timespec64};

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

fn kstat() -> Kstat {
    Kstat {
        ino: 0x1122_3344_5566_7788,
        mode: vfs::S_IFCHR | 0o6754,
        nlink: 0x1020_3040,
        uid: vfs::idmap::INVALID_ID,
        gid: vfs::idmap::INVALID_ID,
        rdev: 0x0000_0103,
        size: 0x1234_5678_9abc_def0,
        blksize: 4096,
        blocks: 0x1234_5678,
        atime: Timespec64::new(1_700_000_001, 234_567_890),
        mtime: Timespec64::new(1_700_000_002, 345_678_901),
        ctime: Timespec64::new(1_700_000_003, 456_789_012),
        btime: None,
        fsid: 0,
        change_cookie: 0,
        result_mask: 0,
        attributes: 0,
        attributes_mask: 0,
    }
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_ne_bytes(b[off..off + 4].try_into().unwrap())
}

fn u64_at(b: &[u8], off: usize) -> u64 {
    u64::from_ne_bytes(b[off..off + 8].try_into().unwrap())
}

fn i32_at(b: &[u8], off: usize) -> i32 {
    i32::from_ne_bytes(b[off..off + 4].try_into().unwrap())
}

fn i64_at(b: &[u8], off: usize) -> i64 {
    i64::from_ne_bytes(b[off..off + 8].try_into().unwrap())
}

#[test]
fn x86_64_new_stat_layout_matches_linux_offsets() {
    let out = stat_common::new_stat_from_kstat(&kstat(), 0x7788).unwrap();
    let mut b = [0xffu8; stat_common::STAT_BYTES_X86_64 as usize];
    stat_common::write_new_stat_x86_64_bytes(&mut b, &out);

    assert_eq!(u64_at(&b, 0), 0x7788);
    assert_eq!(u64_at(&b, 8), 0x1122_3344_5566_7788);
    assert_eq!(u64_at(&b, 16), 0x1020_3040);
    assert_eq!(u32_at(&b, 24), vfs::S_IFCHR | 0o6754);
    assert_eq!(u32_at(&b, 28), vfs::idmap::OVERFLOW_UID);
    assert_eq!(u32_at(&b, 32), vfs::idmap::OVERFLOW_GID);
    assert_eq!(u64_at(&b, 40), 0x0000_0103);
    assert_eq!(i64_at(&b, 48), 0x1234_5678_9abc_def0);
    assert_eq!(i64_at(&b, 56), 4096);
    assert_eq!(i64_at(&b, 64), 0x1234_5678);
    assert_eq!(i64_at(&b, 72), 1_700_000_001);
    assert_eq!(i64_at(&b, 80), 234_567_890);
    assert_eq!(i64_at(&b, 88), 1_700_000_002);
    assert_eq!(i64_at(&b, 96), 345_678_901);
    assert_eq!(i64_at(&b, 104), 1_700_000_003);
    assert_eq!(i64_at(&b, 112), 456_789_012);
    assert!(b[120..].iter().all(|&x| x == 0));
}

#[test]
fn aarch64_new_stat_layout_matches_asm_generic_offsets() {
    let out = stat_common::new_stat_from_kstat(&kstat(), 0x9900).unwrap();
    let mut b = [0xffu8; stat_common::STAT_BYTES_AARCH64 as usize];
    stat_common::write_new_stat_aarch64_bytes(&mut b, &out);

    assert_eq!(u64_at(&b, 0), 0x9900);
    assert_eq!(u64_at(&b, 8), 0x1122_3344_5566_7788);
    assert_eq!(u32_at(&b, 16), vfs::S_IFCHR | 0o6754);
    assert_eq!(u32_at(&b, 20), 0x1020_3040);
    assert_eq!(u32_at(&b, 24), vfs::idmap::OVERFLOW_UID);
    assert_eq!(u32_at(&b, 28), vfs::idmap::OVERFLOW_GID);
    assert_eq!(u64_at(&b, 32), 0x0000_0103);
    assert_eq!(u64_at(&b, 40), 0);
    assert_eq!(i64_at(&b, 48), 0x1234_5678_9abc_def0);
    assert_eq!(i32_at(&b, 56), 4096);
    assert_eq!(u32_at(&b, 60), 0);
    assert_eq!(i64_at(&b, 64), 0x1234_5678);
    assert_eq!(i64_at(&b, 72), 1_700_000_001);
    assert_eq!(i64_at(&b, 80), 234_567_890);
    assert_eq!(i64_at(&b, 88), 1_700_000_002);
    assert_eq!(i64_at(&b, 96), 345_678_901);
    assert_eq!(i64_at(&b, 104), 1_700_000_003);
    assert_eq!(i64_at(&b, 112), 456_789_012);
    assert!(b[120..].iter().all(|&x| x == 0));
}

#[test]
fn impossible_unsigned_kstat_values_fail_before_copyout_fault() {
    static VALIDATE_CALLS: AtomicUsize = AtomicUsize::new(0);

    fn convert_then_validate(st: &Kstat) -> i64 {
        let out = match stat_common::new_stat_from_kstat(st, 1) {
            Ok(o) => o,
            Err(rv) => return rv,
        };
        let _ = out;
        VALIDATE_CALLS.fetch_add(1, Ordering::SeqCst);
        err(Errno::Efault)
    }

    let mut st = kstat();
    st.size = i64::MAX as u64 + 1;
    VALIDATE_CALLS.store(0, Ordering::SeqCst);
    assert_eq!(convert_then_validate(&st), err(Errno::Eoverflow));
    assert_eq!(VALIDATE_CALLS.load(Ordering::SeqCst), 0);

    st = kstat();
    st.blocks = i64::MAX as u64 + 1;
    VALIDATE_CALLS.store(0, Ordering::SeqCst);
    assert_eq!(convert_then_validate(&st), err(Errno::Eoverflow));
    assert_eq!(VALIDATE_CALLS.load(Ordering::SeqCst), 0);

    VALIDATE_CALLS.store(0, Ordering::SeqCst);
    assert_eq!(convert_then_validate(&kstat()), err(Errno::Efault));
    assert_eq!(VALIDATE_CALLS.load(Ordering::SeqCst), 1);
}

/// F767: a PRE-1970 `Kstat` reaches `struct stat` as a NEGATIVE `st_*time` with
/// a NON-negative `st_*time_nsec`, on BOTH arches. `struct stat`'s seconds
/// field is `__kernel_time_t`/`i64` (see `crates/user/glibc/src/posix/stat.rs`,
/// which declares `st_atime: i64` for x86_64 and aarch64 alike), so a wrong
/// cast surfaces as a huge POSITIVE time rather than an error — which is
/// exactly what the old unsigned-ns model would have produced had the syscall
/// layer not rejected the value outright with `EINVAL`.
///
/// The old `write_ts` split `ns / 1e9` and `ns % 1e9` with TRUNCATING division;
/// for -1.5s that yields `(-1, -500_000_000)` — a negative `tv_nsec`, which
/// POSIX forbids. The correct answer is `(-2, 500_000_000)`.
fn pre_epoch_kstat() -> Kstat {
    let mut st = kstat();
    // 1906-08-16T20:26:40.123456789Z, and the -1.5s boundary case for mtime.
    st.atime = Timespec64::new(-2_000_000_000, 123_456_789);
    st.mtime = Timespec64::new(-2, 500_000_000);
    st.ctime = Timespec64::new(-1, 999_999_999);
    st
}

#[test]
fn x86_64_pre_epoch_stat_reports_signed_seconds() {
    let out = stat_common::new_stat_from_kstat(&pre_epoch_kstat(), 0x7788).unwrap();
    let mut b = [0xffu8; stat_common::STAT_BYTES_X86_64 as usize];
    stat_common::write_new_stat_x86_64_bytes(&mut b, &out);
    assert_eq!(i64_at(&b, 72), -2_000_000_000, "st_atime stays negative");
    assert_eq!(i64_at(&b, 80), 123_456_789, "st_atime_nsec non-negative");
    assert_eq!(i64_at(&b, 88), -2, "st_mtime floors to -2, not -1");
    assert_eq!(i64_at(&b, 96), 500_000_000, "st_mtime_nsec non-negative");
    assert_eq!(i64_at(&b, 104), -1);
    assert_eq!(i64_at(&b, 112), 999_999_999);
    for off in [80usize, 96, 112] {
        assert!((0..1_000_000_000).contains(&i64_at(&b, off)), "tv_nsec in [0,1e9) at {off}");
    }
}

#[test]
fn aarch64_pre_epoch_stat_reports_signed_seconds() {
    let out = stat_common::new_stat_from_kstat(&pre_epoch_kstat(), 0x9900).unwrap();
    let mut b = [0xffu8; stat_common::STAT_BYTES_AARCH64 as usize];
    stat_common::write_new_stat_aarch64_bytes(&mut b, &out);
    assert_eq!(i64_at(&b, 72), -2_000_000_000, "st_atime stays negative");
    assert_eq!(i64_at(&b, 80), 123_456_789, "st_atime_nsec non-negative");
    assert_eq!(i64_at(&b, 88), -2, "st_mtime floors to -2, not -1");
    assert_eq!(i64_at(&b, 96), 500_000_000, "st_mtime_nsec non-negative");
    assert_eq!(i64_at(&b, 104), -1);
    assert_eq!(i64_at(&b, 112), 999_999_999);
    for off in [80usize, 96, 112] {
        assert!((0..1_000_000_000).contains(&i64_at(&b, off)), "tv_nsec in [0,1e9) at {off}");
    }
}
