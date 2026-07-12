#[path = "../../syscalls/src/stat_common.rs"]
mod stat_common;

use core::sync::atomic::{AtomicUsize, Ordering};

use syscall::errno::Errno;
use vfs::Kstat;

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
        atime_ns: 1_700_000_001_234_567_890,
        mtime_ns: 1_700_000_002_345_678_901,
        ctime_ns: 1_700_000_003_456_789_012,
        btime_ns: 0,
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
