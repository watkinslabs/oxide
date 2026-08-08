use super::*;

fn rd_i64(b: &[u8], o: usize) -> i64 { i64::from_ne_bytes(b[o..o + 8].try_into().unwrap()) }
fn rd_u64(b: &[u8], o: usize) -> u64 { u64::from_ne_bytes(b[o..o + 8].try_into().unwrap()) }

fn sample(t: Timespec64) -> NewStat {
    NewStat {
        dev: 0x0803, ino: 42, nlink: 1, mode: 0o100_644, uid: 1000, gid: 1000,
        rdev: 0, size: 7, blksize: 4096, blocks: 8,
        atime: t, mtime: t, ctime: t,
    }
}

/// Timestamp offsets are identical on both arches (72/88/104) and each is a
/// SIGNED second followed by an UNSIGNED nanosecond — matching the userspace
/// `struct stat` in `crates/user/glibc/src/posix/stat.rs`, whose ABI golden
/// pins `st_mtime` at 88 on x86_64 AND aarch64. # C: O(1)
#[test]
fn timestamp_offsets_match_both_arch_layouts() {
    let t = Timespec64 { sec: 1_700_000_000, nsec: 123_456_789 };
    let mut x = [0u8; STAT_BYTES_X86_64 as usize];
    let mut a = [0u8; STAT_BYTES_AARCH64 as usize];
    write_new_stat_x86_64_bytes(&mut x, &sample(t));
    write_new_stat_aarch64_bytes(&mut a, &sample(t));
    for buf in [&x[..], &a[..]] {
        for off in [72usize, 88, 104] {
            assert_eq!(rd_i64(buf, off), 1_700_000_000, "sec @{off}");
            assert_eq!(rd_u64(buf, off + 8), 123_456_789, "nsec @{off}");
        }
    }
}

/// The silent-corruption case the split pair fixes: a PRE-1970 stamp.
/// The old encoder held ns as `u64` and split it with truncating division,
/// so `{-2, 500_000_000}` could only be expressed as a huge unsigned ns —
/// and a signed reading of it produced `st_*time_nsec = -500_000_000`, which
/// POSIX forbids (`tv_nsec` is `[0, 1e9)`). # C: O(1)
#[test]
fn pre_1970_stamp_keeps_a_nonnegative_nsec() {
    let t = Timespec64 { sec: -2, nsec: 500_000_000 };
    let mut x = [0u8; STAT_BYTES_X86_64 as usize];
    let mut a = [0u8; STAT_BYTES_AARCH64 as usize];
    write_new_stat_x86_64_bytes(&mut x, &sample(t));
    write_new_stat_aarch64_bytes(&mut a, &sample(t));
    for buf in [&x[..], &a[..]] {
        for off in [72usize, 88, 104] {
            assert_eq!(rd_i64(buf, off), -2, "st_*time must be signed @{off}");
            let nsec = rd_i64(buf, off + 8);
            assert!((0..1_000_000_000).contains(&nsec),
                "st_*time_nsec {nsec} outside [0,1e9) @{off}");
            assert_eq!(nsec, 500_000_000);
        }
    }
    // `i64::MIN` seconds — outside a 64-bit ns scalar entirely — still round
    // trips, because nothing multiplies by 1e9 any more.
    let t = Timespec64 { sec: i64::MIN, nsec: 999_999_999 };
    write_new_stat_x86_64_bytes(&mut x, &sample(t));
    assert_eq!(rd_i64(&x, 72), i64::MIN);
    assert_eq!(rd_u64(&x, 80), 999_999_999);
}

/// `Kstat` → `NewStat` carries the timestamps verbatim; nothing rescales.
/// # C: O(1)
#[test]
fn kstat_timestamps_pass_through_unscaled() {
    let t = Timespec64 { sec: -1_000_000, nsec: 1 };
    let st = vfs::Kstat {
        ino: 1, mode: 0o40_755, nlink: 2, uid: 0, gid: 0, rdev: 0,
        size: 0, blksize: 4096, blocks: 0,
        atime: t, mtime: Timespec64::ZERO, ctime: t, btime: None,
        fsid: 0, change_cookie: 0, dio_mem_align: 0, dio_offset_align: 0,
        result_mask: 0, attributes: 0, attributes_mask: 0,
    };
    let out = new_stat_from_kstat(&st, 0x0803).unwrap();
    assert_eq!(out.atime, t);
    assert_eq!(out.mtime, Timespec64::ZERO);
    assert_eq!(out.ctime, t);
}
