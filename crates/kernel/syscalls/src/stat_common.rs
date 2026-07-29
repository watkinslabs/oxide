// Linux struct-stat ABI encoder shared by stat/lstat/fstat/newfstatat.

use syscall::errno::Errno;
use vfs::Timespec64;

#[cfg(any(test, target_arch = "x86_64"))]
pub(crate) const STAT_BYTES_X86_64: u64 = 144;
#[cfg(any(test, target_arch = "aarch64"))]
pub(crate) const STAT_BYTES_AARCH64: u64 = 128;
#[cfg(all(any(test, target_os = "oxide-kernel"), target_arch = "x86_64"))]
pub(crate) const STAT_BYTES: u64 = STAT_BYTES_X86_64;
#[cfg(all(any(test, target_os = "oxide-kernel"), target_arch = "aarch64"))]
pub(crate) const STAT_BYTES: u64 = STAT_BYTES_AARCH64;

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NewStat {
    pub(crate) dev: u64,
    pub(crate) ino: u64,
    pub(crate) nlink: u32,
    pub(crate) mode: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) rdev: u64,
    pub(crate) size: i64,
    pub(crate) blksize: u32,
    pub(crate) blocks: i64,
    pub(crate) atime: Timespec64,
    pub(crate) mtime: Timespec64,
    pub(crate) ctime: Timespec64,
}

/// Convert VFS `Kstat` into Linux `struct stat` payload fields. # C: O(1)
pub(crate) fn new_stat_from_kstat(st: &vfs::Kstat, dev: u64) -> Result<NewStat, i64> {
    if st.size > i64::MAX as u64 { return Err(errno(Errno::Eoverflow)); }
    if st.blocks > i64::MAX as u64 { return Err(errno(Errno::Eoverflow)); }
    Ok(NewStat {
        dev,
        ino: st.ino,
        nlink: st.nlink,
        mode: st.mode,
        uid: stat_uid(st.uid),
        gid: stat_gid(st.gid),
        rdev: st.rdev as u64,
        size: st.size as i64,
        blksize: st.blksize,
        blocks: st.blocks as i64,
        atime: st.atime,
        mtime: st.mtime,
        ctime: st.ctime,
    })
}

/// Munged `st_uid`/`stx_uid` user value. # C: O(1)
pub(crate) fn stat_uid(uid: u32) -> u32 {
    if uid == vfs::idmap::INVALID_ID { vfs::idmap::OVERFLOW_UID } else { uid }
}

/// Munged `st_gid`/`stx_gid` user value. # C: O(1)
pub(crate) fn stat_gid(gid: u32) -> u32 {
    if gid == vfs::idmap::INVALID_ID { vfs::idmap::OVERFLOW_GID } else { gid }
}

trait StatSink {
    fn zero(&mut self, bytes: u64);
    fn w32(&mut self, off: u64, v: u32);
    fn w64(&mut self, off: u64, v: u64);
    /// Only `write_aarch64` has a signed 32-bit field (`st_blksize`); the
    /// x86_64 `struct stat` widens it to `__kernel_long_t`.
    #[cfg(any(test, target_arch = "aarch64"))]
    fn wi32(&mut self, off: u64, v: i32);
    fn wi64(&mut self, off: u64, v: i64);
}

struct UserSink { base: u64 }

impl StatSink for UserSink {
    fn zero(&mut self, bytes: u64) {
        for off in (0..bytes).step_by(8) {
            // SAFETY: caller validated the full user output range writable.
            unsafe { core::ptr::write_unaligned((self.base + off) as *mut u64, 0); }
        }
    }
    fn w32(&mut self, off: u64, v: u32) {
        // SAFETY: caller validated the full user output range writable.
        unsafe { core::ptr::write_unaligned((self.base + off) as *mut u32, v); }
    }
    fn w64(&mut self, off: u64, v: u64) {
        // SAFETY: caller validated the full user output range writable.
        unsafe { core::ptr::write_unaligned((self.base + off) as *mut u64, v); }
    }
    #[cfg(any(test, target_arch = "aarch64"))]
    fn wi32(&mut self, off: u64, v: i32) {
        // SAFETY: caller validated the full user output range writable.
        unsafe { core::ptr::write_unaligned((self.base + off) as *mut i32, v); }
    }
    fn wi64(&mut self, off: u64, v: i64) {
        // SAFETY: caller validated the full user output range writable.
        unsafe { core::ptr::write_unaligned((self.base + off) as *mut i64, v); }
    }
}

#[cfg(test)]
struct SliceSink<'a> { out: &'a mut [u8] }

#[cfg(test)]
impl StatSink for SliceSink<'_> {
    fn zero(&mut self, bytes: u64) {
        assert!(self.out.len() >= bytes as usize);
        for b in &mut self.out[..bytes as usize] { *b = 0; }
    }
    fn w32(&mut self, off: u64, v: u32) {
        self.out[off as usize..off as usize + 4].copy_from_slice(&v.to_ne_bytes());
    }
    fn w64(&mut self, off: u64, v: u64) {
        self.out[off as usize..off as usize + 8].copy_from_slice(&v.to_ne_bytes());
    }
    fn wi32(&mut self, off: u64, v: i32) {
        self.out[off as usize..off as usize + 4].copy_from_slice(&v.to_ne_bytes());
    }
    fn wi64(&mut self, off: u64, v: i64) {
        self.out[off as usize..off as usize + 8].copy_from_slice(&v.to_ne_bytes());
    }
}

/// One `struct stat` timestamp pair: `__kernel_long_t st_*time` (SIGNED) then
/// `__kernel_ulong_t st_*time_nsec` (`include/uapi/asm-generic/stat.h`, and the
/// x86_64 `arch/x86/include/uapi/asm/stat.h` variant). Written straight from
/// the `timespec64` fields — the pre-fix `(ns / 1e9, ns % 1e9)` division
/// emitted a NEGATIVE `st_*time_nsec` for any pre-1970 stamp, which POSIX
/// forbids. # C: O(1)
fn write_ts<S: StatSink>(s: &mut S, sec_off: u64, t: Timespec64) {
    s.wi64(sec_off, t.sec);
    s.w64(sec_off + 8, t.nsec as u64);
}

#[cfg(any(test, target_arch = "x86_64"))]
fn write_x86_64<S: StatSink>(s: &mut S, st: &NewStat) {
    s.zero(STAT_BYTES_X86_64);
    s.w64(0, st.dev);
    s.w64(8, st.ino);
    s.w64(16, st.nlink as u64);
    s.w32(24, st.mode);
    s.w32(28, st.uid);
    s.w32(32, st.gid);
    s.w64(40, st.rdev);
    s.wi64(48, st.size);
    s.wi64(56, st.blksize as i64);
    s.wi64(64, st.blocks);
    write_ts(s, 72, st.atime);
    write_ts(s, 88, st.mtime);
    write_ts(s, 104, st.ctime);
}

#[cfg(any(test, target_arch = "aarch64"))]
fn write_aarch64<S: StatSink>(s: &mut S, st: &NewStat) {
    s.zero(STAT_BYTES_AARCH64);
    s.w64(0, st.dev);
    s.w64(8, st.ino);
    s.w32(16, st.mode);
    s.w32(20, st.nlink);
    s.w32(24, st.uid);
    s.w32(28, st.gid);
    s.w64(32, st.rdev);
    s.wi64(48, st.size);
    s.wi32(56, st.blksize as i32);
    s.wi64(64, st.blocks);
    write_ts(s, 72, st.atime);
    write_ts(s, 88, st.mtime);
    write_ts(s, 104, st.ctime);
}

/// Copy Linux `struct stat` to a validated user buffer. # C: O(1)
pub(crate) unsafe fn write_new_stat_user(buf: u64, st: &NewStat) {
    let mut sink = UserSink { base: buf };
    #[cfg(target_arch = "x86_64")]
    write_x86_64(&mut sink, st);
    #[cfg(target_arch = "aarch64")]
    write_aarch64(&mut sink, st);
}

/// Host-test x86_64 `struct stat` encoding. # C: O(1)
#[cfg(test)]
pub(crate) fn write_new_stat_x86_64_bytes(out: &mut [u8], st: &NewStat) {
    write_x86_64(&mut SliceSink { out }, st);
}

/// Host-test aarch64 `struct stat` encoding. # C: O(1)
#[cfg(test)]
pub(crate) fn write_new_stat_aarch64_bytes(out: &mut [u8], st: &NewStat) {
    write_aarch64(&mut SliceSink { out }, st);
}

#[cfg(test)]
mod tests {
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
            fsid: 0, change_cookie: 0, result_mask: 0, attributes: 0, attributes_mask: 0,
        };
        let out = new_stat_from_kstat(&st, 0x0803).unwrap();
        assert_eq!(out.atime, t);
        assert_eq!(out.mtime, Timespec64::ZERO);
        assert_eq!(out.ctime, t);
    }
}
