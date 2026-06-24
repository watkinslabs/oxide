// Obsolete libresolv date helper: yyyymmddhhmmss -> uint32_t seconds since
// 1970-01-01 UTC, using glibc/BIND's historical 32-bit wrapping arithmetic.
#![cfg(feature = "freestanding")]
use core::ffi::c_char;

fn strlen(s: *const u8) -> usize {
    let mut n = 0;
    // SAFETY: caller supplies a NUL-terminated C string.
    unsafe { while *s.add(n) != 0 { n += 1; } }
    n
}

fn datepart(buf: *const u8, size: usize, min: i32, max: i32, errp: *mut i32) -> i32 {
    let mut result = 0i32;
    // SAFETY: ns_datetosecs passes fields within its 14-byte input and a live
    // errp pointer; invalid digits set the sticky parse error flag.
    unsafe {
        for i in 0..size {
            let c = *buf.add(i);
            if !c.is_ascii_digit() { *errp = 1; }
            result = result * 10 + c as i32 - b'0' as i32;
        }
        if result < min || result > max { *errp = 1; }
    }
    result
}

fn isleap(y: i32) -> bool { (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 }

// # C: uint32_t ns_datetosecs(const char *cp, int *errp)
#[no_mangle]
pub unsafe extern "C" fn ns_datetosecs(cp: *const c_char, errp: *mut i32) -> u32 {
    // SAFETY: cp is a NUL-terminated date string and errp is writable. glibc
    // requires exactly yyyymmddhhmmss and returns a wrapping uint32 timestamp.
    unsafe {
        let s = cp as *const u8;
        if strlen(s) != 14 { *errp = 1; return 0; }
        *errp = 0;
        let year = datepart(s, 4, 1990, 9999, errp);
        let mon = datepart(s.add(4), 2, 1, 12, errp);
        let mday = datepart(s.add(6), 2, 1, 31, errp);
        let hour = datepart(s.add(8), 2, 0, 23, errp);
        let min = datepart(s.add(10), 2, 0, 59, errp);
        let sec = datepart(s.add(12), 2, 0, 59, errp);
        if *errp != 0 { return 0; }

        const SECS_PER_DAY: u32 = 24 * 60 * 60;
        const DAYS_PER_MONTH: [i32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        let mut result = sec as u32;
        result = result.wrapping_add((min as u32).wrapping_mul(60));
        result = result.wrapping_add((hour as u32).wrapping_mul(60 * 60));
        result = result.wrapping_add(((mday - 1) as u32).wrapping_mul(SECS_PER_DAY));
        let mut mdays = 0i32;
        for i in 0..(mon - 1) as usize { mdays += DAYS_PER_MONTH[i]; }
        result = result.wrapping_add((mdays as u32).wrapping_mul(SECS_PER_DAY));
        if mon > 2 && isleap(year) { result = result.wrapping_add(SECS_PER_DAY); }
        result = result.wrapping_add(((year - 1970) as u32).wrapping_mul(SECS_PER_DAY.wrapping_mul(365)));
        for y in 1970..year {
            if isleap(y) { result = result.wrapping_add(SECS_PER_DAY); }
        }
        result
    }
}
