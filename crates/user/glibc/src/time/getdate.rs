// <time.h> getdate/getdate_r (docs/59§6) — parse a date string against the
// strptime templates listed (one per line) in the file named by $DATEMSK.
// getdate fills a static struct tm and sets getdate_err on failure; getdate_r
// fills a caller tm and returns the error code directly. C ABI only.
#![cfg(feature = "freestanding")]
use crate::stdio::file::FILE;
use crate::string::len::strlen_impl;
use crate::time::tm::tm;
use core::cell::UnsafeCell;

// getdate error codes (host glibc getdate.3).
const GD_NO_DATEMSK: i32 = 1; // DATEMSK unset or null
const GD_OPEN_FAIL: i32 = 3; // template file unreadable
const GD_NO_MATCH: i32 = 7; // no template line matched the input

extern "C" {
    fn getenv(name: *const u8) -> *mut u8;
    fn fopen(path: *const u8, mode: *const u8) -> *mut FILE;
    fn fclose(f: *mut FILE) -> i32;
    fn fgets(buf: *mut u8, size: i32, f: *mut FILE) -> *mut u8;
}

// # C: extern int getdate_err;
struct Err32(UnsafeCell<i32>);
// SAFETY: process-global getdate_err C symbol; single-threaded until TLS lands.
unsafe impl Sync for Err32 {}
#[no_mangle]
static getdate_err: Err32 = Err32(UnsafeCell::new(0));

struct Tm(UnsafeCell<tm>);
// SAFETY: process-global getdate result; single-threaded until TLS lands.
unsafe impl Sync for Tm {}
static RES: Tm = Tm(UnsafeCell::new(tm {
    tm_sec: 0, tm_min: 0, tm_hour: 0, tm_mday: 0, tm_mon: 0, tm_year: 0,
    tm_wday: 0, tm_yday: 0, tm_isdst: -1, tm_gmtoff: 0, tm_zone: core::ptr::null(),
}));

// # C: struct tm *getdate(const char *string)
#[no_mangle]
pub unsafe extern "C" fn getdate(string: *const u8) -> *mut tm {
    // SAFETY: string is NUL-terminated; getdate_r fills the process-global tm
    // and on error stashes the code in getdate_err (returning NULL).
    unsafe {
        let out = RES.0.get();
        let e = getdate_r(string, out);
        if e != 0 { *getdate_err.0.get() = e; core::ptr::null_mut() } else { out }
    }
}

// # C: int getdate_r(const char *string, struct tm *res)
#[no_mangle]
pub unsafe extern "C" fn getdate_r(string: *const u8, res: *mut tm) -> i32 {
    // SAFETY: string/res are valid; read $DATEMSK, open the template file, try
    // each line as a strptime format against `string`, filling res on a match.
    unsafe {
        let msk = getenv(c"DATEMSK".as_ptr() as *const u8);
        if msk.is_null() || *msk == 0 { return GD_NO_DATEMSK; }
        let f = fopen(msk, c"r".as_ptr() as *const u8);
        if f.is_null() { return GD_OPEN_FAIL; }
        let mut line = [0u8; 512];
        let mut matched = false;
        while !fgets(line.as_mut_ptr(), line.len() as i32, f).is_null() {
            // strip a trailing newline so the format doesn't require one.
            let mut n = strlen_impl(line.as_ptr());
            while n > 0 && (line[n - 1] == b'\n' || line[n - 1] == b'\r') { n -= 1; line[n] = 0; }
            if n == 0 { continue; }
            // reset to a clean tm for each attempt.
            *res = tm { tm_sec: 0, tm_min: 0, tm_hour: 0, tm_mday: 0, tm_mon: 0, tm_year: 0,
                        tm_wday: 0, tm_yday: 0, tm_isdst: -1, tm_gmtoff: 0, tm_zone: core::ptr::null() };
            if strptime_match(string, line.as_ptr(), res) { matched = true; break; }
        }
        fclose(f);
        if matched { 0 } else { GD_NO_MATCH }
    }
}

// Minimal strptime: returns true if `fmt` fully consumes a prefix of `s`,
// filling *out. Supports %Y %y %m %d %H %M %S %j and literal/whitespace match.
unsafe fn strptime_match(s: *const u8, fmt: *const u8, out: *mut tm) -> bool {
    // SAFETY: s/fmt are NUL-terminated; out is a writable struct tm. We walk
    // both cursors, reading fixed-width decimal fields for conversion specs.
    unsafe {
        let (mut si, mut fi) = (0usize, 0usize);
        loop {
            let fc = *fmt.add(fi);
            if fc == 0 { return true; } // format exhausted = match
            if fc == b'%' {
                fi += 1;
                let spec = *fmt.add(fi); fi += 1;
                match spec {
                    b'%' => { if *s.add(si) != b'%' { return false; } si += 1; }
                    b'n' | b't' => { while is_sp(*s.add(si)) { si += 1; } }
                    b'Y' => { let (v, c) = read_num(s, si, 4); if c == 0 { return false; } (*out).tm_year = v - 1900; si += c; }
                    b'y' => { let (v, c) = read_num(s, si, 2); if c == 0 { return false; } (*out).tm_year = if v < 69 { v + 100 } else { v }; si += c; }
                    b'm' => { let (v, c) = read_num(s, si, 2); if c == 0 { return false; } (*out).tm_mon = v - 1; si += c; }
                    b'd' | b'e' => { let (v, c) = read_num(s, si, 2); if c == 0 { return false; } (*out).tm_mday = v; si += c; }
                    b'H' => { let (v, c) = read_num(s, si, 2); if c == 0 { return false; } (*out).tm_hour = v; si += c; }
                    b'M' => { let (v, c) = read_num(s, si, 2); if c == 0 { return false; } (*out).tm_min = v; si += c; }
                    b'S' => { let (v, c) = read_num(s, si, 2); if c == 0 { return false; } (*out).tm_sec = v; si += c; }
                    b'j' => { let (v, c) = read_num(s, si, 3); if c == 0 { return false; } (*out).tm_yday = v - 1; si += c; }
                    _ => return false, // unsupported conversion
                }
            } else if is_sp(fc) {
                fi += 1; while is_sp(*s.add(si)) { si += 1; }
            } else {
                if *s.add(si) != fc { return false; } si += 1; fi += 1;
            }
        }
    }
}

fn is_sp(c: u8) -> bool { c == b' ' || c == b'\t' || c == b'\n' || c == b'\r' }

// Read up to `max` decimal digits (leading spaces skipped); returns (value,
// digits consumed including skipped spaces). count==0 ⇒ no digit found.
unsafe fn read_num(s: *const u8, start: usize, max: usize) -> (i32, usize) {
    // SAFETY: s is NUL-terminated; we read at most `max` ASCII digits.
    unsafe {
        let mut i = start;
        while is_sp(*s.add(i)) { i += 1; }
        let lead = i - start;
        let mut v = 0i32; let mut d = 0;
        while d < max && (*s.add(i)).is_ascii_digit() { v = v * 10 + (*s.add(i) - b'0') as i32; i += 1; d += 1; }
        if d == 0 { (0, 0) } else { (v, lead + d) }
    }
}
