// <mntent.h> (docs/59§6) — parse fstab/mtab-style files. getmntent reads one
// non-comment line into a struct mntent whose string fields point into a line
// buffer; setmntent/endmntent wrap fopen/fclose; hasmntopt searches mnt_opts.
// C ABI only.
#![cfg(feature = "freestanding")]
use crate::stdio::file::FILE;
use crate::string::len::strlen_impl;
use core::cell::UnsafeCell;

#[repr(C)]
pub struct mntent {
    pub mnt_fsname: *mut u8,
    pub mnt_dir: *mut u8,
    pub mnt_type: *mut u8,
    pub mnt_opts: *mut u8,
    pub mnt_freq: i32,
    pub mnt_passno: i32,
}

extern "C" {
    fn fopen(path: *const u8, mode: *const u8) -> *mut FILE;
    fn fclose(f: *mut FILE) -> i32;
    fn fgets(buf: *mut u8, size: i32, f: *mut FILE) -> *mut u8;
}

fn is_ws(c: u8) -> bool { c == b' ' || c == b'\t' || c == b'\n' || c == b'\r' }

// # C: FILE *setmntent(const char *file, const char *mode)
#[no_mangle]
pub unsafe extern "C" fn setmntent(file: *const u8, mode: *const u8) -> *mut FILE {
    // SAFETY: file/mode are NUL-terminated; a thin fopen wrapper.
    unsafe { fopen(file, mode) }
}
// # C: int endmntent(FILE *stream)
#[no_mangle]
pub unsafe extern "C" fn endmntent(f: *mut FILE) -> i32 {
    // SAFETY: f came from setmntent; close it. Always returns 1 (per glibc).
    unsafe { if !f.is_null() { fclose(f); } 1 }
}

// Parse one mntent out of `line` (NUL-terminating fields in place). Returns
// false if the line is blank/comment (caller reads the next line).
unsafe fn parse(line: *mut u8, m: *mut mntent) -> bool {
    // SAFETY: line is a writable NUL-terminated buffer; we split on whitespace,
    // writing NULs and recording field pointers into *m.
    unsafe {
        let mut i = 0;
        while is_ws(*line.add(i)) { i += 1; }
        let c0 = *line.add(i);
        if c0 == 0 || c0 == b'#' { return false; }
        // up to 4 string fields then 2 integers
        let mut fields: [*mut u8; 6] = [core::ptr::null_mut(); 6];
        let mut fc = 0;
        while fc < 6 {
            while is_ws(*line.add(i)) { i += 1; }
            if *line.add(i) == 0 { break; }
            fields[fc] = line.add(i);
            fc += 1;
            while *line.add(i) != 0 && !is_ws(*line.add(i)) { i += 1; }
            if *line.add(i) != 0 { *line.add(i) = 0; i += 1; }
        }
        if fc < 4 { return false; } // need at least fsname/dir/type/opts
        (*m).mnt_fsname = fields[0];
        (*m).mnt_dir = fields[1];
        (*m).mnt_type = fields[2];
        (*m).mnt_opts = fields[3];
        (*m).mnt_freq = if fc > 4 { atoi_(fields[4]) } else { 0 };
        (*m).mnt_passno = if fc > 5 { atoi_(fields[5]) } else { 0 };
        true
    }
}

unsafe fn atoi_(s: *mut u8) -> i32 {
    // SAFETY: s is a NUL-terminated field; parse a leading signed decimal.
    unsafe {
        let mut i = 0; let mut neg = false; let mut v = 0i32;
        if *s == b'-' { neg = true; i = 1; } else if *s == b'+' { i = 1; }
        while (*s.add(i)).is_ascii_digit() { v = v * 10 + (*s.add(i) - b'0') as i32; i += 1; }
        if neg { -v } else { v }
    }
}

// # C: struct mntent *getmntent_r(FILE *stream, struct mntent *m, char *buf, int buflen)
#[no_mangle]
pub unsafe extern "C" fn getmntent_r(f: *mut FILE, m: *mut mntent, buf: *mut u8, buflen: i32) -> *mut mntent {
    // SAFETY: f is a mntent stream; m/buf are caller storage (buf >= buflen);
    // read non-comment lines into buf and parse into m.
    unsafe {
        loop {
            if fgets(buf, buflen, f).is_null() { return core::ptr::null_mut(); }
            if parse(buf, m) { return m; }
        }
    }
}

struct Line(UnsafeCell<[u8; 4096]>);
// SAFETY: process-global getmntent line buffer; single-threaded until TLS.
unsafe impl Sync for Line {}
static LINE: Line = Line(UnsafeCell::new([0u8; 4096]));
struct Ent(UnsafeCell<mntent>);
unsafe impl Sync for Ent {}
static ENT: Ent = Ent(UnsafeCell::new(mntent {
    mnt_fsname: core::ptr::null_mut(), mnt_dir: core::ptr::null_mut(),
    mnt_type: core::ptr::null_mut(), mnt_opts: core::ptr::null_mut(),
    mnt_freq: 0, mnt_passno: 0,
}));

// # C: struct mntent *getmntent(FILE *stream)
#[no_mangle]
pub unsafe extern "C" fn getmntent(f: *mut FILE) -> *mut mntent {
    // SAFETY: non-reentrant form over the process-global line buffer + entry.
    unsafe { getmntent_r(f, ENT.0.get(), (*LINE.0.get()).as_mut_ptr(), 4096) }
}

// # C: char *hasmntopt(const struct mntent *m, const char *opt)
#[no_mangle]
pub unsafe extern "C" fn hasmntopt(m: *const mntent, opt: *const u8) -> *mut u8 {
    // SAFETY: m is a valid mntent; opt NUL-terminated. Scan the comma-separated
    // mnt_opts for `opt` as a whole option (start of string or after a comma).
    unsafe {
        let opts = (*m).mnt_opts;
        if opts.is_null() { return core::ptr::null_mut(); }
        let ol = strlen_impl(opt);
        let mut p = opts;
        loop {
            // p is at the start of an option
            let mut k = 0;
            while k < ol && *p.add(k) == *opt.add(k) { k += 1; }
            if k == ol {
                let after = *p.add(ol);
                if after == 0 || after == b',' || after == b'=' { return p; }
            }
            // advance to the next option after a comma
            while *p != 0 && *p != b',' { p = p.add(1); }
            if *p == 0 { return core::ptr::null_mut(); }
            p = p.add(1);
        }
    }
}
