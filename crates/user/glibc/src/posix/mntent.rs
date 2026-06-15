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
    fn fputc(c: i32, f: *mut FILE) -> i32;
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
        for fp in fields.iter().take(4) { unescape(*fp); } // decode \\0NN escapes in place
        (*m).mnt_fsname = fields[0];
        (*m).mnt_dir = fields[1];
        (*m).mnt_type = fields[2];
        (*m).mnt_opts = fields[3];
        (*m).mnt_freq = if fc > 4 { atoi_(fields[4]) } else { 0 };
        (*m).mnt_passno = if fc > 5 { atoi_(fields[5]) } else { 0 };
        true
    }
}

// Decode glibc's \\0NN octal escapes (\\040 \\011 \\012 \\134) in place; a
// 3-digit octal run after a backslash collapses to one byte, shifting the tail.
unsafe fn unescape(s: *mut u8) {
    // SAFETY: s is a NUL-terminated field within the line buffer; rewriting it
    // in place only shrinks it, so it stays within its original allocation.
    unsafe {
        if s.is_null() { return; }
        let (mut r, mut w) = (0usize, 0usize);
        loop {
            let c = *s.add(r);
            if c == 0 { *s.add(w) = 0; return; }
            if c == b'\\' && is_oct(*s.add(r + 1)) && is_oct(*s.add(r + 2)) && is_oct(*s.add(r + 3)) {
                let v = ((*s.add(r + 1) - b'0') << 6) | ((*s.add(r + 2) - b'0') << 3) | (*s.add(r + 3) - b'0');
                *s.add(w) = v; w += 1; r += 4;
            } else { *s.add(w) = c; w += 1; r += 1; }
        }
    }
}
fn is_oct(c: u8) -> bool { (b'0'..=b'7').contains(&c) }

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

// Write one byte to f, escaping space/tab/newline/backslash as octal \\0NN
// per glibc's mangle_mntent so the line round-trips through getmntent's split.
unsafe fn put_escaped(f: *mut FILE, c: u8) {
    // SAFETY: f is a writable FILE* opened in append/write mode by the caller
    // of addmntent; we emit either c or its 3-digit octal escape sequence.
    unsafe {
        let oct = match c { b' ' => Some(0o40u8), b'\t' => Some(0o11), b'\n' => Some(0o12), b'\\' => Some(0o134), _ => None };
        match oct {
            None => { fputc(c as i32, f); }
            Some(v) => {
                fputc(b'\\' as i32, f);
                fputc((b'0' + (v >> 6)) as i32, f);
                fputc((b'0' + ((v >> 3) & 7)) as i32, f);
                fputc((b'0' + (v & 7)) as i32, f);
            }
        }
    }
}

// Write a NUL-terminated field with escaping, or "-" if the pointer is null
// (glibc emits "-" for a missing fsname/dir/type/opts so the line stays 6-col).
unsafe fn put_field(f: *mut FILE, s: *const u8) {
    // SAFETY: s is null or a NUL-terminated C string supplied in the mntent;
    // emit each byte through put_escaped into the append-mode FILE* f.
    unsafe {
        if s.is_null() { fputc(b'-' as i32, f); return; }
        let mut i = 0; let mut any = false;
        while *s.add(i) != 0 { put_escaped(f, *s.add(i)); i += 1; any = true; }
        if !any { fputc(b'-' as i32, f); }
    }
}

unsafe fn put_int(f: *mut FILE, mut v: i32) {
    // SAFETY: f is the append-mode FILE*; emit a signed decimal integer field.
    unsafe {
        if v < 0 { fputc(b'-' as i32, f); v = -v; }
        let mut digs = [0u8; 12]; let mut n = 0;
        loop { digs[n] = b'0' + (v % 10) as u8; v /= 10; n += 1; if v == 0 { break; } }
        while n > 0 { n -= 1; fputc(digs[n] as i32, f); }
    }
}

// # C: int addmntent(FILE *stream, const struct mntent *mnt)
#[no_mangle]
pub unsafe extern "C" fn addmntent(f: *mut FILE, m: *const mntent) -> i32 {
    // SAFETY: f is a FILE* opened for append/write; m is a valid mntent whose
    // string fields are null or NUL-terminated. Emit one fstab line with field
    // escaping, returning 0 on success (1 on a null arg, per glibc EOF guard).
    unsafe {
        if f.is_null() || m.is_null() { return 1; }
        put_field(f, (*m).mnt_fsname); fputc(b' ' as i32, f);
        put_field(f, (*m).mnt_dir);    fputc(b' ' as i32, f);
        put_field(f, (*m).mnt_type);   fputc(b' ' as i32, f);
        put_field(f, (*m).mnt_opts);   fputc(b' ' as i32, f);
        put_int(f, (*m).mnt_freq);     fputc(b' ' as i32, f);
        put_int(f, (*m).mnt_passno);   fputc(b'\n' as i32, f);
        0
    }
}
