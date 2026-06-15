// LFS (_FILE_OFFSET_BITS=64) stdio aliases + fpos round-trips (docs/59§6 G6).
// On LP64 off_t is already 64-bit, so the *64 forms are exact aliases of the
// base functions. fpos_t / fpos64_t match glibc's _G_fpos{,64}_t layout
// ({ __off_t __pos; __mbstate_t __state; } = 16 bytes); we use only __pos.
#![cfg(feature = "freestanding")]
use super::file::{Fpos, FILE};
use super::read::{fopen, freopen, fseek, ftell};
use crate::posix::io;

// # C: FILE *fopen64(const char *path, const char *mode)
#[no_mangle]
pub unsafe extern "C" fn fopen64(path: *const u8, mode: *const u8) -> *mut FILE {
    // SAFETY: LP64 alias of fopen; path/mode are NUL-terminated.
    unsafe { fopen(path, mode) }
}
// # C: FILE *freopen64(const char *path, const char *mode, FILE *f)
#[no_mangle]
pub unsafe extern "C" fn freopen64(path: *const u8, mode: *const u8, f: *mut FILE) -> *mut FILE {
    // SAFETY: LP64 alias of freopen; f is a valid stream.
    unsafe { freopen(path, mode, f) }
}

// # C: int fseeko(FILE *f, off_t off, int whence)
#[no_mangle]
pub unsafe extern "C" fn fseeko(f: *mut FILE, off: i64, whence: i32) -> i32 {
    // SAFETY: off_t is 64-bit on LP64; delegate to the byte-offset fseek.
    unsafe { fseek(f, off, whence) }
}
// # C: off_t ftello(FILE *f) — defined in read.rs; ftello64 mirrors it here.
// # C: int fseeko64(FILE *f, off64_t off, int whence)
#[no_mangle]
pub unsafe extern "C" fn fseeko64(f: *mut FILE, off: i64, whence: i32) -> i32 {
    // SAFETY: LP64 alias of fseeko; f is a seekable stream.
    unsafe { fseek(f, off, whence) }
}
// # C: off64_t ftello64(FILE *f)
#[no_mangle]
pub unsafe extern "C" fn ftello64(f: *mut FILE) -> i64 {
    // SAFETY: LP64 alias of ftello; f is a seekable stream.
    unsafe { ftell(f) }
}

// # C: int fgetpos(FILE *f, fpos_t *pos)
#[no_mangle]
pub unsafe extern "C" fn fgetpos(f: *mut FILE, pos: *mut Fpos) -> i32 {
    // SAFETY: pos is a writable fpos_t out-param; record the current offset.
    unsafe {
        if pos.is_null() { crate::internal::errno::set(22); return -1; }
        let off = ftell(f);
        if off < 0 { return -1; }
        (*pos).__pos = off; (*pos).__state = [0; 8];
        0
    }
}
// # C: int fsetpos(FILE *f, const fpos_t *pos)
#[no_mangle]
pub unsafe extern "C" fn fsetpos(f: *mut FILE, pos: *const Fpos) -> i32 {
    // SAFETY: pos points to a valid fpos_t obtained from fgetpos; seek to it.
    unsafe {
        if pos.is_null() { crate::internal::errno::set(22); return -1; }
        if fseek(f, (*pos).__pos, io::SEEK_SET) < 0 { -1 } else { 0 }
    }
}
// # C: int fgetpos64(FILE *f, fpos64_t *pos)
#[no_mangle]
pub unsafe extern "C" fn fgetpos64(f: *mut FILE, pos: *mut Fpos) -> i32 {
    // SAFETY: LP64 alias of fgetpos; fpos64_t shares the layout.
    unsafe { fgetpos(f, pos) }
}
// # C: int fsetpos64(FILE *f, const fpos64_t *pos)
#[no_mangle]
pub unsafe extern "C" fn fsetpos64(f: *mut FILE, pos: *const Fpos) -> i32 {
    // SAFETY: LP64 alias of fsetpos; fpos64_t shares the layout.
    unsafe { fsetpos(f, pos) }
}
