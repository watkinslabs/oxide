// Character/string output (docs/59§6 G6). Unbuffered via posix::io::write
// (buffering is a G6 follow-up). Read-side (fread/fgets/getline) + fopen
// land next.
#![cfg(feature = "freestanding")]
use super::file::{fd_of, stdout_ptr, FILE};
use crate::posix::io;
use crate::string::len::strlen_impl;

// # C: size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *f)
#[no_mangle]
pub unsafe extern "C" fn fwrite(ptr: *const u8, size: usize, nmemb: usize, f: *mut FILE) -> usize {
    let total = size.saturating_mul(nmemb);
    if total == 0 { return 0; }
    // SAFETY: ptr is valid for `total` bytes per the C contract; f is a stream.
    let w = unsafe { io::write(fd_of(f), ptr, total) };
    if w <= 0 { 0 } else { (w as usize) / size.max(1) }
}

// # C: int fputs(const char *s, FILE *f)
#[no_mangle]
pub unsafe extern "C" fn fputs(s: *const u8, f: *mut FILE) -> i32 {
    // SAFETY: s is NUL-terminated; f is a stream. Returns ≥0 / EOF(-1).
    unsafe {
        let n = strlen_impl(s);
        if io::write(fd_of(f), s, n) < 0 { -1 } else { 0 }
    }
}

// # C: int puts(const char *s) — writes s + newline to stdout.
#[no_mangle]
pub unsafe extern "C" fn puts(s: *const u8) -> i32 {
    // SAFETY: s is NUL-terminated; write the string then a newline.
    unsafe {
        let fd = fd_of(stdout_ptr());
        let n = strlen_impl(s);
        io::write(fd, s, n);
        io::write(fd, b"\n".as_ptr(), 1);
        0
    }
}

// # C: int fputc(int c, FILE *f)
#[no_mangle]
pub unsafe extern "C" fn fputc(c: i32, f: *mut FILE) -> i32 {
    // SAFETY: f is a stream; write one byte from the stack.
    unsafe {
        let b = c as u8;
        if io::write(fd_of(f), &b as *const u8, 1) == 1 { c & 0xff } else { -1 }
    }
}

// # C: int putc(int c, FILE *f) — same as fputc.
#[no_mangle]
pub unsafe extern "C" fn putc(c: i32, f: *mut FILE) -> i32 {
    // SAFETY: alias of fputc; same stream contract.
    unsafe { fputc(c, f) }
}

// # C: void perror(const char *s) — "[s: ]<strerror(errno)>\n" to stderr
#[no_mangle]
pub unsafe extern "C" fn perror(s: *const u8) {
    // SAFETY: s is null or a NUL-terminated C string; write the optional
    // prefix, the C-locale errno message (without its NUL), and a newline to
    // fd 2 (stderr), each via the unbuffered io::write path.
    unsafe {
        let e = *crate::internal::errno::__errno_location();
        if !s.is_null() && *s != 0 {
            io::write(2, s, strlen_impl(s));
            io::write(2, b": ".as_ptr(), 2);
        }
        let m = crate::string::strerror::msg(e);
        io::write(2, m.as_ptr(), m.len() - 1);
        io::write(2, b"\n".as_ptr(), 1);
    }
}

// # C: int putchar(int c)
#[no_mangle]
pub unsafe extern "C" fn putchar(c: i32) -> i32 {
    // SAFETY: writes a single byte to the stdout stream's descriptor.
    unsafe { fputc(c, stdout_ptr()) }
}

// # C: int fflush(FILE *) — no-op while unbuffered (G6a).
#[no_mangle]
pub unsafe extern "C" fn fflush(_f: *mut FILE) -> i32 { 0 }
