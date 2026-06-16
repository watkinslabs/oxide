// Read-side stdio + file open/close/seek (docs/59§6 G6c). Unbuffered via
// posix::io (buffering + putc/getc-macro compat is a follow-up). One-char
// ungetc via the FILE pushback slot (file.rs).
#![cfg(feature = "freestanding")]
use super::cookie::cookie_close;
use super::file::{self, alloc_file, fd_of, free_file, is_cookie, is_mem, is_std, mark_read, set_eof, set_unget, stdin_ptr, take_unget, FILE};
use super::memstream::{mem_close, stream_read, stream_seek, stream_tell};
use crate::internal::errno;
use crate::malloc::heap;
use crate::posix::io;

pub(crate) unsafe fn mode_flags(mode: *const u8) -> Option<i32> {
    // SAFETY: mode is a NUL-terminated mode string ("r"/"w"/"a"[+][b]).
    unsafe {
        let mut plus = false;
        let mut i = 0;
        while *mode.add(i) != 0 { if *mode.add(i) == b'+' { plus = true; } i += 1; }
        Some(match *mode {
            b'r' => if plus { io::O_RDWR } else { io::O_RDONLY },
            b'w' => (if plus { io::O_RDWR } else { io::O_WRONLY }) | io::O_CREAT | io::O_TRUNC,
            b'a' => (if plus { io::O_RDWR } else { io::O_WRONLY }) | io::O_CREAT | io::O_APPEND,
            _ => return None,
        })
    }
}

// Initial _flags access bits from a mode string: NO_WRITES for "r" (no '+'),
// NO_READS for "w"/"a" (no '+'); "+" clears both (read+write).
pub(crate) unsafe fn mode_initflags(mode: *const u8) -> i32 {
    // SAFETY: mode is a NUL-terminated open-mode string.
    unsafe {
        let mut plus = false;
        let mut i = 0; while *mode.add(i) != 0 { if *mode.add(i) == b'+' { plus = true; } i += 1; }
        if plus { return 0; }
        match *mode { b'r' => file::IO_NO_WRITES, b'w' | b'a' => file::IO_NO_READS, _ => 0 }
    }
}

// shared one-byte read honouring the pushback slot.
pub(crate) unsafe fn getc_raw(f: *mut FILE) -> i32 {
    // SAFETY: f is a valid stream; reads pushback then one byte from its fd.
    unsafe {
        mark_read(f);
        if let Some(c) = take_unget(f) { return c as i32; }
        let mut b = 0u8;
        if stream_read(f, &mut b as *mut u8, 1) == 1 { b as i32 } else { set_eof(f); -1 }
    }
}

// # C: FILE *fopen(const char *path, const char *mode)
#[no_mangle]
pub unsafe extern "C" fn fopen(path: *const u8, mode: *const u8) -> *mut FILE {
    // SAFETY: path/mode are NUL-terminated; we open then wrap the fd.
    unsafe {
        let flags = match mode_flags(mode) { Some(f) => f, None => { errno::set(22); return core::ptr::null_mut(); } };
        let fd = io::open(path, flags, 0o666);
        if fd < 0 { return core::ptr::null_mut(); }
        let f = alloc_file(fd, mode_initflags(mode));
        if f.is_null() { io::close(fd); errno::set(12); }
        f
    }
}
// # C: FILE *fdopen(int fd, const char *mode)
#[no_mangle]
pub unsafe extern "C" fn fdopen(fd: i32, mode: *const u8) -> *mut FILE {
    // SAFETY: fd is an open descriptor the caller hands to the stream; record
    // the mode's access bits so the GNU introspection can report direction.
    unsafe { let fl = if mode.is_null() { 0 } else { mode_initflags(mode) }; alloc_file(fd, fl) }
}
// # C: FILE *freopen(const char *path, const char *mode, FILE *f)
#[no_mangle]
pub unsafe extern "C" fn freopen(path: *const u8, mode: *const u8, f: *mut FILE) -> *mut FILE {
    // SAFETY: f is a valid stream; reopen its fd onto `path`.
    unsafe {
        if path.is_null() { return f; }
        let flags = match mode_flags(mode) { Some(x) => x, None => return core::ptr::null_mut() };
        let fd = io::open(path, flags, 0o666);
        if fd < 0 { return core::ptr::null_mut(); }
        let old = fd_of(f);
        if old >= 0 { io::close(old); }
        (*f)._fileno = fd;
        (*f)._flags = mode_initflags(mode);
        f
    }
}
// # C: int fclose(FILE *f)
#[no_mangle]
pub unsafe extern "C" fn fclose(f: *mut FILE) -> i32 {
    // SAFETY: f is a valid stream; close its fd and free heap FILEs.
    unsafe {
        if is_std(f) { return 0; }
        if is_mem(f) { mem_close(f); free_file(f); return 0; }
        if is_cookie(f) { cookie_close(f); free_file(f); return 0; }
        let r = io::close(fd_of(f));
        free_file(f);
        if r < 0 { -1 } else { 0 }
    }
}

// # C: size_t fread(void *ptr, size_t size, size_t nmemb, FILE *f)
#[no_mangle]
pub unsafe extern "C" fn fread(ptr: *mut u8, size: usize, nmemb: usize, f: *mut FILE) -> usize {
    // SAFETY: ptr is valid for size*nmemb bytes; f is a readable stream.
    unsafe {
        let total = size.saturating_mul(nmemb);
        if total == 0 { return 0; }
        let mut got = 0usize;
        if let Some(c) = take_unget(f) { *ptr = c; got = 1; }
        if got < total {
            let r = stream_read(f, ptr.add(got), total - got);
            if r > 0 { got += r as usize; }
        }
        if got < total { set_eof(f); }
        got / size.max(1)
    }
}

// # C: int __uflow(FILE *) — get-buffer underflow handler (the getc/getc_unlocked
// macros call this when _IO_read_ptr>=_IO_read_end, always so for our unbuffered
// streams): read and return the next byte, or EOF.
#[no_mangle]
pub unsafe extern "C" fn __uflow(f: *mut FILE) -> i32 {
    // SAFETY: f is a valid readable stream; read one byte via the choke point.
    unsafe { getc_raw(f) }
}
// # C: int __underflow(FILE *) — like __uflow but glibc leaves the byte; we have
// no buffer to peek, so reading + returning is the closest unbuffered behaviour.
#[no_mangle]
pub unsafe extern "C" fn __underflow(f: *mut FILE) -> i32 {
    // SAFETY: f is a valid readable stream; reads one byte via the choke point.
    unsafe { getc_raw(f) }
}

// # C: int fgetc(FILE *) / getc(FILE *)
#[no_mangle]
pub unsafe extern "C" fn fgetc(f: *mut FILE) -> i32 {
    // SAFETY: f is a valid readable stream per the C contract.
    unsafe { getc_raw(f) }
}
#[no_mangle]
pub unsafe extern "C" fn getc(f: *mut FILE) -> i32 {
    // SAFETY: f is a valid readable stream per the C contract.
    unsafe { getc_raw(f) }
}
// # C: int getchar(void)
#[no_mangle]
pub unsafe extern "C" fn getchar() -> i32 {
    // SAFETY: reads one byte from the stdin stream.
    unsafe { getc_raw(stdin_ptr()) }
}

// # C: char *gets(char *s) — read a line from stdin, drop the newline, NUL-
// terminate. Unbounded (deprecated/removed in C11) but still exported by glibc.
#[no_mangle]
pub unsafe extern "C" fn gets(s: *mut u8) -> *mut u8 {
    // SAFETY: s is a caller buffer large enough for the line + NUL; we read
    // bytes from stdin until newline/EOF. NULL on immediate EOF with no input.
    unsafe {
        let mut i = 0usize;
        loop {
            let c = getc_raw(stdin_ptr());
            if c < 0 { if i == 0 { return core::ptr::null_mut(); } break; }
            if c == b'\n' as i32 { break; }
            *s.add(i) = c as u8;
            i += 1;
        }
        *s.add(i) = 0;
        s
    }
}

// # C: int ungetc(int c, FILE *f)
#[no_mangle]
pub unsafe extern "C" fn ungetc(c: i32, f: *mut FILE) -> i32 {
    // SAFETY: f is a valid stream; stash one pushed-back byte.
    unsafe { if c < 0 { return -1; } set_unget(f, c as u8); c & 0xff }
}

// # C: char *fgets(char *buf, int size, FILE *f)
#[no_mangle]
pub unsafe extern "C" fn fgets(buf: *mut u8, size: i32, f: *mut FILE) -> *mut u8 {
    // SAFETY: buf is valid for `size` bytes; reads up to size-1 or newline.
    unsafe {
        if size <= 0 { return core::ptr::null_mut(); }
        let cap = (size - 1) as usize;
        let mut i = 0usize;
        while i < cap {
            let c = getc_raw(f);
            if c < 0 { break; }
            *buf.add(i) = c as u8;
            i += 1;
            if c == b'\n' as i32 { break; }
        }
        if i == 0 { return core::ptr::null_mut(); }
        *buf.add(i) = 0;
        buf
    }
}

// # C: ssize_t getdelim(char **lineptr, size_t *n, int delim, FILE *f)
#[no_mangle]
pub unsafe extern "C" fn getdelim(lineptr: *mut *mut u8, n: *mut usize, delim: i32, f: *mut FILE) -> isize {
    // SAFETY: lineptr/n are valid out-params per C getline; the buffer is
    // (re)allocated through our heap and returned to the caller.
    unsafe {
        if lineptr.is_null() || n.is_null() { errno::set(22); return -1; }
        let mut buf = *lineptr;
        let mut cap = *n;
        if buf.is_null() || cap == 0 { cap = 128; buf = heap::malloc(cap); if buf.is_null() { return -1; } }
        let mut len = 0usize;
        loop {
            let c = getc_raw(f);
            if c < 0 { if len == 0 { *lineptr = buf; *n = cap; return -1; } break; }
            if len + 1 >= cap { cap *= 2; let nb = heap::realloc(buf, cap); if nb.is_null() { return -1; } buf = nb; }
            *buf.add(len) = c as u8;
            len += 1;
            if c == delim { break; }
        }
        *buf.add(len) = 0;
        *lineptr = buf;
        *n = cap;
        len as isize
    }
}
// # C: ssize_t getline(char **lineptr, size_t *n, FILE *f)
#[no_mangle]
pub unsafe extern "C" fn getline(lineptr: *mut *mut u8, n: *mut usize, f: *mut FILE) -> isize {
    // SAFETY: delegates to getdelim with '\n'; same out-param contract.
    unsafe { getdelim(lineptr, n, b'\n' as i32, f) }
}

// # C: int fseek(FILE *f, long off, int whence)
#[no_mangle]
pub unsafe extern "C" fn fseek(f: *mut FILE, off: i64, whence: i32) -> i32 {
    // SAFETY: f is a seekable stream; clears EOF/pushback on success.
    unsafe {
        let _ = take_unget(f);
        if stream_seek(f, off, whence) < 0 { return -1; }
        (*f)._flags &= !file::IO_EOF_SEEN;
        0
    }
}
// # C: long ftell(FILE *) / off_t ftello(FILE *)
#[no_mangle]
pub unsafe extern "C" fn ftell(f: *mut FILE) -> i64 {
    // SAFETY: f is a seekable stream; query the current offset.
    unsafe { stream_tell(f) }
}
#[no_mangle]
pub unsafe extern "C" fn ftello(f: *mut FILE) -> i64 {
    // SAFETY: alias of ftell; f is a seekable stream.
    unsafe { ftell(f) }
}
// # C: void rewind(FILE *)
#[no_mangle]
pub unsafe extern "C" fn rewind(f: *mut FILE) {
    // SAFETY: f is a seekable stream; seek to 0 and clear flags.
    unsafe { fseek(f, 0, io::SEEK_SET); (*f)._flags &= !file::IO_ERR_SEEN; }
}
