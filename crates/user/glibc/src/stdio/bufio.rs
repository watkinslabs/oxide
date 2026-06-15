// Buffering control + popen/pclose + tmpfile + getw/putw (docs/59§6 G6).
// Our streams are unbuffered; setvbuf/setbuf record the buffer + mode in the
// glibc FILE fields so introspection (__fbufsize/__flbf) stays consistent.
// popen forks /bin/sh -c with one pipe end dup'd onto the child's stdio.
#![cfg(feature = "freestanding")]
// Byte-string + .as_ptr() is the crate idiom for *const u8 C strings (matches
// posix::process); c"" literals are *const i8 and need a cast at every call.
#![allow(clippy::manual_c_str_literals)]
use super::file::{popen_pid, set_buf, set_bufmode, set_popen_pid, FILE};
use super::read::{fclose, fgetc};
use super::put::fputc;
use crate::posix::fd::{dup2, pipe};
use crate::posix::io;
use crate::posix::process::{execve, fork, waitpid};
use crate::stdlib::env::current_environ;
use crate::stdlib::exit::exit_group;
use crate::stdlib::mkstemp::mkstemp;

const BUFSIZ: usize = 8192;
// setvbuf modes (stdio.h): full, line, none.
const IOFBF: i32 = 0;
const IOLBF: i32 = 1;
const IONBF: i32 = 2;
const EINVAL: i32 = 22;

// # C: int setvbuf(FILE *f, char *buf, int mode, size_t size)
#[no_mangle]
pub unsafe extern "C" fn setvbuf(f: *mut FILE, buf: *mut u8, mode: i32, size: usize) -> i32 {
    // SAFETY: f is a valid stream; buf is null or valid for `size` bytes. We
    // record the user's buffer + mode in the FILE; I/O stays unbuffered.
    unsafe {
        if mode != IOFBF && mode != IOLBF && mode != IONBF { crate::internal::errno::set(EINVAL); return -1; }
        set_bufmode(f, mode);
        if mode == IONBF { set_buf(f, core::ptr::null_mut(), 0); }
        else { set_buf(f, buf, if buf.is_null() { BUFSIZ } else { size }); }
        0
    }
}
// # C: void setbuf(FILE *f, char *buf) — _IOFBF/BUFSIZ if buf, else _IONBF.
#[no_mangle]
pub unsafe extern "C" fn setbuf(f: *mut FILE, buf: *mut u8) {
    // SAFETY: f is a valid stream; buf is null or valid for BUFSIZ bytes.
    unsafe { let _ = setvbuf(f, buf, if buf.is_null() { IONBF } else { IOFBF }, BUFSIZ); }
}
// # C: void setbuffer(FILE *f, char *buf, size_t size) — BSD setbuf w/ size.
#[no_mangle]
pub unsafe extern "C" fn setbuffer(f: *mut FILE, buf: *mut u8, size: usize) {
    // SAFETY: f is a valid stream; buf is null or valid for `size` bytes.
    unsafe { let _ = setvbuf(f, buf, if buf.is_null() { IONBF } else { IOFBF }, size); }
}
// # C: void setlinebuf(FILE *f) — BSD: line-buffer the stream.
#[no_mangle]
pub unsafe extern "C" fn setlinebuf(f: *mut FILE) {
    // SAFETY: f is a valid stream; switch it to line-buffered mode.
    unsafe { let _ = setvbuf(f, core::ptr::null_mut(), IOLBF, BUFSIZ); }
}

// # C: FILE *tmpfile(void) — anonymous read/write temp file, auto-unlinked.
#[no_mangle]
pub unsafe extern "C" fn tmpfile() -> *mut FILE {
    // SAFETY: build a unique /tmp path via mkstemp, unlink it (stays open),
    // and wrap the fd in a "w+" stream.
    unsafe {
        let mut tmpl = *b"/tmp/tmpf.XXXXXX\0";
        let fd = mkstemp(tmpl.as_mut_ptr());
        if fd < 0 { return core::ptr::null_mut(); }
        crate::posix::fs::unlink(tmpl.as_ptr());
        super::read::fdopen(fd, b"w+\0".as_ptr())
    }
}
// # C: FILE *tmpfile64(void) — LP64 alias of tmpfile.
#[no_mangle]
pub unsafe extern "C" fn tmpfile64() -> *mut FILE {
    // SAFETY: LP64 alias of tmpfile; no off_t-typed arguments to widen.
    unsafe { tmpfile() }
}

// # C: FILE *popen(const char *command, const char *type)
#[no_mangle]
pub unsafe extern "C" fn popen(command: *const u8, ty: *const u8) -> *mut FILE {
    // SAFETY: command/type are NUL-terminated; fork /bin/sh -c command with one
    // pipe end on the parent FILE and the other dup'd onto the child's stdio.
    unsafe {
        if command.is_null() || ty.is_null() { crate::internal::errno::set(EINVAL); return core::ptr::null_mut(); }
        let reading = *ty == b'r';
        if !reading && *ty != b'w' { crate::internal::errno::set(EINVAL); return core::ptr::null_mut(); }
        let mut fds = [0i32; 2];
        if pipe(fds.as_mut_ptr()) < 0 { return core::ptr::null_mut(); }
        // reading: parent reads fds[0], child writes fds[1] -> child stdout.
        // writing: parent writes fds[1], child reads fds[0] -> child stdin.
        let (parent_fd, child_fd, child_target) = if reading { (fds[0], fds[1], 1) } else { (fds[1], fds[0], 0) };
        let pid = fork();
        if pid < 0 { io::close(fds[0]); io::close(fds[1]); return core::ptr::null_mut(); }
        if pid == 0 {
            dup2(child_fd, child_target);
            io::close(fds[0]); io::close(fds[1]);
            let argv: [*const u8; 4] = [b"sh\0".as_ptr(), b"-c\0".as_ptr(), command, core::ptr::null()];
            execve(b"/bin/sh\0".as_ptr(), argv.as_ptr(), current_environ() as *const *const u8);
            exit_group(127);
        }
        io::close(child_fd);
        let f = super::read::fdopen(parent_fd, if reading { b"r\0".as_ptr() } else { b"w\0".as_ptr() });
        if f.is_null() { io::close(parent_fd); return core::ptr::null_mut(); }
        set_popen_pid(f, pid);
        f
    }
}
// # C: int pclose(FILE *f) — close the popen stream, reap the shell.
#[no_mangle]
pub unsafe extern "C" fn pclose(f: *mut FILE) -> i32 {
    // SAFETY: f is a stream returned by popen; close its fd then waitpid the
    // recorded child, returning the wait status (or -1 on failure).
    unsafe {
        if f.is_null() { crate::internal::errno::set(EINVAL); return -1; }
        let pid = popen_pid(f);
        fclose(f);
        if pid <= 0 { return -1; }
        let mut status = 0i32;
        if waitpid(pid, &mut status, 0) < 0 { -1 } else { status }
    }
}

// # C: int fcloseall(void) — close all open streams (GNU).
#[no_mangle]
pub unsafe extern "C" fn fcloseall() -> i32 {
    // SAFETY: flush the std streams (unbuffered fd streams need no per-stream
    // teardown; heap streams are owned by their callers). Returns 0.
    unsafe { super::put::fflush(core::ptr::null_mut()); 0 }
}

// # C: int getw(FILE *f) — read a machine int via getc; EOF on short read.
#[no_mangle]
pub unsafe extern "C" fn getw(f: *mut FILE) -> i32 {
    // SAFETY: f is a readable stream; assemble sizeof(int)=4 bytes (host order).
    unsafe {
        let mut b = [0u8; 4];
        for slot in b.iter_mut() { let c = fgetc(f); if c < 0 { return -1; } *slot = c as u8; }
        i32::from_ne_bytes(b)
    }
}
// # C: int putw(int w, FILE *f) — write a machine int via putc; 0 ok / EOF.
#[no_mangle]
pub unsafe extern "C" fn putw(w: i32, f: *mut FILE) -> i32 {
    // SAFETY: f is a writable stream; emit the int's 4 bytes (host order).
    unsafe {
        let b = w.to_ne_bytes();
        for byte in b.iter() { if fputc(*byte as i32, f) < 0 { return -1; } }
        0
    }
}
