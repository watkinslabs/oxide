// Low-level unistd I/O (docs/59§6 G2/G3; full posix io family at G8).
// libc convention: on error return -1 + set errno (errno::ret_isize).
// `open` is composed from `openat` so x86_64 and aarch64 (which has no
// SYS_open) share one path — the glibc sysdeps approach.
//
// Whole file is C-ABI exports: only built into the shipped artifact.
#![cfg(feature = "freestanding")]
use crate::arch::syscall::{sys0, sys3, sys4};
use crate::internal::errno::ret_isize;
use crate::internal::nr;

pub const AT_FDCWD: i32 = -100;

// # C: ssize_t write(int fd, const void *buf, size_t n)
#[no_mangle]
pub unsafe extern "C" fn write(fd: i32, buf: *const u8, n: usize) -> isize {
    // SAFETY: write(2); kernel validates [buf, buf+n) against the caller's
    // address space and faults rather than corrupting libc.
    ret_isize(unsafe { sys3(nr::WRITE, fd as usize, buf as usize, n) })
}

// # C: ssize_t read(int fd, void *buf, size_t n)
#[no_mangle]
pub unsafe extern "C" fn read(fd: i32, buf: *mut u8, n: usize) -> isize {
    // SAFETY: read(2); kernel validates [buf, buf+n) is writable in the
    // caller's address space before storing.
    ret_isize(unsafe { sys3(nr::READ, fd as usize, buf as usize, n) })
}

// # C: int openat(int dirfd, const char *path, int flags, mode_t mode)
#[no_mangle]
pub unsafe extern "C" fn openat(dirfd: i32, path: *const u8, flags: i32, mode: u32) -> i32 {
    // SAFETY: openat(2); kernel reads the NUL-terminated path from the
    // caller's address space, faulting on a bad pointer.
    ret_isize(unsafe { sys4(nr::OPENAT, dirfd as usize, path as usize, flags as usize, mode as usize) }) as i32
}

// # C: int open(const char *path, int flags, mode_t mode)
#[no_mangle]
pub unsafe extern "C" fn open(path: *const u8, flags: i32, mode: u32) -> i32 {
    // SAFETY: forwards to openat(AT_FDCWD, ...); same pointer contract.
    unsafe { openat(AT_FDCWD, path, flags, mode) }
}

// # C: int close(int fd)
#[no_mangle]
pub unsafe extern "C" fn close(fd: i32) -> i32 {
    // SAFETY: close(2) takes a scalar fd; no memory is dereferenced.
    ret_isize(unsafe { sys3(nr::CLOSE, fd as usize, 0, 0) }) as i32
}

// # C: off_t lseek(int fd, off_t off, int whence)
#[no_mangle]
pub unsafe extern "C" fn lseek(fd: i32, off: i64, whence: i32) -> i64 {
    // SAFETY: lseek(2) on 64-bit takes scalar args; no deref.
    ret_isize(unsafe { sys3(nr::LSEEK, fd as usize, off as usize, whence as usize) }) as i64
}

// # C: pid_t getpid(void) — always succeeds, never sets errno.
#[no_mangle]
pub unsafe extern "C" fn getpid() -> i32 {
    // SAFETY: getpid(2) takes no args and cannot fail.
    (unsafe { sys0(nr::GETPID) }) as i32
}
