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

// open(2) flags (asm-generic / x86_64 — same values both arches).
pub const O_RDONLY: i32 = 0;
pub const O_WRONLY: i32 = 1;
pub const O_RDWR: i32 = 2;
pub const O_CREAT: i32 = 0o100;
pub const O_TRUNC: i32 = 0o1000;
pub const O_APPEND: i32 = 0o2000;
pub const O_DIRECTORY: i32 = 0o200000;
pub const O_CLOEXEC: i32 = 0o2000000;
// lseek(2) whence.
pub const SEEK_SET: i32 = 0;
pub const SEEK_CUR: i32 = 1;
pub const SEEK_END: i32 = 2;

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

// # C: int creat(const char *path, mode_t mode) — open O_WRONLY|O_CREAT|O_TRUNC
#[no_mangle]
pub unsafe extern "C" fn creat(path: *const u8, mode: u32) -> i32 {
    // SAFETY: forwards to open with the creat flag set; same pointer contract.
    unsafe { open(path, O_WRONLY | O_CREAT | O_TRUNC, mode) }
}

// # C: ssize_t pread(int fd, void *buf, size_t n, off_t off)
#[no_mangle]
pub unsafe extern "C" fn pread(fd: i32, buf: *mut u8, n: usize, off: i64) -> isize {
    // SAFETY: pread(2); kernel writes up to n bytes into buf at file offset off.
    ret_isize(unsafe { sys4(nr::PREAD64, fd as usize, buf as usize, n, off as usize) })
}
// # C: ssize_t pwrite(int fd, const void *buf, size_t n, off_t off)
#[no_mangle]
pub unsafe extern "C" fn pwrite(fd: i32, buf: *const u8, n: usize, off: i64) -> isize {
    // SAFETY: pwrite(2); kernel reads up to n bytes from buf, writing at off.
    ret_isize(unsafe { sys4(nr::PWRITE64, fd as usize, buf as usize, n, off as usize) })
}

// LFS aliases — on LP64 off64_t == off_t, so these equal the base calls.
// # C: int open64(const char *, int, mode_t)
// SAFETY: LFS alias of open; identical args on LP64. Forwards.
#[no_mangle] pub unsafe extern "C" fn open64(path: *const u8, flags: i32, mode: u32) -> i32 { unsafe { open(path, flags, mode) } }
// # C: int openat64(int, const char *, int, mode_t)
// SAFETY: LFS alias of openat; identical args on LP64. Forwards.
#[no_mangle] pub unsafe extern "C" fn openat64(d: i32, path: *const u8, flags: i32, mode: u32) -> i32 { unsafe { openat(d, path, flags, mode) } }
// # C: int creat64(const char *, mode_t)
// SAFETY: LFS alias of creat; identical args on LP64. Forwards.
#[no_mangle] pub unsafe extern "C" fn creat64(path: *const u8, mode: u32) -> i32 { unsafe { creat(path, mode) } }
// # C: off64_t lseek64(int, off64_t, int)
// SAFETY: LFS alias of lseek; off64_t == off_t on LP64. Forwards.
#[no_mangle] pub unsafe extern "C" fn lseek64(fd: i32, off: i64, whence: i32) -> i64 { unsafe { lseek(fd, off, whence) } }
// # C: off_t llseek(int, off_t, int)
// SAFETY: GNU llseek alias of lseek on LP64; same scalar args/return.
#[no_mangle] pub unsafe extern "C" fn llseek(fd: i32, off: i64, whence: i32) -> i64 { unsafe { lseek(fd, off, whence) } }
// # C: ssize_t pread64(int, void *, size_t, off64_t)
// SAFETY: LFS alias of pread; buf valid for n bytes per the caller. Forwards.
#[no_mangle] pub unsafe extern "C" fn pread64(fd: i32, buf: *mut u8, n: usize, off: i64) -> isize { unsafe { pread(fd, buf, n, off) } }
// # C: ssize_t pwrite64(int, const void *, size_t, off64_t)
// SAFETY: LFS alias of pwrite; buf valid for n bytes per the caller. Forwards.
#[no_mangle] pub unsafe extern "C" fn pwrite64(fd: i32, buf: *const u8, n: usize, off: i64) -> isize { unsafe { pwrite(fd, buf, n, off) } }

// # C: pid_t getpid(void) — always succeeds, never sets errno.
#[no_mangle]
pub unsafe extern "C" fn getpid() -> i32 {
    // SAFETY: getpid(2) takes no args and cannot fail.
    (unsafe { sys0(nr::GETPID) }) as i32
}
