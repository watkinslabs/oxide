// Special-file + size ops (docs/59§6 G8): mknod/mknodat, mkfifo/mkfifoat,
// truncate64/ftruncate64 (LFS aliases), fallocate, posix_fallocate(64).
// Thin: parse args, syscall, errno=-ret & return -1 on negative. Plain
// mknod/mkfifo compose from the *at form via AT_FDCWD so the asm-generic
// arch (no plain mknod) shares one path.
#![cfg(feature = "freestanding")]
use crate::arch::syscall::{sys4};
use crate::internal::errno::ret_isize;
use crate::internal::nr;
use crate::posix::io::AT_FDCWD;

// st_mode type bits (asm-generic / x86_64 — identical).
pub const S_IFMT: u32 = 0o170000;
pub const S_IFSOCK: u32 = 0o140000;
pub const S_IFLNK: u32 = 0o120000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFBLK: u32 = 0o060000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFCHR: u32 = 0o020000;
pub const S_IFIFO: u32 = 0o010000;
// fallocate(2) mode flags.
pub const FALLOC_FL_KEEP_SIZE: i32 = 0x01;
pub const FALLOC_FL_PUNCH_HOLE: i32 = 0x02;

// # C: int mknodat(int dirfd, const char *path, mode_t mode, dev_t dev)
#[no_mangle]
pub unsafe extern "C" fn mknodat(dirfd: i32, path: *const u8, mode: u32, dev: u64) -> i32 {
    // SAFETY: path NUL-terminated; mknodat(2) reads it from caller memory.
    ret_isize(unsafe { sys4(nr::MKNODAT, dirfd as usize, path as usize, mode as usize, dev as usize) }) as i32
}
// # C: int mknod(const char *path, mode_t mode, dev_t dev)
#[no_mangle]
pub unsafe extern "C" fn mknod(path: *const u8, mode: u32, dev: u64) -> i32 {
    // SAFETY: composes mknodat(AT_FDCWD, ...); same NUL-terminated path contract.
    unsafe { mknodat(AT_FDCWD, path, mode, dev) }
}
// # C: int mkfifoat(int dirfd, const char *path, mode_t mode)
#[no_mangle]
pub unsafe extern "C" fn mkfifoat(dirfd: i32, path: *const u8, mode: u32) -> i32 {
    // SAFETY: a FIFO is mknodat with S_IFIFO and dev 0; path is NUL-terminated.
    unsafe { mknodat(dirfd, path, (mode & 0o7777) | S_IFIFO, 0) }
}
// # C: int mkfifo(const char *path, mode_t mode)
#[no_mangle]
pub unsafe extern "C" fn mkfifo(path: *const u8, mode: u32) -> i32 {
    // SAFETY: composes mkfifoat(AT_FDCWD, ...); same path contract.
    unsafe { mkfifoat(AT_FDCWD, path, mode) }
}

// # C: int truncate64(const char *path, off64_t len) — LFS alias of truncate.
#[no_mangle]
pub unsafe extern "C" fn truncate64(path: *const u8, len: i64) -> i32 {
    // SAFETY: off64_t == off_t on LP64; forwards to the base truncate.
    unsafe { crate::posix::fs::truncate(path, len) }
}
// # C: int ftruncate64(int fd, off64_t len) — LFS alias of ftruncate.
#[no_mangle]
pub unsafe extern "C" fn ftruncate64(fd: i32, len: i64) -> i32 {
    // SAFETY: off64_t == off_t on LP64; forwards to the base ftruncate.
    unsafe { crate::posix::fs::ftruncate(fd, len) }
}

// # C: int fallocate(int fd, int mode, off_t offset, off_t len)
#[no_mangle]
pub unsafe extern "C" fn fallocate(fd: i32, mode: i32, offset: i64, len: i64) -> i32 {
    // SAFETY: fallocate(2) takes scalar fd/mode/offset/len; no memory deref.
    ret_isize(unsafe { sys4(nr::FALLOCATE, fd as usize, mode as usize, offset as usize, len as usize) }) as i32
}
// # C: int posix_fallocate(int fd, off_t offset, off_t len) — returns errno.
#[no_mangle]
pub unsafe extern "C" fn posix_fallocate(fd: i32, offset: i64, len: i64) -> i32 {
    // SAFETY: posix_fallocate is fallocate(mode=0) but returns the errno value
    // directly (0 on success) rather than via the errno cell.
    let r = unsafe { sys4(nr::FALLOCATE, fd as usize, 0, offset as usize, len as usize) };
    if r < 0 { -r as i32 } else { 0 }
}
// # C: int posix_fallocate64(int fd, off64_t offset, off64_t len) — LFS alias.
#[no_mangle]
pub unsafe extern "C" fn posix_fallocate64(fd: i32, offset: i64, len: i64) -> i32 {
    // SAFETY: off64_t == off_t on LP64; forwards to posix_fallocate.
    unsafe { posix_fallocate(fd, offset, len) }
}
