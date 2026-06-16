// Filesystem ops (docs/59§6 G8). Implemented in terms of the *at
// syscalls (present on both arches); the legacy plain forms compose via
// AT_FDCWD so x86_64 and aarch64 (asm-generic, *at-only) share one path.
// Smoke-verified (mkdir/rmdir/getcwd round-trip). faccessat/fchmodat
// flags use the 3-arg kernel call (flags!=0 → faccessat2/fchmodat2 is a
// follow-up).
#![cfg(feature = "freestanding")]
use crate::arch::syscall::{sys1, sys2, sys3, sys4, sys5};
use crate::internal::errno::ret_isize;
use crate::internal::nr;
use crate::posix::io::AT_FDCWD;

const AT_REMOVEDIR: usize = 0x200;
const AT_SYMLINK_NOFOLLOW: usize = 0x100;

// # C: char *getcwd(char *buf, size_t size)
#[no_mangle]
pub unsafe extern "C" fn getcwd(buf: *mut u8, size: usize) -> *mut u8 {
    // SAFETY: buf is valid for `size` bytes; getcwd(2) writes the path + NUL.
    let r = unsafe { sys2(nr::GETCWD, buf as usize, size) };
    if r < 0 { crate::internal::errno::set(-r as i32); core::ptr::null_mut() } else { buf }
}
// # C: int chdir(const char *path)
#[no_mangle]
pub unsafe extern "C" fn chdir(path: *const u8) -> i32 {
    // SAFETY: path is a NUL-terminated string read by the kernel.
    ret_isize(unsafe { sys1(nr::CHDIR, path as usize) }) as i32
}
// # C: int fchdir(int fd)
#[no_mangle]
pub unsafe extern "C" fn fchdir(fd: i32) -> i32 {
    // SAFETY: fchdir(2) takes a scalar fd; no memory is dereferenced.
    ret_isize(unsafe { sys1(nr::FCHDIR, fd as usize) }) as i32
}
// # C: int faccessat(int dirfd, const char *path, int mode, int flags)
#[no_mangle]
pub unsafe extern "C" fn faccessat(dirfd: i32, path: *const u8, mode: i32, _flags: i32) -> i32 {
    // SAFETY: path NUL-terminated; kernel faccessat is 3-arg (flags via
    // faccessat2, a follow-up).
    ret_isize(unsafe { sys3(nr::FACCESSAT, dirfd as usize, path as usize, mode as usize) }) as i32
}
// # C: int access(const char *path, int mode)
#[no_mangle]
pub unsafe extern "C" fn access(path: *const u8, mode: i32) -> i32 {
    // SAFETY: composes faccessat(AT_FDCWD, ...).
    unsafe { faccessat(AT_FDCWD, path, mode, 0) }
}
// # C: int unlinkat(int dirfd, const char *path, int flags)
#[no_mangle]
pub unsafe extern "C" fn unlinkat(dirfd: i32, path: *const u8, flags: i32) -> i32 {
    // SAFETY: path NUL-terminated; unlinkat(2).
    ret_isize(unsafe { sys3(nr::UNLINKAT, dirfd as usize, path as usize, flags as usize) }) as i32
}
// # C: int unlink(const char *path)
#[no_mangle]
pub unsafe extern "C" fn unlink(path: *const u8) -> i32 {
    // SAFETY: composes unlinkat(AT_FDCWD, path, 0).
    unsafe { unlinkat(AT_FDCWD, path, 0) }
}
// # C: int rmdir(const char *path)
#[no_mangle]
pub unsafe extern "C" fn rmdir(path: *const u8) -> i32 {
    // SAFETY: composes unlinkat(AT_FDCWD, path, AT_REMOVEDIR).
    ret_isize(unsafe { sys3(nr::UNLINKAT, AT_FDCWD as usize, path as usize, AT_REMOVEDIR) }) as i32
}
// # C: int mkdirat(int dirfd, const char *path, mode_t mode)
#[no_mangle]
pub unsafe extern "C" fn mkdirat(dirfd: i32, path: *const u8, mode: u32) -> i32 {
    // SAFETY: path NUL-terminated; mkdirat(2).
    ret_isize(unsafe { sys3(nr::MKDIRAT, dirfd as usize, path as usize, mode as usize) }) as i32
}
// # C: int mkdir(const char *path, mode_t mode)
#[no_mangle]
pub unsafe extern "C" fn mkdir(path: *const u8, mode: u32) -> i32 {
    // SAFETY: composes mkdirat(AT_FDCWD, path, mode).
    unsafe { mkdirat(AT_FDCWD, path, mode) }
}
// # C: int renameat(int od, const char *op, int nd, const char *np)
#[no_mangle]
pub unsafe extern "C" fn renameat(od: i32, op: *const u8, nd: i32, np: *const u8) -> i32 {
    // SAFETY: op/np NUL-terminated; renameat(2).
    ret_isize(unsafe { sys4(nr::RENAMEAT, od as usize, op as usize, nd as usize, np as usize) }) as i32
}
// # C: int rename(const char *old, const char *new)
#[no_mangle]
pub unsafe extern "C" fn rename(old: *const u8, new: *const u8) -> i32 {
    // SAFETY: composes renameat(AT_FDCWD, old, AT_FDCWD, new).
    unsafe { renameat(AT_FDCWD, old, AT_FDCWD, new) }
}
// # C: int symlinkat(const char *target, int nd, const char *linkpath)
#[no_mangle]
pub unsafe extern "C" fn symlinkat(target: *const u8, nd: i32, linkpath: *const u8) -> i32 {
    // SAFETY: target/linkpath NUL-terminated; symlinkat(2).
    ret_isize(unsafe { sys3(nr::SYMLINKAT, target as usize, nd as usize, linkpath as usize) }) as i32
}
// # C: int symlink(const char *target, const char *linkpath)
#[no_mangle]
pub unsafe extern "C" fn symlink(target: *const u8, linkpath: *const u8) -> i32 {
    // SAFETY: composes symlinkat(target, AT_FDCWD, linkpath).
    unsafe { symlinkat(target, AT_FDCWD, linkpath) }
}
// # C: int linkat(int od, const char *op, int nd, const char *np, int flags)
#[no_mangle]
pub unsafe extern "C" fn linkat(od: i32, op: *const u8, nd: i32, np: *const u8, flags: i32) -> i32 {
    // SAFETY: op/np NUL-terminated; linkat(2).
    ret_isize(unsafe { sys5(nr::LINKAT, od as usize, op as usize, nd as usize, np as usize, flags as usize) }) as i32
}
// # C: int link(const char *old, const char *new)
#[no_mangle]
pub unsafe extern "C" fn link(old: *const u8, new: *const u8) -> i32 {
    // SAFETY: composes linkat(AT_FDCWD, old, AT_FDCWD, new, 0).
    unsafe { linkat(AT_FDCWD, old, AT_FDCWD, new, 0) }
}
// # C: ssize_t readlinkat(int dirfd, const char *path, char *buf, size_t sz)
#[no_mangle]
pub unsafe extern "C" fn readlinkat(dirfd: i32, path: *const u8, buf: *mut u8, sz: usize) -> isize {
    // SAFETY: path NUL-terminated; buf valid for `sz` bytes; readlinkat(2).
    ret_isize(unsafe { sys4(nr::READLINKAT, dirfd as usize, path as usize, buf as usize, sz) })
}
// # C: ssize_t readlink(const char *path, char *buf, size_t sz)
#[no_mangle]
pub unsafe extern "C" fn readlink(path: *const u8, buf: *mut u8, sz: usize) -> isize {
    // SAFETY: composes readlinkat(AT_FDCWD, ...).
    unsafe { readlinkat(AT_FDCWD, path, buf, sz) }
}
// # C: int fchmodat(int dirfd, const char *path, mode_t mode, int flags)
#[no_mangle]
pub unsafe extern "C" fn fchmodat(dirfd: i32, path: *const u8, mode: u32, _flags: i32) -> i32 {
    // SAFETY: path NUL-terminated; kernel fchmodat is 3-arg (flags via
    // fchmodat2, a follow-up).
    ret_isize(unsafe { sys3(nr::FCHMODAT, dirfd as usize, path as usize, mode as usize) }) as i32
}
// # C: int chmod(const char *path, mode_t mode)
#[no_mangle]
pub unsafe extern "C" fn chmod(path: *const u8, mode: u32) -> i32 {
    // SAFETY: composes fchmodat(AT_FDCWD, path, mode).
    unsafe { fchmodat(AT_FDCWD, path, mode, 0) }
}
// # C: int fchmod(int fd, mode_t mode)
#[no_mangle]
pub unsafe extern "C" fn fchmod(fd: i32, mode: u32) -> i32 {
    // SAFETY: fchmod(2) takes scalar fd/mode.
    ret_isize(unsafe { sys2(nr::FCHMOD, fd as usize, mode as usize) }) as i32
}
// # C: int lchmod(const char *path, mode_t mode) — chmod without following a
// final symlink. Uses fchmodat2(AT_SYMLINK_NOFOLLOW); a symlink target ⇒ EOPNOTSUPP.
#[no_mangle]
pub unsafe extern "C" fn lchmod(path: *const u8, mode: u32) -> i32 {
    const AT_SYMLINK_NOFOLLOW: usize = 0x100;
    // SAFETY: path NUL-terminated; fchmodat2(2) is the 4-arg flagged chmod.
    ret_isize(unsafe { sys4(nr::FCHMODAT2, AT_FDCWD as usize, path as usize, mode as usize, AT_SYMLINK_NOFOLLOW) }) as i32
}
// # C: int fchownat(int dirfd, const char *path, uid_t, gid_t, int flags)
#[no_mangle]
pub unsafe extern "C" fn fchownat(dirfd: i32, path: *const u8, owner: u32, group: u32, flags: i32) -> i32 {
    // SAFETY: path NUL-terminated; fchownat(2).
    ret_isize(unsafe { sys5(nr::FCHOWNAT, dirfd as usize, path as usize, owner as usize, group as usize, flags as usize) }) as i32
}
// # C: int chown(const char *path, uid_t, gid_t)
#[no_mangle]
pub unsafe extern "C" fn chown(path: *const u8, owner: u32, group: u32) -> i32 {
    // SAFETY: composes fchownat(AT_FDCWD, path, owner, group, 0).
    unsafe { fchownat(AT_FDCWD, path, owner, group, 0) }
}
// # C: int lchown(const char *path, uid_t, gid_t)
#[no_mangle]
pub unsafe extern "C" fn lchown(path: *const u8, owner: u32, group: u32) -> i32 {
    // SAFETY: composes fchownat(..., AT_SYMLINK_NOFOLLOW).
    ret_isize(unsafe { sys5(nr::FCHOWNAT, AT_FDCWD as usize, path as usize, owner as usize, group as usize, AT_SYMLINK_NOFOLLOW) }) as i32
}
// # C: int fchown(int fd, uid_t, gid_t)
#[no_mangle]
pub unsafe extern "C" fn fchown(fd: i32, owner: u32, group: u32) -> i32 {
    // SAFETY: fchown(2) takes scalar fd/ids.
    ret_isize(unsafe { sys3(nr::FCHOWN, fd as usize, owner as usize, group as usize) }) as i32
}
// # C: mode_t umask(mode_t mask)
#[no_mangle]
pub unsafe extern "C" fn umask(mask: u32) -> u32 {
    // SAFETY: umask(2) takes a scalar and returns the previous mask.
    (unsafe { sys1(nr::UMASK, mask as usize) }) as u32
}
// # C: int truncate(const char *path, off_t len)
#[no_mangle]
pub unsafe extern "C" fn truncate(path: *const u8, len: i64) -> i32 {
    // SAFETY: path NUL-terminated; truncate(2).
    ret_isize(unsafe { sys2(nr::TRUNCATE, path as usize, len as usize) }) as i32
}
// # C: int ftruncate(int fd, off_t len)
#[no_mangle]
pub unsafe extern "C" fn ftruncate(fd: i32, len: i64) -> i32 {
    // SAFETY: ftruncate(2) takes scalar fd/len.
    ret_isize(unsafe { sys2(nr::FTRUNCATE, fd as usize, len as usize) }) as i32
}
// # C: int fsync(int fd)
#[no_mangle]
pub unsafe extern "C" fn fsync(fd: i32) -> i32 {
    // SAFETY: fsync(2) takes a scalar fd; no memory is dereferenced.
    ret_isize(unsafe { sys1(nr::FSYNC, fd as usize) }) as i32
}
// # C: int fdatasync(int fd)
#[no_mangle]
pub unsafe extern "C" fn fdatasync(fd: i32) -> i32 {
    // SAFETY: fdatasync(2) takes a scalar fd.
    ret_isize(unsafe { sys1(nr::FDATASYNC, fd as usize) }) as i32
}
