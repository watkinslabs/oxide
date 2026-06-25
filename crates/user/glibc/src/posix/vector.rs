// Scatter/gather I/O + fcntl/ioctl (docs/59§6 G8). Thin syscall wrappers:
// parse args, syscall, errno=-ret & return -1 on negative. fcntl/ioctl take
// a varargs 3rd arg whose type (int vs ptr) depends on the request; the
// C-ABI signature here takes a usize and the caller (or a header inline)
// passes either an int-widened-to-usize or a pointer cast to usize. Both
// arches share the *v/fcntl/ioctl slots (asm-generic + x86_64 align).
#![cfg(feature = "freestanding")]
use crate::arch::syscall::{sys3};
use crate::internal::errno::ret_isize;
use crate::internal::nr;

// fcntl(2) commands (asm-generic / x86_64 — identical values both arches).
pub const F_DUPFD: i32 = 0;
pub const F_GETFD: i32 = 1;
pub const F_SETFD: i32 = 2;
pub const F_GETFL: i32 = 3;
pub const F_SETFL: i32 = 4;
pub const F_GETLK: i32 = 5;
pub const F_SETLK: i32 = 6;
pub const F_SETLKW: i32 = 7;
pub const F_SETOWN: i32 = 8;
pub const F_GETOWN: i32 = 9;
pub const F_SETSIG: i32 = 10;
pub const F_GETSIG: i32 = 11;
pub const F_SETOWN_EX: i32 = 15;
pub const F_GETOWN_EX: i32 = 16;
pub const F_DUPFD_CLOEXEC: i32 = 1030;
// FD_CLOEXEC flag for F_SETFD/F_GETFD.
pub const FD_CLOEXEC: i32 = 1;

// # C: struct iovec { void *iov_base; size_t iov_len; }
#[repr(C)]
pub struct iovec { pub iov_base: *mut u8, pub iov_len: usize }

// # C: ssize_t readv(int fd, const struct iovec *iov, int iovcnt)
#[no_mangle]
pub unsafe extern "C" fn readv(fd: i32, iov: *const iovec, iovcnt: i32) -> isize {
    // SAFETY: readv(2); the kernel validates each iov_base/iov_len against the
    // caller's address space and faults on a bad pointer rather than corrupting libc.
    ret_isize(unsafe { sys3(nr::READV, fd as usize, iov as usize, iovcnt as usize) })
}
// # C: ssize_t writev(int fd, const struct iovec *iov, int iovcnt)
#[no_mangle]
pub unsafe extern "C" fn writev(fd: i32, iov: *const iovec, iovcnt: i32) -> isize {
    // SAFETY: writev(2); the kernel validates each iov_base/iov_len against the
    // caller's address space and faults on a bad pointer rather than corrupting libc.
    ret_isize(unsafe { sys3(nr::WRITEV, fd as usize, iov as usize, iovcnt as usize) })
}
// # C: ssize_t preadv(int fd, const struct iovec *iov, int iovcnt, off_t off)
#[no_mangle]
pub unsafe extern "C" fn preadv(fd: i32, iov: *const iovec, iovcnt: i32, off: i64) -> isize {
    // SAFETY: preadv(2); off split into lo/hi halves is unneeded on LP64 — the
    // kernel takes the full offset in one register; pointers validated by the kernel.
    ret_isize(unsafe { crate::arch::syscall::sys5(nr::PREADV, fd as usize, iov as usize, iovcnt as usize, (off as usize) & 0xffff_ffff, (off as u64 >> 32) as usize) })
}
// # C: ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt, off_t off)
#[no_mangle]
pub unsafe extern "C" fn pwritev(fd: i32, iov: *const iovec, iovcnt: i32, off: i64) -> isize {
    // SAFETY: pwritev(2); offset passed lo/hi like the kernel ABI; the kernel
    // validates each iov entry against the caller address space.
    ret_isize(unsafe { crate::arch::syscall::sys5(nr::PWRITEV, fd as usize, iov as usize, iovcnt as usize, (off as usize) & 0xffff_ffff, (off as u64 >> 32) as usize) })
}
// LFS aliases — off64_t == off_t on LP64.
// SAFETY: preadv64 == preadv on LP64; same fd + iovec + offset contract.
#[no_mangle] pub unsafe extern "C" fn preadv64(fd: i32, iov: *const iovec, c: i32, off: i64) -> isize { unsafe { preadv(fd, iov, c, off) } }
// SAFETY: pwritev64 == pwritev on LP64; same fd + iovec + offset contract.
#[no_mangle] pub unsafe extern "C" fn pwritev64(fd: i32, iov: *const iovec, c: i32, off: i64) -> isize { unsafe { pwritev(fd, iov, c, off) } }

// # C: int fcntl(int fd, int cmd, ... /* arg */)
// The varargs 3rd arg is an int for most cmds and a struct flock*/f_owner_ex*
// pointer for the lock/owner cmds; we forward it as an opaque usize either way.
#[no_mangle]
pub unsafe extern "C" fn fcntl(fd: i32, cmd: i32, arg: usize) -> i32 {
    // SAFETY: fcntl(2); for pointer-taking cmds (F_GETLK/F_SETLK/F_SETLKW/
    // F_GETOWN_EX/F_SETOWN_EX) `arg` is a caller-owned struct the kernel reads/
    // writes; for the int cmds it is a scalar. The kernel validates either.
    ret_isize(unsafe { sys3(nr::FCNTL, fd as usize, cmd as usize, arg) }) as i32
}
// # C: int __fcntl(int fd, int cmd, ... /* arg */)
#[no_mangle]
pub unsafe extern "C" fn __fcntl(fd: i32, cmd: i32, arg: usize) -> i32 {
    // SAFETY: __fcntl has the same ABI and arg contract as fcntl.
    unsafe { fcntl(fd, cmd, arg) }
}
// # C: int fcntl64(int fd, int cmd, ...) — LFS alias; identical on LP64.
#[no_mangle]
pub unsafe extern "C" fn fcntl64(fd: i32, cmd: i32, arg: usize) -> i32 {
    // SAFETY: LFS alias of fcntl; struct flock == flock64 on LP64. Forwards.
    unsafe { fcntl(fd, cmd, arg) }
}

// # C: int ioctl(int fd, unsigned long request, ... /* arg */)
// The varargs arg is request-specific (an int, or a pointer to a struct/value);
// forwarded as an opaque usize.
#[no_mangle]
pub unsafe extern "C" fn ioctl(fd: i32, request: usize, arg: usize) -> i32 {
    // SAFETY: ioctl(2); `arg` is a driver-defined scalar or caller-owned buffer
    // that the kernel validates per the request's direction bits, faulting on
    // a bad pointer rather than corrupting libc.
    ret_isize(unsafe { sys3(nr::IOCTL, fd as usize, request, arg) }) as i32
}
