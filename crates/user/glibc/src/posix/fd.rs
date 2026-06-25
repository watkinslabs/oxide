// File-descriptor ops (docs/59§6 G8). pipe→pipe2, dup2→dup3 (both arches
// have pipe2/dup3; the legacy forms compose). Smoke-verified.
#![cfg(feature = "freestanding")]
use crate::arch::syscall::{sys1, sys2, sys3};
use crate::internal::errno::ret_isize;
use crate::internal::nr;

// # C: int pipe(int fds[2])
#[no_mangle]
pub unsafe extern "C" fn pipe(fds: *mut i32) -> i32 {
    // SAFETY: fds is a writable array of two ints per pipe(2).
    ret_isize(unsafe { sys2(nr::PIPE2, fds as usize, 0) }) as i32
}
// # C: int pipe2(int fds[2], int flags)
#[no_mangle]
pub unsafe extern "C" fn pipe2(fds: *mut i32, flags: i32) -> i32 {
    // SAFETY: fds is a writable array of two ints per pipe2(2).
    ret_isize(unsafe { sys2(nr::PIPE2, fds as usize, flags as usize) }) as i32
}
// # C: int dup(int fd)
#[no_mangle]
pub unsafe extern "C" fn dup(fd: i32) -> i32 {
    // SAFETY: dup(2) takes a scalar fd; no memory is dereferenced.
    ret_isize(unsafe { sys1(nr::DUP, fd as usize) }) as i32
}
// # C: int dup2(int oldfd, int newfd)
#[no_mangle]
pub unsafe extern "C" fn dup2(oldfd: i32, newfd: i32) -> i32 {
    // SAFETY: dup3 errors EINVAL when old==new, but dup2 must return newfd
    // then; otherwise compose via dup3(old,new,0). (Validity recheck for
    // the equal case is a follow-up — needs fcntl F_GETFD.)
    if oldfd == newfd { return newfd; }
    // SAFETY: dup3(2) takes scalar fds; old != new here so EINVAL can't fire.
    ret_isize(unsafe { sys3(nr::DUP3, oldfd as usize, newfd as usize, 0) }) as i32
}
// # C: int __dup2(int oldfd, int newfd)
#[no_mangle]
pub unsafe extern "C" fn __dup2(oldfd: i32, newfd: i32) -> i32 {
    // SAFETY: __dup2 has the same scalar fd contract as dup2.
    unsafe { dup2(oldfd, newfd) }
}
// # C: int dup3(int oldfd, int newfd, int flags)
#[no_mangle]
pub unsafe extern "C" fn dup3(oldfd: i32, newfd: i32, flags: i32) -> i32 {
    // SAFETY: dup3(2) takes scalar fds/flags; no memory is dereferenced.
    ret_isize(unsafe { sys3(nr::DUP3, oldfd as usize, newfd as usize, flags as usize) }) as i32
}
