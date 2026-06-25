// Process/credential ids (docs/59§6 G8). Thin syscall wrappers; the
// get*id calls cannot fail. Smoke-verified via the boot path.
#![cfg(feature = "freestanding")]
use crate::arch::syscall::{sys0, sys1, sys2};
use crate::internal::errno::ret_isize;
use crate::internal::nr;

// # C: uid_t getuid(void)
#[no_mangle]
pub unsafe extern "C" fn getuid() -> u32 {
    // SAFETY: getuid(2) takes no args and cannot fail.
    (unsafe { sys0(nr::GETUID) }) as u32
}
// # C: uid_t geteuid(void)
#[no_mangle]
pub unsafe extern "C" fn geteuid() -> u32 {
    // SAFETY: geteuid(2) takes no args and cannot fail.
    (unsafe { sys0(nr::GETEUID) }) as u32
}
// # C: gid_t getgid(void)
#[no_mangle]
pub unsafe extern "C" fn getgid() -> u32 {
    // SAFETY: getgid(2) takes no args and cannot fail.
    (unsafe { sys0(nr::GETGID) }) as u32
}
// # C: gid_t getegid(void)
#[no_mangle]
pub unsafe extern "C" fn getegid() -> u32 {
    // SAFETY: getegid(2) takes no args and cannot fail.
    (unsafe { sys0(nr::GETEGID) }) as u32
}
// # C: pid_t getppid(void)
#[no_mangle]
pub unsafe extern "C" fn getppid() -> i32 {
    // SAFETY: getppid(2) takes no args and cannot fail.
    (unsafe { sys0(nr::GETPPID) }) as i32
}
// # C: pid_t gettid(void)
#[no_mangle]
pub unsafe extern "C" fn gettid() -> i32 {
    // SAFETY: gettid(2) takes no args and cannot fail.
    (unsafe { sys0(nr::GETTID) }) as i32
}
// # C: int setuid(uid_t)
#[no_mangle]
pub unsafe extern "C" fn setuid(uid: u32) -> i32 {
    // SAFETY: setuid(2) takes a scalar id; no memory is dereferenced.
    ret_isize(unsafe { sys1(nr::SETUID, uid as usize) }) as i32
}
// # C: int setgid(gid_t)
#[no_mangle]
pub unsafe extern "C" fn setgid(gid: u32) -> i32 {
    // SAFETY: setgid(2) takes a scalar id; no memory is dereferenced.
    ret_isize(unsafe { sys1(nr::SETGID, gid as usize) }) as i32
}
// # C: int setpgid(pid_t, pid_t)
#[no_mangle]
pub unsafe extern "C" fn setpgid(pid: i32, pgid: i32) -> i32 {
    // SAFETY: setpgid(2) takes scalar ids; no memory is dereferenced.
    ret_isize(unsafe { sys2(nr::SETPGID, pid as usize, pgid as usize) }) as i32
}
// # C: int __setpgid(pid_t, pid_t)
#[no_mangle]
pub unsafe extern "C" fn __setpgid(pid: i32, pgid: i32) -> i32 {
    // SAFETY: internal alias has the same scalar pid/pgid contract as setpgid.
    unsafe { setpgid(pid, pgid) }
}
// # C: pid_t getpgid(pid_t)
#[no_mangle]
pub unsafe extern "C" fn getpgid(pid: i32) -> i32 {
    // SAFETY: getpgid(2) takes a scalar pid; no memory is dereferenced.
    ret_isize(unsafe { sys1(nr::GETPGID, pid as usize) }) as i32
}
// # C: pid_t __getpgid(pid_t)
#[no_mangle]
pub unsafe extern "C" fn __getpgid(pid: i32) -> i32 {
    // SAFETY: __getpgid has the same scalar pid contract as getpgid.
    unsafe { getpgid(pid) }
}
// # C: pid_t getpgrp(void) — POSIX getpgid(0)
#[no_mangle]
pub unsafe extern "C" fn getpgrp() -> i32 {
    // SAFETY: getpgid(0) returns the caller's pgrp; cannot fault.
    ret_isize(unsafe { sys1(nr::GETPGID, 0) }) as i32
}
// # C: pid_t setsid(void)
#[no_mangle]
pub unsafe extern "C" fn setsid() -> i32 {
    // SAFETY: setsid(2) takes no args; returns the new session id / -1.
    ret_isize(unsafe { sys0(nr::SETSID) }) as i32
}
// # C: pid_t getsid(pid_t)
#[no_mangle]
pub unsafe extern "C" fn getsid(pid: i32) -> i32 {
    // SAFETY: getsid(2) takes a scalar pid; no memory is dereferenced.
    ret_isize(unsafe { sys1(nr::GETSID, pid as usize) }) as i32
}
// # C: int setgroups(size_t size, const gid_t *list)
#[no_mangle]
pub unsafe extern "C" fn setgroups(size: usize, list: *const u32) -> i32 {
    // SAFETY: list points to `size` gid_t values (or null when size==0);
    // setgroups(2) reads them. nss/shadow.rs already uses SETGROUPS via initgroups.
    ret_isize(unsafe { sys2(nr::SETGROUPS, size, list as usize) }) as i32
}
