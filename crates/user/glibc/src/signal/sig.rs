// Signal delivery + mask syscall wrappers (docs/59§6 G9). sigaction +
// the restorer trampoline land in G9b. rt_sigprocmask/rt_sigpending take
// the kernel sigset size (8 bytes); our sigset_t's low word is the kernel
// mask. Smoke-verified.
#![cfg(feature = "freestanding")]
use super::sigset::sigset_t;
use crate::arch::syscall::{sys2, sys3, sys4};
use crate::internal::errno::ret_isize;
use crate::internal::nr;

const KERNEL_SIGSET: usize = 8;

// # C: int kill(pid_t pid, int sig)
#[no_mangle]
pub unsafe extern "C" fn kill(pid: i32, sig: i32) -> i32 {
    // SAFETY: kill(2) takes scalar pid/sig; no memory dereferenced.
    ret_isize(unsafe { sys2(nr::KILL, pid as usize, sig as usize) }) as i32
}
// # C: int killpg(int pgrp, int sig)
#[no_mangle]
pub unsafe extern "C" fn killpg(pgrp: i32, sig: i32) -> i32 {
    // SAFETY: killpg(pgrp) == kill(-pgrp); scalar args only.
    unsafe { kill(-pgrp, sig) }
}
// # C: int tgkill(int tgid, int tid, int sig)
#[no_mangle]
pub unsafe extern "C" fn tgkill(tgid: i32, tid: i32, sig: i32) -> i32 {
    // SAFETY: tgkill(2) takes scalar ids/sig.
    ret_isize(unsafe { sys3(nr::TGKILL, tgid as usize, tid as usize, sig as usize) }) as i32
}
// # C: int raise(int sig) — send to the calling thread.
#[no_mangle]
pub unsafe extern "C" fn raise(sig: i32) -> i32 {
    // SAFETY: tgkill(getpid, gettid, sig) targets this thread.
    unsafe {
        let pid = crate::posix::io::getpid();
        let tid = crate::posix::ids::gettid();
        tgkill(pid, tid, sig)
    }
}
// # C: int sigprocmask(int how, const sigset_t *set, sigset_t *oldset)
#[no_mangle]
pub unsafe extern "C" fn sigprocmask(how: i32, set: *const sigset_t, oldset: *mut sigset_t) -> i32 {
    // SAFETY: set/oldset are null or valid sigset_t; the kernel reads/writes
    // the low KERNEL_SIGSET bytes (our sigset_t's low word).
    ret_isize(unsafe { sys4(nr::RT_SIGPROCMASK, how as usize, set as usize, oldset as usize, KERNEL_SIGSET) }) as i32
}
// # C: int sigpending(sigset_t *set)
#[no_mangle]
pub unsafe extern "C" fn sigpending(set: *mut sigset_t) -> i32 {
    // SAFETY: set is a valid sigset_t out-param.
    ret_isize(unsafe { sys2(nr::RT_SIGPENDING, set as usize, KERNEL_SIGSET) }) as i32
}
// # C: int sigsuspend(const sigset_t *mask)
#[no_mangle]
pub unsafe extern "C" fn sigsuspend(mask: *const sigset_t) -> i32 {
    // SAFETY: mask is a valid sigset_t; rt_sigsuspend always returns -1/EINTR.
    ret_isize(unsafe { sys2(nr::RT_SIGSUSPEND, mask as usize, KERNEL_SIGSET) }) as i32
}
// # C: int sigaltstack(const stack_t *ss, stack_t *old)
#[no_mangle]
pub unsafe extern "C" fn sigaltstack(ss: *const core::ffi::c_void, old: *mut core::ffi::c_void) -> i32 {
    // SAFETY: ss/old are null or valid stack_t per sigaltstack(2).
    ret_isize(unsafe { sys2(nr::SIGALTSTACK, ss as usize, old as usize) }) as i32
}

// # C: int pause(void)
#[cfg(target_arch = "x86_64")]
#[no_mangle]
pub unsafe extern "C" fn pause() -> i32 {
    // SAFETY: pause(2) blocks until a signal; always returns -1/EINTR.
    ret_isize(unsafe { crate::arch::syscall::sys0(nr::PAUSE) }) as i32
}
#[cfg(not(target_arch = "x86_64"))]
#[no_mangle]
pub unsafe extern "C" fn pause() -> i32 {
    // SAFETY: aarch64 has no pause(2); ppoll(NULL,0,NULL,NULL,0) blocks
    // until a signal, returning -1/EINTR.
    ret_isize(unsafe { crate::arch::syscall::sys5(nr::PPOLL, 0, 0, 0, 0, 0) }) as i32
}
