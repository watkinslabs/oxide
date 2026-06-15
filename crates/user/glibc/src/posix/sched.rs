// Scheduler control (docs/59§6 G8): <sched.h> syscall wrappers. Thin
// parse/invoke/ret shims — all real work is in the kernel scheduler.
// cpu_set_t is a 1024-bit (128-byte) mask, matching host glibc CPU_SETSIZE.
#![cfg(feature = "freestanding")]
use crate::arch::syscall::{sys0, sys1, sys2, sys3};
use crate::internal::errno;
use crate::internal::errno::{ret, ret_isize};
use crate::internal::nr;

// struct sched_param { int sched_priority; } — 4 bytes, matches host.
#[repr(C)]
pub struct SchedParam {
    pub sched_priority: i32,
}

// # C: int sched_getparam(pid_t pid, struct sched_param *param)
#[no_mangle]
pub unsafe extern "C" fn sched_getparam(pid: i32, param: *mut SchedParam) -> i32 {
    // SAFETY: sched_getparam(2); param is a valid sched_param out-pointer.
    ret_isize(unsafe { sys2(nr::SCHED_GETPARAM, pid as usize, param as usize) }) as i32
}
// # C: int sched_setparam(pid_t pid, const struct sched_param *param)
#[no_mangle]
pub unsafe extern "C" fn sched_setparam(pid: i32, param: *const SchedParam) -> i32 {
    // SAFETY: sched_setparam(2); param points to a valid sched_param.
    ret_isize(unsafe { sys2(nr::SCHED_SETPARAM, pid as usize, param as usize) }) as i32
}
// # C: int sched_getscheduler(pid_t pid)
#[no_mangle]
pub unsafe extern "C" fn sched_getscheduler(pid: i32) -> i32 {
    // SAFETY: sched_getscheduler(2) takes a scalar pid; no memory touched.
    ret_isize(unsafe { sys1(nr::SCHED_GETSCHEDULER, pid as usize) }) as i32
}
// # C: int sched_setscheduler(pid_t pid, int policy, const struct sched_param *param)
#[no_mangle]
pub unsafe extern "C" fn sched_setscheduler(pid: i32, policy: i32, param: *const SchedParam) -> i32 {
    // SAFETY: sched_setscheduler(2); param points to a valid sched_param.
    ret_isize(unsafe { sys3(nr::SCHED_SETSCHEDULER, pid as usize, policy as usize, param as usize) }) as i32
}
// # C: int sched_get_priority_max(int policy)
#[no_mangle]
pub unsafe extern "C" fn sched_get_priority_max(policy: i32) -> i32 {
    // SAFETY: sched_get_priority_max(2) takes a scalar policy; no memory touched.
    ret_isize(unsafe { sys1(nr::SCHED_GET_PRIORITY_MAX, policy as usize) }) as i32
}
// # C: int sched_get_priority_min(int policy)
#[no_mangle]
pub unsafe extern "C" fn sched_get_priority_min(policy: i32) -> i32 {
    // SAFETY: sched_get_priority_min(2) takes a scalar policy; no memory touched.
    ret_isize(unsafe { sys1(nr::SCHED_GET_PRIORITY_MIN, policy as usize) }) as i32
}
// # C: int sched_rr_get_interval(pid_t pid, struct timespec *tp)
#[no_mangle]
pub unsafe extern "C" fn sched_rr_get_interval(pid: i32, tp: *mut core::ffi::c_void) -> i32 {
    // SAFETY: sched_rr_get_interval(2); tp is a valid timespec out-pointer.
    ret_isize(unsafe { sys2(nr::SCHED_RR_GET_INTERVAL, pid as usize, tp as usize) }) as i32
}
// # C: int sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask)
#[no_mangle]
pub unsafe extern "C" fn sched_getaffinity(pid: i32, cpusetsize: usize, mask: *mut core::ffi::c_void) -> i32 {
    // SAFETY: sched_getaffinity(2); mask is a buffer of cpusetsize bytes out.
    // The raw syscall returns the byte count written; glibc zero-fills the
    // tail and reports 0 on success, so collapse any non-negative ret to 0.
    let r = unsafe { sys3(nr::SCHED_GETAFFINITY, pid as usize, cpusetsize, mask as usize) };
    match ret(r) { Ok(_) => 0, Err(e) => { errno::set(e); -1 } }
}
// # C: int sched_setaffinity(pid_t pid, size_t cpusetsize, const cpu_set_t *mask)
#[no_mangle]
pub unsafe extern "C" fn sched_setaffinity(pid: i32, cpusetsize: usize, mask: *const core::ffi::c_void) -> i32 {
    // SAFETY: sched_setaffinity(2); mask points to cpusetsize bytes of mask.
    ret_isize(unsafe { sys3(nr::SCHED_SETAFFINITY, pid as usize, cpusetsize, mask as usize) }) as i32
}
// # C: int sched_yield(void)
#[no_mangle]
pub unsafe extern "C" fn sched_yield() -> i32 {
    // SAFETY: sched_yield(2) takes no args; relinquishes the cpu.
    ret_isize(unsafe { sys0(nr::SCHED_YIELD) }) as i32
}
