// Resource limits + usage (docs/59§6 G8): <sys/resource.h> syscall
// wrappers. struct rlimit / rusage layouts match host <bits/resource.h>
// exactly (rlim_t = unsigned long; rusage = 2 timevals + 14 longs = 144 B).
#![cfg(feature = "freestanding")]
use crate::arch::syscall::{sys2, sys3, sys4};
use crate::internal::errno;
use crate::internal::errno::{ret, ret_isize};
use crate::internal::nr;

// rlim_t = unsigned long. RLIM_INFINITY = ~0UL.
pub const RLIM_INFINITY: u64 = u64::MAX;
pub const RLIM_SAVED_MAX: u64 = u64::MAX;
pub const RLIM_SAVED_CUR: u64 = u64::MAX;

// struct rlimit { rlim_t rlim_cur, rlim_max; } — 16 bytes.
#[repr(C)]
pub struct Rlimit {
    pub rlim_cur: u64,
    pub rlim_max: u64,
}

// getpriority quirk: kernel returns (20 - nice) so the result is never
// in the -errno band on success; libc maps it back to the real nice value.
const PRIO_BIAS: isize = 20;

// # C: int getrlimit(int resource, struct rlimit *rlim)
#[no_mangle]
pub unsafe extern "C" fn getrlimit(resource: i32, rlim: *mut Rlimit) -> i32 {
    // SAFETY: getrlimit via prlimit64(0, res, NULL, rlim); rlim is a valid out.
    ret_isize(unsafe { sys4(nr::PRLIMIT64, 0, resource as usize, 0, rlim as usize) }) as i32
}
// # C: int setrlimit(int resource, const struct rlimit *rlim)
#[no_mangle]
pub unsafe extern "C" fn setrlimit(resource: i32, rlim: *const Rlimit) -> i32 {
    // SAFETY: setrlimit via prlimit64(0, res, rlim, NULL); rlim points to a rlimit.
    ret_isize(unsafe { sys4(nr::PRLIMIT64, 0, resource as usize, rlim as usize, 0) }) as i32
}
// # C: int prlimit(pid_t pid, int resource, const struct rlimit *new, struct rlimit *old)
#[no_mangle]
pub unsafe extern "C" fn prlimit(pid: i32, resource: i32, new_limit: *const Rlimit, old_limit: *mut Rlimit) -> i32 {
    // SAFETY: prlimit64(2); new_limit/old_limit are NULL or valid rlimit pointers.
    ret_isize(unsafe { sys4(nr::PRLIMIT64, pid as usize, resource as usize, new_limit as usize, old_limit as usize) }) as i32
}
// alias for the 64-bit-explicit name some callers use.
// # C: int prlimit64(pid_t pid, int resource, const struct rlimit *new, struct rlimit *old)
#[no_mangle]
pub unsafe extern "C" fn prlimit64(pid: i32, resource: i32, new_limit: *const Rlimit, old_limit: *mut Rlimit) -> i32 {
    // SAFETY: identical ABI to prlimit; forwards the four scalar/pointer args.
    unsafe { prlimit(pid, resource, new_limit, old_limit) }
}
// # C: int getrusage(int who, struct rusage *usage)
#[no_mangle]
pub unsafe extern "C" fn getrusage(who: i32, usage: *mut core::ffi::c_void) -> i32 {
    // SAFETY: getrusage(2); usage is a valid 144-byte rusage out-pointer.
    ret_isize(unsafe { sys2(nr::GETRUSAGE, who as usize, usage as usize) }) as i32
}
// # C: int getpriority(int which, id_t who)
#[no_mangle]
pub unsafe extern "C" fn getpriority(which: i32, who: u32) -> i32 {
    // SAFETY: getpriority(2) takes scalar which/who; no memory dereferenced.
    let r = unsafe { sys2(nr::GETPRIORITY, which as usize, who as usize) };
    match ret(r) {
        Ok(v) => (PRIO_BIAS - v) as i32, // kernel returns 20 - nice
        Err(e) => { errno::set(e); -1 }
    }
}
// # C: int setpriority(int which, id_t who, int prio)
#[no_mangle]
pub unsafe extern "C" fn setpriority(which: i32, who: u32, prio: i32) -> i32 {
    // SAFETY: setpriority(2) takes scalar which/who/prio; no memory touched.
    ret_isize(unsafe { sys3(nr::SETPRIORITY, which as usize, who as usize, prio as usize) }) as i32
}
// # C: int nice(int inc)
#[no_mangle]
pub unsafe extern "C" fn nice(inc: i32) -> i32 {
    // SAFETY: nice via getpriority(PRIO_PROCESS=0, 0) + setpriority; reads then
    // writes the caller's own nice value, no memory dereferenced.
    unsafe {
        errno::set(0);
        let cur = getpriority(0, 0);
        if cur == -1 && *crate::internal::errno::__errno_location() != 0 { return -1; }
        let newp = cur + inc;
        if setpriority(0, 0, newp) < 0 { return -1; }
        newp
    }
}
