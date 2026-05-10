// `sys_prctl` (slot 157) real impl. Split out of
// `syscall_glue_proc.rs` to keep that file under the 1000-line cap.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use core::sync::atomic::Ordering;

const PR_SET_PDEATHSIG:       u64 = 1;
const PR_GET_PDEATHSIG:       u64 = 2;
const PR_GET_DUMPABLE:        u64 = 3;
const PR_SET_DUMPABLE:        u64 = 4;
const PR_SET_KEEPCAPS:        u64 = 8;
const PR_GET_KEEPCAPS:        u64 = 7;
const PR_SET_NAME:            u64 = 15;
const PR_GET_NAME:            u64 = 16;
const PR_SET_SECCOMP:         u64 = 22;
const PR_GET_SECCOMP:         u64 = 21;
const PR_CAPBSET_READ:        u64 = 23;
const PR_CAPBSET_DROP:        u64 = 24;
const PR_GET_TSC:             u64 = 25;
const PR_SET_TSC:             u64 = 26;
const PR_SET_NO_NEW_PRIVS:    u64 = 38;
const PR_GET_NO_NEW_PRIVS:    u64 = 39;
const PR_SET_THP_DISABLE:     u64 = 41;
const PR_GET_THP_DISABLE:     u64 = 42;
const PR_SET_CHILD_SUBREAPER: u64 = 36;
const PR_GET_CHILD_SUBREAPER: u64 = 37;

/// `sys_personality(persona)` — slot 135. Returns previous personality
/// and (when `persona != 0xFFFFFFFF`) sets the new one. Per-task slot
/// added in F78. Stored opaquely; v1 doesn't act on the bits.
/// # C: O(1)
pub fn kernel_sys_personality(args: &SyscallArgs) -> i64 {
    let new = args.a0 as u32;
    let cur = match sched::live::current() { Some(c) => c, None => return 0 };
    let prev = cur.personality.load(Ordering::Acquire);
    if new != u32::MAX { cur.personality.store(new, Ordering::Release); }
    prev as i64
}

/// `sys_prctl(option, arg2, arg3, arg4, arg5)` — slot 157.
///
/// Real per-task storage for PR_SET_NO_NEW_PRIVS, PR_SET_KEEPCAPS,
/// PR_SET_PDEATHSIG, PR_SET_CHILD_SUBREAPER, plus reads via the
/// matching PR_GET_*. PR_CAPBSET_READ / PR_CAPBSET_DROP read from
/// the cap_bounding mask added in F66.
/// # C: O(1)
pub fn kernel_sys_prctl(args: &SyscallArgs) -> i64 {
    let cur = match sched::live::current() { Some(c) => c, None => return 0 };
    match args.a0 {
        PR_SET_NAME | PR_SET_DUMPABLE | PR_SET_TSC | PR_SET_THP_DISABLE => 0,
        PR_GET_DUMPABLE => 1,
        PR_GET_TSC      => 1,
        PR_GET_THP_DISABLE => 0,
        PR_GET_NAME => {
            let p = args.a1;
            if p != 0 && p < hal::USER_VA_END {
                let name = cur.name;
                let n = name.len().min(15);
                // SAFETY: p validated < USER_VA_END; n bytes from a 'static str fit in the user 16-byte name buf.
                unsafe {
                    for i in 0..n {
                        core::ptr::write_volatile((p + i as u64) as *mut u8, name.as_bytes()[i]);
                    }
                    core::ptr::write_volatile((p + n as u64) as *mut u8, 0);
                }
            }
            0
        }
        PR_SET_NO_NEW_PRIVS => {
            if args.a1 != 1 { return -(Errno::Einval.as_i32() as i64); }
            cur.no_new_privs.store(true, Ordering::Release);
            0
        }
        PR_GET_NO_NEW_PRIVS => cur.no_new_privs.load(Ordering::Acquire) as i64,
        PR_SET_KEEPCAPS => {
            if args.a1 > 1 { return -(Errno::Einval.as_i32() as i64); }
            cur.keep_caps.store(args.a1 != 0, Ordering::Release);
            0
        }
        PR_GET_KEEPCAPS => cur.keep_caps.load(Ordering::Acquire) as i64,
        PR_SET_PDEATHSIG => {
            let sig = args.a1 as u32;
            if sig > 64 { return -(Errno::Einval.as_i32() as i64); }
            cur.pdeathsig.store(sig, Ordering::Release);
            0
        }
        PR_GET_PDEATHSIG => {
            let p = args.a1;
            let v = cur.pdeathsig.load(Ordering::Acquire);
            if p != 0 && p < hal::USER_VA_END {
                // SAFETY: p validated < USER_VA_END; CPL=0 i32 write through caller's AS at the prctl-ABI specified pointer.
                unsafe { core::ptr::write_volatile(p as *mut i32, v as i32); }
            }
            0
        }
        PR_SET_CHILD_SUBREAPER => {
            cur.child_subreaper.store(args.a1 != 0, Ordering::Release);
            0
        }
        PR_GET_CHILD_SUBREAPER => {
            let p = args.a1;
            let v = cur.child_subreaper.load(Ordering::Acquire);
            if p != 0 && p < hal::USER_VA_END {
                // SAFETY: p validated < USER_VA_END; CPL=0 i32 write through caller's AS at the prctl-ABI specified pointer.
                unsafe { core::ptr::write_volatile(p as *mut i32, v as i32); }
            }
            0
        }
        PR_CAPBSET_READ => {
            let cap = args.a1;
            if cap >= 64 { return -(Errno::Einval.as_i32() as i64); }
            ((cur.creds.cap_bounding.load(Ordering::Acquire) >> cap) & 1) as i64
        }
        PR_CAPBSET_DROP => {
            let cap = args.a1;
            if cap >= 64 { return -(Errno::Einval.as_i32() as i64); }
            if !cur.has_cap(sched::cap::SETPCAP) { return -(Errno::Eperm.as_i32() as i64); }
            let mask = !(1u64 << cap);
            cur.creds.cap_bounding.fetch_and(mask, Ordering::AcqRel);
            0
        }
        PR_GET_SECCOMP => {
            // SAFETY: running task on this CPU; preempt-off; sole reader/writer of seccomp_filters per `13§5`.
            let n = unsafe { (*cur.seccomp_filters.get()).len() };
            if n == 0 { 0 } else { 2 } // 0 = SECCOMP_MODE_DISABLED, 2 = SECCOMP_MODE_FILTER
        }
        PR_SET_SECCOMP => {
            // Modern programs use the seccomp(2) syscall directly; this
            // legacy entry stays EINVAL for now.
            -(Errno::Einval.as_i32() as i64)
        }
        _ => -(Errno::Einval.as_i32() as i64),
    }
}
