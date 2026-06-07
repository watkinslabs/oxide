// 142 sched_setparam — one syscall, one file (docs/53 §0).
// sched_setparam(pid, param): set the RT priority of `pid` (struct sched_param
// { i32 sched_priority; }) keeping its policy. SCHED_OTHER tasks require
// priority 0 (no-op); changing an RT priority requires privilege (euid 0).
use core::sync::atomic::Ordering;
use sched::SchedClass;
use syscall::{errno::Errno, SyscallArgs};

const RT_PRIO_MIN: i32 = 1;
const RT_PRIO_MAX: i32 = 99;

/// `sys_sched_setparam(pid, param)` — slot 142.
/// # C: O(log N) requeue
pub fn sys_sched_setparam(args: &SyscallArgs) -> i64 {
    let pid = args.a0 as u32;
    let uparam = args.a1;
    if uparam == 0 || uparam.saturating_add(4) > hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: uparam range-checked < USER_VA_END; read the i32 sched_priority.
    let prio = unsafe { core::ptr::read_unaligned(uparam as *const i32) };
    let task = if pid == 0 {
        sched::live::current().and_then(|c| sched::live::registry::lookup(c.tid))
    } else { sched::live::registry::lookup(pid) };
    let t = match task { Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64) };
    match t.sched_class() {
        SchedClass::Rt { policy, .. } => {
            if !(RT_PRIO_MIN..=RT_PRIO_MAX).contains(&prio) { return -(Errno::Einval.as_i32() as i64); }
            if !crate::s314_sched_setattr::caller_is_root() { return -(Errno::Eperm.as_i32() as i64); }
            sched::live::runqueue::set_class(&t, SchedClass::Rt { prio: prio as u8, policy });
            0
        }
        SchedClass::Normal { .. } => if prio == 0 { 0 } else { -(Errno::Einval.as_i32() as i64) },
        SchedClass::Idle => -(Errno::Einval.as_i32() as i64),
    }
}
