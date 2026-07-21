// 142 sched_setparam — one syscall, one file (docs/53 §0).
// sched_setparam(pid, param): set the RT priority of `pid` (struct sched_param
// { i32 sched_priority; }) keeping its policy. SCHED_OTHER tasks require
// priority 0 (no-op); changing an RT priority requires CAP_SYS_NICE.
use sched::SchedClass;
use syscall::{errno::Errno, SyscallArgs};
use crate::userbuf::validate_user_buf;

const RT_PRIO_MIN: i32 = 1;
const RT_PRIO_MAX: i32 = 99;

/// `sys_sched_setparam(pid, param)` — slot 142.
/// # C: O(log N) requeue
pub fn sys_sched_setparam(args: &SyscallArgs) -> i64 {
    let pid = args.a0 as u32;
    let uparam = args.a1;
    if let Err(rv) = validate_user_buf(uparam, 4, 1) { return rv; }
    // SAFETY: uparam validated readable for struct sched_param.sched_priority.
    let prio = unsafe { core::ptr::read_unaligned(uparam as *const i32) };
    let task = if pid == 0 {
        sched::live::current().and_then(|c| sched::live::registry::lookup(c.tid))
    } else { sched::live::registry::resolve_user_pid(pid) };
    let t = match task { Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64) };
    match t.sched_class() {
        SchedClass::Rt { policy, .. } => {
            if !(RT_PRIO_MIN..=RT_PRIO_MAX).contains(&prio) { return -(Errno::Einval.as_i32() as i64); }
            let caller = match sched::live::current() { Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64) };
            let policy_nr = if policy == sched::SchedPolicy::Fifo { 1 } else { 2 };
            let authorization = crate::s314_sched_setattr::authorize_sched_change(caller, &t, policy_nr, t.nice.load(core::sync::atomic::Ordering::Acquire) as i32, prio as u32);
            crate::s314_sched_setattr::trace_sched_admission(caller, &t, policy_nr, prio as u32, authorization);
            if authorization != 0 { return authorization; }
            sched::live::runqueue::set_class(&t, SchedClass::Rt { prio: prio as u8, policy });
            0
        }
        SchedClass::Normal { .. } => if prio == 0 { 0 } else { -(Errno::Einval.as_i32() as i64) },
        SchedClass::Idle => -(Errno::Einval.as_i32() as i64),
    }
}
