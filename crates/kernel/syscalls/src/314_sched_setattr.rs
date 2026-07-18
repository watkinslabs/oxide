// 314 sched_setattr — one syscall, one file (docs/53 §0).
// sched_setattr(pid, attr, flags): set policy + priority + nice. Mutates the
// task's SchedClass via the runqueue (dequeue→change→requeue). RT policies
// require privilege; SCHED_DEADLINE is not supported (EOPNOTSUPP).
use core::sync::atomic::Ordering;
use sched::{SchedClass, SchedPolicy};
use syscall::{errno::Errno, SyscallArgs};
use crate::userbuf::validate_user_buf;

const SCHED_OTHER:    u32 = 0;
const SCHED_FIFO:     u32 = 1;
const SCHED_RR:       u32 = 2;
const SCHED_BATCH:    u32 = 3;
const SCHED_IDLE:     u32 = 5;
const SCHED_DEADLINE: u32 = 6;
const SCHED_IDLE_WEIGHT: u32 = 3;   // Linux WEIGHT_IDLEPRIO
const SCHED_ATTR_MIN_SIZE: u64 = 48;
const RT_PRIO_MIN: u32 = 1;
const RT_PRIO_MAX: u32 = 99;
// struct sched_attr field offsets (uapi).
const SA_OFF_SIZE: u64 = 0;
const SA_OFF_POLICY: u64 = 4;
const SA_OFF_NICE: u64 = 16;
const SA_OFF_PRIORITY: u64 = 20;

/// Whether the caller may make RT scheduling changes. Linux gates this on
/// CAP_SYS_NICE in the caller's effective set, not on a uid-0 shortcut: a
/// service such as rtkit intentionally drops uid while retaining this cap.
/// # C: O(1)
pub(crate) fn caller_has_sys_nice() -> bool {
    sched::live::current().map(|c| c.has_cap(sched::cap::SYS_NICE)).unwrap_or(false)
}

/// `sys_sched_setattr(pid, attr, flags)` — slot 314.
/// # C: O(log N) requeue
pub fn sys_sched_setattr(args: &SyscallArgs) -> i64 {
    let pid = args.a0 as u32;
    let uattr = args.a1;
    if args.a2 != 0 { return -(Errno::Einval.as_i32() as i64); } // flags
    if let Err(rv) = validate_user_buf(uattr, SCHED_ATTR_MIN_SIZE, 1) { return rv; }
    // SAFETY: uattr validated readable for the fixed 48-byte sched_attr prefix.
    let (size, policy, nice, prio) = unsafe {
        (core::ptr::read_unaligned((uattr + SA_OFF_SIZE) as *const u32),
         core::ptr::read_unaligned((uattr + SA_OFF_POLICY) as *const u32),
         core::ptr::read_unaligned((uattr + SA_OFF_NICE) as *const i32),
         core::ptr::read_unaligned((uattr + SA_OFF_PRIORITY) as *const u32))
    };
    if (size as u64) < SCHED_ATTR_MIN_SIZE { return -(Errno::Einval.as_i32() as i64); }
    let task = if pid == 0 {
        sched::live::current().and_then(|c| sched::live::registry::lookup(c.tid))
    } else { sched::live::registry::resolve_user_pid(pid) };
    let t = match task { Some(t) => t, None => return -(Errno::Esrch.as_i32() as i64) };
    apply_sched_policy(&t, policy, nice, prio)
}

/// Apply a scheduling `policy` (+ `nice` for normal classes, `prio` for RT) to
/// `t` via the runqueue (dequeue→change→requeue). Shared by sched_setattr and
/// sched_setscheduler (Linux `__sched_setscheduler`). RT policies require
/// CAP_SYS_NICE; SCHED_DEADLINE is EOPNOTSUPP. Returns 0 or `-errno`. # C: O(log N)
pub(crate) fn apply_sched_policy(t: &alloc::sync::Arc<sched::Task>, policy: u32, nice: i32, prio: u32) -> i64 {
    let new_class = match policy {
        SCHED_OTHER | SCHED_BATCH => {
            let n = sched::rlimit::clamp_nice(nice);
            let w = sched::cputime::nice_to_weight(n);
            t.nice.store(n, Ordering::Release);
            t.load_weight.store(w, Ordering::Release);
            SchedClass::Normal { weight: w }
        }
        SCHED_IDLE => {
            t.load_weight.store(SCHED_IDLE_WEIGHT, Ordering::Release);
            SchedClass::Normal { weight: SCHED_IDLE_WEIGHT }
        }
        SCHED_FIFO | SCHED_RR => {
            if !(RT_PRIO_MIN..=RT_PRIO_MAX).contains(&prio) { return -(Errno::Einval.as_i32() as i64); }
            if !caller_has_sys_nice() { return -(Errno::Eperm.as_i32() as i64); }
            let p = if policy == SCHED_FIFO { SchedPolicy::Fifo } else { SchedPolicy::Rr };
            SchedClass::Rt { prio: prio as u8, policy: p }
        }
        SCHED_DEADLINE => return -(Errno::Eopnotsupp.as_i32() as i64),
        _ => return -(Errno::Einval.as_i32() as i64),
    };
    sched::live::runqueue::set_class(t, new_class);
    0
}
