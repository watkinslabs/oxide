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

/// Whether the caller holds CAP_SYS_NICE in its effective set. This is an
/// override, not the sole way to enter an RT class: Linux also permits a
/// same-owner task within the target's RLIMIT_RTPRIO allowance.
/// # C: O(1)
fn policy_of(t: &sched::Task) -> u32 {
    match t.sched_class() {
        SchedClass::Rt { policy: SchedPolicy::Fifo, .. } => SCHED_FIFO,
        SchedClass::Rt { policy: SchedPolicy::Rr, .. } => SCHED_RR,
        SchedClass::Idle => SCHED_IDLE,
        _ => SCHED_OTHER,
    }
}

/// Bounded-by-call-site scheduler admission record. Kept behind debug-boot so
/// desktop bring-up can distinguish an RLIMIT denial from a credential or
/// policy validation denial without perturbing normal scheduling.
#[cfg(feature = "debug-boot")]
pub(crate) fn trace_sched_admission(caller: &sched::Task, target: &sched::Task,
                                    policy: u32, prio: u32, result: i64) {
    let rtprio = target.rlimit(sched::rlimit::rlim::RTPRIO).0;
    klog::write_raw(b"[SCHEDCTL caller="); klog::write_dec_u64(caller.tid as u64);
    klog::write_raw(b" target="); klog::write_dec_u64(target.tid as u64);
    klog::write_raw(b" policy="); klog::write_dec_u64(policy as u64);
    klog::write_raw(b" prio="); klog::write_dec_u64(prio as u64);
    klog::write_raw(b" rlimit_rtprio="); klog::write_dec_u64(rtprio);
    klog::write_raw(b" cap_sys_nice="); klog::write_dec_u64(caller.has_cap(sched::cap::SYS_NICE) as u64);
    klog::write_raw(b" rv=");
    if result < 0 { klog::write_raw(b"-"); klog::write_dec_u64(result.wrapping_neg() as u64); }
    else { klog::write_dec_u64(result as u64); }
    klog::write_raw(b"]\n");
}

#[cfg(not(feature = "debug-boot"))]
pub(crate) fn trace_sched_admission(_caller: &sched::Task, _target: &sched::Task,
                                    _policy: u32, _prio: u32, _result: i64) {}

/// Linux `user_check_sched_setscheduler()` subset represented by this
/// scheduler: same-owner checks, RLIMIT_NICE and RLIMIT_RTPRIO, with
/// CAP_SYS_NICE as the privileged override. The target's limits matter here,
/// not the caller's; that is Linux's `task_rlimit(p, ...)` contract.
/// # C: O(1)
pub(crate) fn authorize_sched_change(caller: &sched::Task, target: &sched::Task,
                                     policy: u32, nice: i32, prio: u32) -> i64 {
    if caller.has_cap(sched::cap::SYS_NICE) { return 0; }
    let euid = caller.creds.euid.load(Ordering::Acquire);
    let owner_matches = euid == target.creds.euid.load(Ordering::Acquire)
        || euid == target.creds.ruid.load(Ordering::Acquire);
    if !owner_matches { return -(Errno::Eperm.as_i32() as i64); }

    if matches!(policy, SCHED_OTHER | SCHED_BATCH) {
        let old_nice = target.nice.load(Ordering::Acquire) as i32;
        // Linux `is_nice_reduction`: RLIMIT_NICE is expressed as 20 - nice.
        if nice < old_nice {
            let allowed = target.rlimit(sched::rlimit::rlim::NICE).0;
            if (20 - nice) as u64 > allowed { return -(Errno::Eperm.as_i32() as i64); }
        }
    }
    if matches!(policy, SCHED_FIFO | SCHED_RR) {
        let allowed = target.rlimit(sched::rlimit::rlim::RTPRIO).0;
        let (old_policy, old_prio) = match target.sched_class() {
            SchedClass::Rt { prio, .. } => (policy_of(target), prio as u32),
            _ => (policy_of(target), 0),
        };
        // Linux permits an unprivileged RT task to lower its priority. Entering
        // or changing RT policy requires a nonzero RT priority allowance.
        if (policy != old_policy && allowed == 0) || (prio > old_prio && prio as u64 > allowed) {
            return -(Errno::Eperm.as_i32() as i64);
        }
    }
    0
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
    let caller = match sched::live::current() { Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64) };
    apply_sched_policy(caller, &t, policy, nice, prio)
}

/// Apply a scheduling `policy` (+ `nice` for normal classes, `prio` for RT) to
/// `t` via the runqueue (dequeue→change→requeue). Shared by sched_setattr and
/// sched_setscheduler (Linux `__sched_setscheduler`). SCHED_DEADLINE is not
/// implemented. Returns 0 or `-errno`. # C: O(log N)
pub(crate) fn apply_sched_policy(caller: &sched::Task, t: &alloc::sync::Arc<sched::Task>, policy: u32, nice: i32, prio: u32) -> i64 {
    if !matches!(policy, SCHED_OTHER | SCHED_BATCH | SCHED_IDLE | SCHED_FIFO | SCHED_RR | SCHED_DEADLINE) {
        return -(Errno::Einval.as_i32() as i64);
    }
    if !matches!(policy, SCHED_FIFO | SCHED_RR) && prio != 0 {
        return -(Errno::Einval.as_i32() as i64);
    }
    if policy == SCHED_DEADLINE { return -(Errno::Eopnotsupp.as_i32() as i64); }
    let authorization = authorize_sched_change(caller, t, policy, nice, prio);
    trace_sched_admission(caller, t, policy, prio, authorization);
    if authorization != 0 { return authorization; }
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
            let p = if policy == SCHED_FIFO { SchedPolicy::Fifo } else { SchedPolicy::Rr };
            SchedClass::Rt { prio: prio as u8, policy: p }
        }
        SCHED_DEADLINE => unreachable!(),
        _ => return -(Errno::Einval.as_i32() as i64),
    };
    sched::live::runqueue::set_class(t, new_class);
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::Ordering;

    fn task(tid: u32, uid: u32, class: SchedClass) -> sched::Task {
        let task = sched::Task::new(tid, "sched-test", class);
        task.creds.ruid.store(uid, Ordering::Release);
        task.creds.euid.store(uid, Ordering::Release);
        task.creds.cap_effective.store(0, Ordering::Release);
        task
    }

    #[test]
    fn rtprio_limit_allows_same_owner_realtime_policy() {
        let caller = task(1, 1000, SchedClass::Normal { weight: 1024 });
        let target = task(2, 1000, SchedClass::Normal { weight: 1024 });
        assert_eq!(authorize_sched_change(&caller, &target, SCHED_RR, 0, 50), 0);
    }

    #[test]
    fn rtprio_zero_allows_only_lowering_existing_realtime_priority() {
        let caller = task(1, 1000, SchedClass::Normal { weight: 1024 });
        let target = task(2, 1000, SchedClass::Rt { prio: 30, policy: SchedPolicy::Rr });
        target.set_rlimit(sched::rlimit::rlim::RTPRIO, (0, target.rlimit(sched::rlimit::rlim::RTPRIO).1));
        assert_eq!(authorize_sched_change(&caller, &target, SCHED_RR, 0, 20), 0);
        assert_eq!(authorize_sched_change(&caller, &target, SCHED_FIFO, 0, 20), -(Errno::Eperm.as_i32() as i64));
    }

    #[test]
    fn unprivileged_cross_owner_change_is_denied() {
        let caller = task(1, 1000, SchedClass::Normal { weight: 1024 });
        let target = task(2, 1001, SchedClass::Normal { weight: 1024 });
        assert_eq!(authorize_sched_change(&caller, &target, SCHED_OTHER, 0, 0), -(Errno::Eperm.as_i32() as i64));
    }
}
