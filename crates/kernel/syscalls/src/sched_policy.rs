// Scheduler-policy decision core — Linux `kernel/sched/syscalls.c`
// (`__sched_setscheduler`, `user_check_sched_setscheduler`,
// `sys_sched_get_priority_{max,min}`, `sched_rr_get_interval`) and the
// `kernel/sched/sched.h` policy predicates.
//
// Deliberately NOT `#![cfg(target_os = "oxide-kernel")]`: the slot files
// (142/143/144/145/146/147/148/314/315) are kernel-only, so every rule that
// lived inside them was unreachable from `cargo test`. The errno ORDER and
// the policy-dependent priority ranges are exactly the parts that regress
// silently, so they live here and the slots stay thin shims (docs/53).
//
// Module manifest:
//   this file — UAPI constants, policy predicates, parameter validation,
//               priority ranges, RR interval, and the `Task`-level
//               permission check + policy application.
//   tests/     — hosted unit tests (`sched_policy_tests.rs`).

use syscall::errno::Errno;

/// `SCHED_NORMAL` == `SCHED_OTHER`.
pub const SCHED_NORMAL: u32 = 0;
/// `SCHED_FIFO`.
pub const SCHED_FIFO: u32 = 1;
/// `SCHED_RR`.
pub const SCHED_RR: u32 = 2;
/// `SCHED_BATCH`.
pub const SCHED_BATCH: u32 = 3;
/// `SCHED_IDLE`.
pub const SCHED_IDLE: u32 = 5;
/// `SCHED_DEADLINE`.
pub const SCHED_DEADLINE: u32 = 6;
/// `SCHED_EXT`. Not a valid `sched_setscheduler` policy here (oxide has no
/// sched_ext class, i.e. Linux `CONFIG_SCHED_CLASS_EXT=n`), but Linux's
/// `sched_get_priority_{max,min}` switch accepts it unconditionally.
pub const SCHED_EXT: u32 = 7;
/// `SCHED_RESET_ON_FORK` — ORed into the `policy` argument of
/// `sched_setscheduler(2)` (uapi/linux/sched.h).
pub const SCHED_RESET_ON_FORK: u32 = 0x4000_0000;

/// Linux `MAX_RT_PRIO - 1` — the largest `sched_priority` any policy accepts.
pub const RT_PRIO_MAX: u32 = 99;
/// Lowest RT priority.
pub const RT_PRIO_MIN: u32 = 1;
/// Linux `SETPARAM_POLICY`: the internal "keep the task's current policy"
/// sentinel `sched_setparam(2)` passes down.
pub const SETPARAM_POLICY: i32 = -1;

/// Linux `RR_TIMESLICE` = `100 * HZ / 1000` jiffies = 100 ms.
pub const SCHED_RR_TIMESLICE_NS: u64 = 100_000_000;
/// Linux `sysctl_sched_base_slice` — the CFS slice reported by
/// `get_rr_interval_fair` for a loaded runqueue.
pub const SCHED_BASE_SLICE_NS: u64 = 3_000_000;
/// Linux `WEIGHT_IDLEPRIO` — the CFS weight a `SCHED_IDLE` task carries.
pub const SCHED_IDLE_WEIGHT: u32 = 3;

/// Linux `nice_to_rlimit()`: nice [19,-20] → rlimit style [1,40].
/// # C: O(1)
pub fn nice_to_rlimit(nice: i32) -> i32 { 20 - nice }

/// Linux `idle_policy()`.
/// # C: O(1)
pub fn idle_policy(policy: u32) -> bool { policy == SCHED_IDLE }

/// Linux `fair_policy()`. `SCHED_EXT` is excluded — no sched_ext class here.
/// # C: O(1)
pub fn fair_policy(policy: u32) -> bool { policy == SCHED_NORMAL || policy == SCHED_BATCH }

/// Linux `rt_policy()`.
/// # C: O(1)
pub fn rt_policy(policy: u32) -> bool { policy == SCHED_FIFO || policy == SCHED_RR }

/// Linux `dl_policy()`.
/// # C: O(1)
pub fn dl_policy(policy: u32) -> bool { policy == SCHED_DEADLINE }

/// Linux `valid_policy()` — the set `sched_setscheduler`/`sched_setattr` accept.
/// # C: O(1)
pub fn valid_policy(policy: u32) -> bool {
    idle_policy(policy) || fair_policy(policy) || rt_policy(policy) || dl_policy(policy)
}

/// Negative `errno` as the syscall return convention uses it.
/// # C: O(1)
pub fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Split `SCHED_RESET_ON_FORK` out of the `policy` argument, Linux
/// `_sched_setscheduler()`'s "fixup the legacy SCHED_RESET_ON_FORK hack".
/// The sentinel `SETPARAM_POLICY` is passed through untouched.
/// # C: O(1)
pub fn split_reset_on_fork(policy_arg: i32) -> (i32, bool) {
    if policy_arg == SETPARAM_POLICY { return (policy_arg, false); }
    let raw = policy_arg as u32;
    ((raw & !SCHED_RESET_ON_FORK) as i32, raw & SCHED_RESET_ON_FORK != 0)
}

/// Linux `sys_sched_get_priority_max()`. Policy-dependent, `-EINVAL` for an
/// unknown policy — NOT a constant.
/// # C: O(1)
pub fn priority_max(policy: i32) -> i64 {
    match policy as u32 {
        SCHED_FIFO | SCHED_RR => RT_PRIO_MAX as i64,
        SCHED_DEADLINE | SCHED_NORMAL | SCHED_BATCH | SCHED_IDLE | SCHED_EXT => 0,
        _ => err(Errno::Einval),
    }
}

/// Linux `sys_sched_get_priority_min()`.
/// # C: O(1)
pub fn priority_min(policy: i32) -> i64 {
    match policy as u32 {
        SCHED_FIFO | SCHED_RR => RT_PRIO_MIN as i64,
        SCHED_DEADLINE | SCHED_NORMAL | SCHED_BATCH | SCHED_IDLE | SCHED_EXT => 0,
        _ => err(Errno::Einval),
    }
}

/// Linux `__checkparam_dl()` applied to the parameters a `sched_param`-based
/// `sched_setscheduler(2)` can express: `sched_runtime`/`sched_deadline`/
/// `sched_period` are all zero there, so a DEADLINE request from slot 144 can
/// never satisfy it and fails `-EINVAL` before any permission check. That is
/// what mainline Linux returns for `sched_setscheduler(pid, SCHED_DEADLINE, …)`.
/// # C: O(1)
pub fn checkparam_dl(runtime: u64, deadline: u64, period: u64) -> bool {
    // Linux: a special (0-runtime) DL attr is only legal via SCHED_FLAG_SUGOV,
    // which is kernel-internal. runtime must be non-zero, and
    // runtime <= deadline <= period once period is given.
    if runtime == 0 || deadline == 0 { return false; }
    let period = if period == 0 { deadline } else { period };
    if period < deadline { return false; }
    if deadline < runtime { return false; }
    true
}

/// Linux `__sched_setscheduler()` parameter validation, in Linux's ORDER —
/// this runs BEFORE any permission check, so a bad priority is `EINVAL` even
/// for a caller that would have been denied `EPERM`.
///
/// `prio` is the raw `sched_param.sched_priority`, interpreted the way Linux
/// does (`attr->sched_priority` is `__u32`), so a negative value becomes a
/// huge unsigned and trips the range check.
///
/// Rule: RT policies need `1..=99`, every non-RT policy needs exactly `0`.
/// # C: O(1)
pub fn check_params(policy: u32, prio: i32, dl_ok: bool) -> Result<(), i64> {
    if !valid_policy(policy) { return Err(err(Errno::Einval)); }
    if (prio as u32) > RT_PRIO_MAX { return Err(err(Errno::Einval)); }
    if dl_policy(policy) && !dl_ok { return Err(err(Errno::Einval)); }
    if rt_policy(policy) != (prio != 0) { return Err(err(Errno::Einval)); }
    Ok(())
}

/// Linux `sched_rr_get_interval()` + the class `get_rr_interval` hooks:
/// `SCHED_RR` → the RR quantum; `SCHED_FIFO` → 0; the fair policies
/// (`NORMAL`/`BATCH`/`IDLE`) → the CFS slice when the runqueue carries load,
/// else 0. A `sched_rr_get_interval` on a non-RR task therefore reports ZERO
/// seconds for RT-FIFO and a slice (never the RR quantum) for CFS.
/// # C: O(1)
pub fn rr_interval_ns(policy: u32, rq_loaded: bool) -> u64 {
    if policy == SCHED_RR { return SCHED_RR_TIMESLICE_NS; }
    if rt_policy(policy) || dl_policy(policy) { return 0; }
    if rq_loaded { SCHED_BASE_SLICE_NS } else { 0 }
}

/// Linux `pid_t` argument decoding for the sched family: the syscall argument
/// is an `int`, a negative pid is `-EINVAL` (never a huge unsigned wrap).
/// # C: O(1)
pub fn pid_arg(raw: u64) -> Result<u32, i64> {
    let pid = raw as i32;
    if pid < 0 { return Err(err(Errno::Einval)); }
    Ok(pid as u32)
}

// ---------------------------------------------------------------------------
// Task-level rules. `&sched::Task` is hosted-constructible (`Task::new`), so
// these stay testable without a boot.
// ---------------------------------------------------------------------------

/// Live policy of `t` — Linux `p->policy`, stored separately from the
/// scheduler class exactly as Linux does, so `SCHED_BATCH`/`SCHED_IDLE`
/// round-trip through `sched_getscheduler` instead of collapsing onto the
/// class that implements them.
/// # C: O(1)
pub fn task_policy(t: &sched::Task) -> u32 {
    t.policy.load(core::sync::atomic::Ordering::Acquire)
}

/// Linux `p->rt_priority`: the RT priority, 0 for every non-RT policy.
/// # C: O(1)
pub fn task_rt_priority(t: &sched::Task) -> u32 {
    match t.sched_class() { sched::SchedClass::Rt { prio, .. } => prio as u32, _ => 0 }
}

/// Linux `is_nice_reduction()`: is `nice` within the target's `RLIMIT_NICE`
/// allowance (expressed as `20 - nice`)?
/// # C: O(1)
fn is_nice_reduction(target: &sched::Task, nice: i32) -> bool {
    let lim = target.rlimit(sched::rlimit::rlim::NICE).0;
    nice_to_rlimit(nice) as i64 <= lim as i64
}

/// Linux `check_same_owner()`: caller's euid matches the target's euid or ruid.
/// # C: O(1)
pub fn check_same_owner(caller: &sched::Task, target: &sched::Task) -> bool {
    use core::sync::atomic::Ordering;
    let euid = caller.creds.euid.load(Ordering::Acquire);
    euid == target.creds.euid.load(Ordering::Acquire)
        || euid == target.creds.ruid.load(Ordering::Acquire)
}

/// Linux `user_check_sched_setscheduler()` verbatim: every branch that needs
/// privilege falls through to a single `capable(CAP_SYS_NICE)` test, so
/// `CAP_SYS_NICE` is an override rather than a precondition. Returns `0` or
/// `-EPERM`.
/// # C: O(1)
pub fn user_check(caller: &sched::Task, target: &sched::Task,
                  policy: u32, nice: i32, prio: u32, reset_on_fork: bool) -> i64 {
    use core::sync::atomic::Ordering;
    let mut req_priv = false;
    let target_nice = target.nice.load(Ordering::Acquire) as i32;

    if fair_policy(policy) && nice < target_nice && !is_nice_reduction(target, nice) { req_priv = true; }

    if rt_policy(policy) {
        let rlim_rtprio = target.rlimit(sched::rlimit::rlim::RTPRIO).0;
        let old_policy = task_policy(target);
        let old_prio = task_rt_priority(target);
        // Can't set/change the rt policy:
        if policy != old_policy && rlim_rtprio == 0 { req_priv = true; }
        // Can't increase priority:
        if prio > old_prio && prio as u64 > rlim_rtprio { req_priv = true; }
    }

    // Unprivileged tasks may never request SCHED_DEADLINE.
    if dl_policy(policy) { req_priv = true; }

    // SCHED_IDLE is treated as nice 20: leaving it needs the RLIMIT_NICE room.
    if idle_policy(task_policy(target)) && !idle_policy(policy)
        && !is_nice_reduction(target, target_nice) { req_priv = true; }

    if !check_same_owner(caller, target) { req_priv = true; }

    // Normal users shall not reset the sched_reset_on_fork flag.
    if target.sched_reset_on_fork.load(Ordering::Acquire) && !reset_on_fork { req_priv = true; }

    if req_priv && !caller.has_cap(sched::cap::SYS_NICE) { return err(Errno::Eperm); }
    0
}

/// Linux `__sched_setscheduler()` for the policies this scheduler implements.
///
/// `policy_arg` is the caller-supplied policy INCLUDING `SCHED_RESET_ON_FORK`,
/// or `SETPARAM_POLICY` for `sched_setparam(2)`. Ordering is Linux's:
/// policy validity → priority validity → permission → apply. Returns `0` or
/// `-errno`.
/// # C: O(log N) requeue
pub fn setscheduler(caller: &sched::Task, t: &alloc::sync::Arc<sched::Task>,
                    policy_arg: i32, prio: i32, nice: i32, dl_ok: bool) -> i64 {
    use core::sync::atomic::Ordering;
    let (policy_i, reset_on_fork) = split_reset_on_fork(policy_arg);
    let (policy, reset_on_fork) = if policy_i == SETPARAM_POLICY {
        (task_policy(t), t.sched_reset_on_fork.load(Ordering::Acquire))
    } else {
        (policy_i as u32, reset_on_fork)
    };
    if let Err(rv) = check_params(policy, prio, dl_ok) { return rv; }
    let prio = prio as u32;

    let authorization = user_check(caller, t, policy, nice, prio, reset_on_fork);
    trace_admission(caller, t, policy, prio, authorization);
    if authorization != 0 { return authorization; }

    // A policy this scheduler cannot honour must not be silently recorded and
    // then run as SCHED_NORMAL. SCHED_DEADLINE has no deadline class here.
    if dl_policy(policy) { return err(Errno::Eopnotsupp); }

    apply(t, policy, nice, prio, reset_on_fork);
    0
}

/// Commit a validated + authorized policy change onto `t`, moving it between
/// the RT and CFS trees under the runqueue lock (Linux's
/// `dequeue → __setscheduler_params → enqueue`).
/// # C: O(log N)
fn apply(t: &alloc::sync::Arc<sched::Task>, policy: u32, nice: i32, prio: u32, reset_on_fork: bool) {
    use core::sync::atomic::Ordering;
    use sched::{SchedClass, SchedPolicy};
    let new_class = match policy {
        SCHED_FIFO | SCHED_RR => {
            let p = if policy == SCHED_FIFO { SchedPolicy::Fifo } else { SchedPolicy::Rr };
            SchedClass::Rt { prio: prio as u8, policy: p }
        }
        SCHED_IDLE => {
            t.load_weight.store(SCHED_IDLE_WEIGHT, Ordering::Release);
            SchedClass::Normal { weight: SCHED_IDLE_WEIGHT }
        }
        // SCHED_NORMAL / SCHED_BATCH
        _ => {
            let n = sched::rlimit::clamp_nice(nice);
            let w = sched::cputime::nice_to_weight(n);
            t.nice.store(n, Ordering::Release);
            t.load_weight.store(w, Ordering::Release);
            SchedClass::Normal { weight: w }
        }
    };
    t.policy.store(policy, Ordering::Release);
    t.sched_reset_on_fork.store(reset_on_fork, Ordering::Release);
    sched::live::runqueue::set_class(t, new_class);
}

/// Bounded scheduler-admission record. Kept behind `debug-boot` so desktop
/// bring-up can separate an RLIMIT denial from a credential denial without
/// perturbing normal scheduling.
#[cfg(all(feature = "debug-boot", target_os = "oxide-kernel"))]
pub fn trace_admission(caller: &sched::Task, target: &sched::Task, policy: u32, prio: u32, result: i64) {
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

/// # C: O(1)
#[cfg(not(all(feature = "debug-boot", target_os = "oxide-kernel")))]
pub fn trace_admission(_caller: &sched::Task, _target: &sched::Task, _policy: u32, _prio: u32, _result: i64) {}

#[cfg(all(test, not(target_os = "oxide-kernel")))]
#[path = "sched_policy/tests.rs"]
mod tests;
