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
//   this file  — UAPI constants, policy predicates, parameter/flag validation,
//                priority ranges, RR interval, pid decoding.
//   task.rs    — live `Task` accessors + the permission ladder.
//   setattr.rs — `__sched_setscheduler` + the runqueue commit.
//   tests.rs   — hosted unit tests.

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

/// Linux `DL_SCALE` (`kernel/sched/sched.h:182`): the low bits `sched_runtime`
/// loses to the bandwidth fixed point, so a runtime below `1 << DL_SCALE` is
/// rejected outright.
pub const DL_SCALE: u32 = 10;
/// `sysctl_sched_dl_period_min` (`kernel/sched/deadline.c:32`), in ns.
pub const DL_PERIOD_MIN_NS: u64 = 100 * 1_000;
/// `sysctl_sched_dl_period_max` (`kernel/sched/deadline.c:31`), in ns.
pub const DL_PERIOD_MAX_NS: u64 = (1u64 << 22) * 1_000;

/// Linux `__checkparam_dl()` (`kernel/sched/deadline.c:3889`). A `sched_param`-
/// based `sched_setscheduler(2)` leaves runtime/deadline/period zero, so a
/// DEADLINE request from slot 144 can never satisfy this and fails `-EINVAL`
/// before any permission check — mainline's answer for
/// `sched_setscheduler(pid, SCHED_DEADLINE, …)`.
/// # C: O(1)
pub fn checkparam_dl(attr: &crate::sched_attr::SchedAttr) -> bool {
    // Special (parameter-less) DL tasks exist only via the kernel-internal
    // SCHED_FLAG_SUGOV, which the syscall path rejects separately.
    if attr.flags & crate::sched_attr::FLAG_SUGOV != 0 { return true; }
    if attr.deadline == 0 { return false; }
    if attr.runtime < (1u64 << DL_SCALE) { return false; }
    // The MSB is reserved for wrap-around/sign handling in the bandwidth math.
    if attr.deadline & (1u64 << 63) != 0 || attr.period & (1u64 << 63) != 0 { return false; }
    let period = if attr.period == 0 { attr.deadline } else { attr.period };
    if period < attr.deadline || attr.deadline < attr.runtime { return false; }
    if period < DL_PERIOD_MIN_NS || period > DL_PERIOD_MAX_NS { return false; }
    true
}

/// Linux `__sched_setscheduler()` flag-mask gate: anything outside
/// `SCHED_FLAG_ALL | SCHED_FLAG_SUGOV` is an unknown flag.
/// # C: O(1)
pub fn check_flags(flags: u64) -> Result<(), i64> {
    use crate::sched_attr::{FLAG_ALL, FLAG_SUGOV};
    if flags & !(FLAG_ALL | FLAG_SUGOV) != 0 { return Err(err(Errno::Einval)); }
    Ok(())
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

// Task-level rules live in the child modules; `&sched::Task` is
// hosted-constructible (`Task::new`), so both stay testable without a boot.
//   task.rs    — live policy/priority/slice accessors + the permission ladder
//                (`user_check_sched_setscheduler`, `check_same_owner`).
//   setattr.rs — `__sched_setscheduler` proper: validation order, the no-change
//                fast path, and the commit onto the runqueue.
mod task;
mod setattr;
pub use task::{check_same_owner, get_params, task_policy, task_rt_priority, task_slice_ns,
               uclamp_req, user_check};
pub use setattr::{setattr, setscheduler, trace_admission};

#[cfg(all(test, not(target_os = "oxide-kernel")))]
#[path = "sched_policy/tests.rs"]
mod tests;
