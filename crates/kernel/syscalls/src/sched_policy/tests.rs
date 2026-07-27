// Hosted unit tests for the scheduler-policy decision core. These are the
// rules that only ever regressed silently, because the syscall slot files are
// `#![cfg(target_os = "oxide-kernel")]` and unreachable from `cargo test`.
// Reference: Linux `kernel/sched/syscalls.c` (v7.2.0-rc4).

use super::*;
use alloc::sync::Arc;
use core::sync::atomic::Ordering;
use sched::{SchedClass, SchedPolicy, Task};
use syscall::errno::Errno;

const EINVAL: i64 = -(Errno::Einval as i32 as i64);
const EPERM: i64 = -(Errno::Eperm as i32 as i64);
const EOPNOTSUPP: i64 = -(Errno::Eopnotsupp as i32 as i64);

/// Unprivileged task owned by `uid`, running `policy`.
fn task(tid: u32, uid: u32, class: SchedClass, policy: u32) -> Arc<Task> {
    let t = Task::new(tid, "sched-policy-test", class);
    t.creds.ruid.store(uid, Ordering::Release);
    t.creds.euid.store(uid, Ordering::Release);
    t.creds.cap_effective.store(0, Ordering::Release);
    t.policy.store(policy, Ordering::Release);
    Arc::new(t)
}

fn normal(tid: u32, uid: u32) -> Arc<Task> {
    task(tid, uid, SchedClass::Normal { weight: 1024 }, SCHED_NORMAL)
}

fn privileged(t: &Arc<Task>) {
    t.creds.cap_effective.store(1u64 << sched::cap::SYS_NICE, Ordering::Release);
}

fn set_rtprio(t: &Arc<Task>, v: u64) {
    t.set_rlimit(sched::rlimit::rlim::RTPRIO, (v, v));
}

// --- policy predicates -----------------------------------------------------

#[test]
fn policy_set_matches_linux_valid_policy() {
    for p in [SCHED_NORMAL, SCHED_FIFO, SCHED_RR, SCHED_BATCH, SCHED_IDLE, SCHED_DEADLINE] {
        assert!(valid_policy(p), "policy {p} must be valid");
    }
    // 4 is SCHED_ISO (reserved, never implemented); 7 is SCHED_EXT, which this
    // scheduler does not have (Linux CONFIG_SCHED_CLASS_EXT=n).
    for p in [4u32, SCHED_EXT, 8, 100, u32::MAX] {
        assert!(!valid_policy(p), "policy {p} must be invalid");
    }
}

#[test]
fn reset_on_fork_flag_splits_off_the_policy_argument() {
    assert_eq!(split_reset_on_fork(SCHED_FIFO as i32), (SCHED_FIFO as i32, false));
    let arg = (SCHED_RR | SCHED_RESET_ON_FORK) as i32;
    assert_eq!(split_reset_on_fork(arg), (SCHED_RR as i32, true));
    // SETPARAM_POLICY is a sentinel, never masked.
    assert_eq!(split_reset_on_fork(SETPARAM_POLICY), (SETPARAM_POLICY, false));
}

// --- policy-dependent priority ranges --------------------------------------

#[test]
fn get_priority_max_is_policy_dependent_not_constant() {
    assert_eq!(priority_max(SCHED_FIFO as i32), 99);
    assert_eq!(priority_max(SCHED_RR as i32), 99);
    assert_eq!(priority_max(SCHED_NORMAL as i32), 0);
    assert_eq!(priority_max(SCHED_BATCH as i32), 0);
    assert_eq!(priority_max(SCHED_IDLE as i32), 0);
    assert_eq!(priority_max(SCHED_DEADLINE as i32), 0);
    assert_eq!(priority_max(SCHED_EXT as i32), 0);
    assert_eq!(priority_max(4), EINVAL);
    assert_eq!(priority_max(8), EINVAL);
    assert_eq!(priority_max(-1), EINVAL);
}

#[test]
fn get_priority_min_is_policy_dependent_not_constant() {
    assert_eq!(priority_min(SCHED_FIFO as i32), 1);
    assert_eq!(priority_min(SCHED_RR as i32), 1);
    assert_eq!(priority_min(SCHED_NORMAL as i32), 0);
    assert_eq!(priority_min(SCHED_BATCH as i32), 0);
    assert_eq!(priority_min(SCHED_IDLE as i32), 0);
    assert_eq!(priority_min(SCHED_DEADLINE as i32), 0);
    assert_eq!(priority_min(SCHED_EXT as i32), 0);
    assert_eq!(priority_min(4), EINVAL);
    assert_eq!(priority_min(-1), EINVAL);
}

// --- priority validity is POLICY-DEPENDENT ---------------------------------

#[test]
fn rt_policies_require_priority_one_to_ninetynine() {
    for p in [SCHED_FIFO, SCHED_RR] {
        assert_eq!(check_params(p, 0, false), Err(EINVAL), "RT prio 0 is EINVAL");
        assert_eq!(check_params(p, 1, false), Ok(()));
        assert_eq!(check_params(p, 99, false), Ok(()));
        assert_eq!(check_params(p, 100, false), Err(EINVAL));
        assert_eq!(check_params(p, -1, false), Err(EINVAL));
    }
}

#[test]
fn non_rt_policies_require_priority_exactly_zero() {
    for p in [SCHED_NORMAL, SCHED_BATCH, SCHED_IDLE] {
        assert_eq!(check_params(p, 0, false), Ok(()));
        // The commonly-missed one: a non-zero priority with SCHED_NORMAL.
        assert_eq!(check_params(p, 1, false), Err(EINVAL));
        assert_eq!(check_params(p, 50, false), Err(EINVAL));
        assert_eq!(check_params(p, 99, false), Err(EINVAL));
    }
}

#[test]
fn unknown_policy_is_einval() {
    assert_eq!(check_params(4, 0, false), Err(EINVAL));
    assert_eq!(check_params(SCHED_EXT, 0, false), Err(EINVAL));
    assert_eq!(check_params(99, 0, false), Err(EINVAL));
}

#[test]
fn deadline_without_dl_parameters_is_einval() {
    // sched_setscheduler(2) carries no runtime/deadline/period, so Linux's
    // __checkparam_dl always fails there.
    assert_eq!(check_params(SCHED_DEADLINE, 0, false), Err(EINVAL));
    assert!(!checkparam_dl(0, 0, 0));
    assert!(checkparam_dl(1_000_000, 10_000_000, 10_000_000));
    assert!(!checkparam_dl(20_000_000, 10_000_000, 10_000_000)); // runtime > deadline
    assert!(!checkparam_dl(1_000_000, 10_000_000, 5_000_000));   // period < deadline
}

// --- pid argument ----------------------------------------------------------

#[test]
fn negative_pid_is_einval_not_an_unsigned_wrap() {
    assert_eq!(pid_arg(0), Ok(0));
    assert_eq!(pid_arg(42), Ok(42));
    assert_eq!(pid_arg((-1i32) as u32 as u64), Err(EINVAL));
    assert_eq!(pid_arg((-4096i32) as u32 as u64), Err(EINVAL));
    // Upper 32 bits are ignored (pid_t is int), same as Linux.
    assert_eq!(pid_arg(0xFFFF_FFFF_0000_0007), Ok(7));
}

// --- rr_get_interval -------------------------------------------------------

#[test]
fn rr_interval_is_zero_for_every_non_rr_policy() {
    assert_eq!(rr_interval_ns(SCHED_RR, true), SCHED_RR_TIMESLICE_NS);
    assert_eq!(rr_interval_ns(SCHED_RR, false), SCHED_RR_TIMESLICE_NS);
    // SCHED_FIFO has no timeslice at all.
    assert_eq!(rr_interval_ns(SCHED_FIFO, true), 0);
    assert_eq!(rr_interval_ns(SCHED_DEADLINE, true), 0);
    // Fair policies report the CFS slice, never the RR quantum, and 0 on an
    // otherwise-idle runqueue.
    for p in [SCHED_NORMAL, SCHED_BATCH, SCHED_IDLE] {
        assert_eq!(rr_interval_ns(p, false), 0);
        assert_eq!(rr_interval_ns(p, true), SCHED_BASE_SLICE_NS);
        assert_ne!(rr_interval_ns(p, true), SCHED_RR_TIMESLICE_NS);
    }
}

// --- permission rules ------------------------------------------------------

#[test]
fn cross_owner_change_is_denied_without_cap_sys_nice() {
    let caller = normal(1, 1000);
    let target = normal(2, 1001);
    assert_eq!(user_check(&caller, &target, SCHED_NORMAL, 0, 0, false), EPERM);
    privileged(&caller);
    assert_eq!(user_check(&caller, &target, SCHED_NORMAL, 0, 0, false), 0);
}

#[test]
fn entering_rt_needs_rlimit_rtprio_or_cap_sys_nice() {
    let caller = normal(1, 1000);
    let target = normal(2, 1000);
    set_rtprio(&target, 0);
    assert_eq!(user_check(&caller, &target, SCHED_FIFO, 0, 10, false), EPERM);
    set_rtprio(&target, 50);
    assert_eq!(user_check(&caller, &target, SCHED_FIFO, 0, 10, false), 0);
    // Above the allowance is still denied.
    assert_eq!(user_check(&caller, &target, SCHED_FIFO, 0, 60, false), EPERM);
    privileged(&caller);
    assert_eq!(user_check(&caller, &target, SCHED_FIFO, 0, 60, false), 0);
}

#[test]
fn unprivileged_rt_task_may_lower_its_own_priority() {
    let caller = normal(1, 1000);
    let target = task(2, 1000, SchedClass::Rt { prio: 30, policy: SchedPolicy::Rr }, SCHED_RR);
    set_rtprio(&target, 0);
    // Same policy, lower priority: allowed even with RLIMIT_RTPRIO == 0.
    assert_eq!(user_check(&caller, &target, SCHED_RR, 0, 20, false), 0);
    // Raising is not.
    assert_eq!(user_check(&caller, &target, SCHED_RR, 0, 40, false), EPERM);
    // Switching to a different RT policy is not.
    assert_eq!(user_check(&caller, &target, SCHED_FIFO, 0, 20, false), EPERM);
}

#[test]
fn unprivileged_deadline_is_always_denied() {
    let caller = normal(1, 1000);
    let target = normal(2, 1000);
    set_rtprio(&target, 99);
    assert_eq!(user_check(&caller, &target, SCHED_DEADLINE, 0, 0, false), EPERM);
}

#[test]
fn leaving_sched_idle_needs_rlimit_nice_room() {
    let caller = normal(1, 1000);
    let target = task(2, 1000, SchedClass::Normal { weight: SCHED_IDLE_WEIGHT }, SCHED_IDLE);
    target.set_rlimit(sched::rlimit::rlim::NICE, (0, 0));
    assert_eq!(user_check(&caller, &target, SCHED_NORMAL, 0, 0, false), EPERM);
    // Staying in SCHED_IDLE is fine.
    assert_eq!(user_check(&caller, &target, SCHED_IDLE, 0, 0, false), 0);
    // With RLIMIT_NICE room (nice_to_rlimit(0) == 20), leaving is allowed.
    target.set_rlimit(sched::rlimit::rlim::NICE, (20, 20));
    assert_eq!(user_check(&caller, &target, SCHED_NORMAL, 0, 0, false), 0);
}

#[test]
fn unprivileged_user_may_not_clear_reset_on_fork() {
    let caller = normal(1, 1000);
    let target = normal(2, 1000);
    target.sched_reset_on_fork.store(true, Ordering::Release);
    assert_eq!(user_check(&caller, &target, SCHED_NORMAL, 0, 0, false), EPERM);
    // Keeping it set is fine.
    assert_eq!(user_check(&caller, &target, SCHED_NORMAL, 0, 0, true), 0);
}

#[test]
fn lowering_nice_beyond_rlimit_nice_needs_privilege() {
    let caller = normal(1, 1000);
    let target = normal(2, 1000);
    target.nice.store(5, Ordering::Release);
    target.set_rlimit(sched::rlimit::rlim::NICE, (0, 0));
    assert_eq!(user_check(&caller, &target, SCHED_NORMAL, -5, 0, false), EPERM);
    // Raising nice (lower priority) never needs privilege.
    assert_eq!(user_check(&caller, &target, SCHED_NORMAL, 10, 0, false), 0);
}

// --- errno ORDER: EINVAL beats EPERM ---------------------------------------

#[test]
fn invalid_priority_is_einval_even_when_the_caller_would_be_denied() {
    // Cross-owner caller (would be EPERM) with an out-of-range RT priority:
    // Linux validates parameters BEFORE user_check_sched_setscheduler.
    let caller = normal(1, 1000);
    let target = normal(2, 1001);
    assert_eq!(setscheduler(&caller, &target, SCHED_FIFO as i32, 200, 0, false), EINVAL);
    assert_eq!(setscheduler(&caller, &target, SCHED_NORMAL as i32, 5, 0, false), EINVAL);
    assert_eq!(setscheduler(&caller, &target, 4, 0, 0, false), EINVAL);
    // With a valid priority the same call is EPERM.
    assert_eq!(setscheduler(&caller, &target, SCHED_FIFO as i32, 10, 0, false), EPERM);
}

// --- end-to-end policy application -----------------------------------------

#[test]
fn setscheduler_round_trips_every_implemented_policy() {
    let caller = normal(1, 0);
    privileged(&caller);
    for (p, prio) in [(SCHED_FIFO, 40), (SCHED_RR, 7), (SCHED_NORMAL, 0),
                      (SCHED_BATCH, 0), (SCHED_IDLE, 0)] {
        let t = normal(2, 0);
        assert_eq!(setscheduler(&caller, &t, p as i32, prio, 0, false), 0, "policy {p}");
        assert_eq!(task_policy(&t), p, "policy {p} must round-trip");
        assert_eq!(task_rt_priority(&t), prio as u32, "prio for policy {p}");
    }
}

#[test]
fn sched_idle_lands_on_the_idle_weight() {
    let caller = normal(1, 0);
    privileged(&caller);
    let t = normal(2, 0);
    assert_eq!(setscheduler(&caller, &t, SCHED_IDLE as i32, 0, 0, false), 0);
    assert_eq!(t.load_weight.load(Ordering::Acquire), SCHED_IDLE_WEIGHT);
    assert!(matches!(t.sched_class(), SchedClass::Normal { weight } if weight == SCHED_IDLE_WEIGHT));
}

#[test]
fn reset_on_fork_bit_is_recorded_and_reported() {
    let caller = normal(1, 0);
    privileged(&caller);
    let t = normal(2, 0);
    let arg = (SCHED_RR | SCHED_RESET_ON_FORK) as i32;
    assert_eq!(setscheduler(&caller, &t, arg, 5, 0, false), 0);
    assert_eq!(task_policy(&t), SCHED_RR);
    assert!(t.sched_reset_on_fork.load(Ordering::Acquire));
    // Clearing it: a privileged caller may.
    assert_eq!(setscheduler(&caller, &t, SCHED_RR as i32, 5, 0, false), 0);
    assert!(!t.sched_reset_on_fork.load(Ordering::Acquire));
}

#[test]
fn setparam_sentinel_keeps_the_current_policy() {
    let caller = normal(1, 0);
    privileged(&caller);
    let t = normal(2, 0);
    assert_eq!(setscheduler(&caller, &t, SCHED_FIFO as i32, 20, 0, false), 0);
    // sched_setparam(2): SETPARAM_POLICY + a new RT priority.
    assert_eq!(setscheduler(&caller, &t, SETPARAM_POLICY, 33, 0, false), 0);
    assert_eq!(task_policy(&t), SCHED_FIFO);
    assert_eq!(task_rt_priority(&t), 33);
    // A non-zero priority on a SCHED_NORMAL task is EINVAL through the same path.
    let n = normal(3, 0);
    assert_eq!(setscheduler(&caller, &n, SETPARAM_POLICY, 5, 0, false), EINVAL);
    assert_eq!(setscheduler(&caller, &n, SETPARAM_POLICY, 0, 0, false), 0);
    // As is a non-zero priority on a SCHED_IDLE task; zero is accepted.
    let i = normal(4, 0);
    assert_eq!(setscheduler(&caller, &i, SCHED_IDLE as i32, 0, 0, false), 0);
    assert_eq!(setscheduler(&caller, &i, SETPARAM_POLICY, 1, 0, false), EINVAL);
    assert_eq!(setscheduler(&caller, &i, SETPARAM_POLICY, 0, 0, false), 0);
    assert_eq!(task_policy(&i), SCHED_IDLE);
}

#[test]
fn deadline_is_rejected_never_silently_run_as_normal() {
    let caller = normal(1, 0);
    privileged(&caller);
    let t = normal(2, 0);
    // sched_setscheduler(2) path: no DL parameters ⇒ EINVAL, like Linux.
    assert_eq!(setscheduler(&caller, &t, SCHED_DEADLINE as i32, 0, 0, false), EINVAL);
    // sched_setattr(2) path with well-formed DL parameters: this scheduler has
    // no deadline class, so it refuses rather than recording a policy it would
    // then run as SCHED_NORMAL.
    assert_eq!(setscheduler(&caller, &t, SCHED_DEADLINE as i32, 0, 0, true), EOPNOTSUPP);
    assert_eq!(task_policy(&t), SCHED_NORMAL);
}

// --- fork inheritance ------------------------------------------------------

#[test]
fn fork_inherits_policy_and_priority() {
    let parent = task(1, 0, SchedClass::Rt { prio: 42, policy: SchedPolicy::Rr }, SCHED_RR);
    parent.nice.store(-3, Ordering::Release);
    let child = normal(2, 0);
    sched::live::sched_fork::inherit_sched_params(&child, &parent);
    assert_eq!(task_policy(&child), SCHED_RR);
    assert_eq!(task_rt_priority(&child), 42);
    assert_eq!(child.nice.load(Ordering::Acquire), -3);
}

#[test]
fn reset_on_fork_demotes_the_child_and_clears_itself() {
    let parent = task(1, 0, SchedClass::Rt { prio: 42, policy: SchedPolicy::Fifo }, SCHED_FIFO);
    parent.sched_reset_on_fork.store(true, Ordering::Release);
    let child = normal(2, 0);
    sched::live::sched_fork::inherit_sched_params(&child, &parent);
    assert_eq!(task_policy(&child), SCHED_NORMAL);
    assert_eq!(task_rt_priority(&child), 0);
    assert_eq!(child.nice.load(Ordering::Acquire), 0);
    // One generation only: the child does not pass the flag on.
    assert!(!child.sched_reset_on_fork.load(Ordering::Acquire));
    // The parent keeps its own policy.
    assert_eq!(task_policy(&parent), SCHED_FIFO);
}

#[test]
fn reset_on_fork_lifts_a_negative_nice_child_to_zero() {
    let parent = normal(1, 0);
    parent.nice.store(-10, Ordering::Release);
    parent.sched_reset_on_fork.store(true, Ordering::Release);
    let child = normal(2, 0);
    sched::live::sched_fork::inherit_sched_params(&child, &parent);
    assert_eq!(child.nice.load(Ordering::Acquire), 0);
    // A positive nice is NOT reset.
    parent.nice.store(7, Ordering::Release);
    let child2 = normal(3, 0);
    sched::live::sched_fork::inherit_sched_params(&child2, &parent);
    assert_eq!(child2.nice.load(Ordering::Acquire), 7);
}

// --- namespace-scoped pid lookup -------------------------------------------

#[test]
fn pid_lookup_is_scoped_to_a_pid_namespace() {
    use namespace_identity::NamespaceKind;
    let t = normal(90001, 0);
    t.vtid.store(4242, Ordering::Release);
    t.vtgid.store(4242, Ordering::Release);
    sched::live::registry::insert(&t);

    let init_ns = namespace_identity::initial(NamespaceKind::Pid);
    let found = sched::live::registry::lookup_in_namespace(&init_ns, 4242);
    assert!(found.is_some(), "vpid 4242 must resolve inside its own pid namespace");
    assert_eq!(found.unwrap().tid, 90001);

    // A pid namespace the task is not a member of must not see it: the lookup
    // matches `visible_tid(ns)`, never a bare tid comparison.
    let user_ns = namespace_identity::initial(NamespaceKind::User);
    let other = namespace_identity::allocate(NamespaceKind::Pid, user_ns, Some(init_ns))
        .expect("child pid namespace");
    assert!(sched::live::registry::lookup_in_namespace(&other, 4242).is_none(),
            "vpid must not leak across pid namespaces");
    sched::registry::clear_for_tests();
}
