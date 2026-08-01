// Yama's scope ladder. The scope cell and the relation list are process-wide,
// so every test that moves them takes the registry test lock and restores the
// starting scope on the way out.

use super::*;
use crate::task::{SchedClass, Task};
use crate::tests::common::registry_test_lock;

/// Restore the scope on drop. `set_scope` refuses to LOWER the value, so the
/// tests write the cell directly to reset it.
struct ScopeGuard(u8);
impl Drop for ScopeGuard {
    fn drop(&mut self) { SCOPE.store(self.0, Ordering::Release); }
}
fn with_scope(s: u8) -> ScopeGuard {
    let g = ScopeGuard(SCOPE.load(Ordering::Acquire));
    SCOPE.store(s, Ordering::Release);
    g
}

fn task(tid: u32, caps: u64) -> Task {
    let t = Task::new(tid, "yama", SchedClass::Normal { weight: 1024 });
    t.tgid.store(tid, Ordering::Release);
    t.creds.cap_effective.store(caps, Ordering::Release);
    t
}

const CAP_PTRACE: u64 = 1u64 << crate::cap::SYS_PTRACE;

#[test]
fn the_scope_knob_is_bounded_and_one_way() {
    let _g = registry_test_lock();
    let _s = with_scope(SCOPE_DISABLED);
    assert!(set_scope(SCOPE_RELATIONAL as i64));
    assert_eq!(scope(), SCOPE_RELATIONAL);
    // Raising is allowed...
    assert!(set_scope(SCOPE_NO_ATTACH as i64));
    // ...lowering never is, so a compromised privileged process cannot relax
    // a hardened box back to unrestricted ptrace.
    assert!(!set_scope(SCOPE_DISABLED as i64));
    assert_eq!(scope(), SCOPE_NO_ATTACH);
    // Out of range in either direction.
    assert!(!set_scope(-1));
    assert!(!set_scope(SCOPE_MAX as i64 + 1));
}

#[test]
fn scope_zero_restricts_nothing() {
    let _g = registry_test_lock();
    let _s = with_scope(SCOPE_DISABLED);
    let tracer = task(7001, 0);
    let tracee = task(7002, 0);
    assert!(ptrace_access_check(&tracer, &tracee).is_ok());
    assert!(ptrace_traceme(&tracer).is_ok());
}

#[test]
fn scope_relational_refuses_an_unrelated_stranger_without_cap_sys_ptrace() {
    let _g = registry_test_lock();
    let _s = with_scope(SCOPE_RELATIONAL);
    let tracer = task(7011, 0);
    let tracee = task(7012, 0);
    assert!(ptrace_access_check(&tracer, &tracee).is_err());
    let capable = task(7013, CAP_PTRACE);
    assert!(ptrace_access_check(&capable, &tracee).is_ok());
}

#[test]
fn scope_relational_allows_an_already_established_tracer() {
    let _g = registry_test_lock();
    let _s = with_scope(SCOPE_RELATIONAL);
    let tracer = task(7021, 0);
    let tracee = task(7022, 0);
    assert!(ptrace_access_check(&tracer, &tracee).is_err());
    // An attach already in force is itself the exception — that is what lets
    // process_vm_readv follow a tracer that Yama already admitted.
    tracee.traced_by.store(7021, Ordering::Release);
    // Without the tracer in the registry the lookup fails closed.
    assert!(ptrace_access_check(&tracer, &tracee).is_err());
}

#[test]
fn pr_set_ptracer_any_exempts_every_tracer() {
    let _g = registry_test_lock();
    let _s = with_scope(SCOPE_RELATIONAL);
    let tracer = task(7031, 0);
    let tracee = task(7032, 0);
    ptracer_del(7032);
    assert!(ptrace_access_check(&tracer, &tracee).is_err());
    ptracer_add(7032, None);
    assert!(ptrace_access_check(&tracer, &tracee).is_ok());
    // prctl(PR_SET_PTRACER, 0) removes it again.
    ptracer_del(7032);
    assert!(ptrace_access_check(&tracer, &tracee).is_err());
}

#[test]
fn a_named_ptracer_relation_admits_only_that_tracer_tree() {
    let _g = registry_test_lock();
    let _s = with_scope(SCOPE_RELATIONAL);
    let allowed = task(7041, 0);
    let other   = task(7042, 0);
    let tracee  = task(7043, 0);
    ptracer_add(7043, Some(7041));
    // `task_is_descendant(allowed, tracer)` is reflexive on the leader itself.
    assert!(ptrace_access_check(&allowed, &tracee).is_ok());
    assert!(ptrace_access_check(&other, &tracee).is_err());
    ptracer_del(7043);
}

#[test]
fn a_second_pr_set_ptracer_replaces_the_first_rather_than_stacking() {
    let _g = registry_test_lock();
    let _s = with_scope(SCOPE_RELATIONAL);
    let first  = task(7051, 0);
    let second = task(7052, 0);
    let tracee = task(7053, 0);
    ptracer_add(7053, Some(7051));
    ptracer_add(7053, Some(7052));
    assert!(ptrace_access_check(&second, &tracee).is_ok());
    assert!(ptrace_access_check(&first, &tracee).is_err(),
        "the replaced relation must not survive");
    ptracer_del(7053);
}

#[test]
fn a_dead_task_loses_its_relation_in_both_roles() {
    let _g = registry_test_lock();
    let _s = with_scope(SCOPE_RELATIONAL);
    let tracer = task(7061, 0);
    let tracee = task(7062, 0);
    ptracer_add(7062, Some(7061));
    assert!(ptrace_access_check(&tracer, &tracee).is_ok());
    // The named tracer dies: a recycled tid must not inherit the exemption.
    task_free(7061);
    assert!(ptrace_access_check(&tracer, &tracee).is_err());
    ptracer_add(7062, None);
    task_free(7062);
    assert!(ptrace_access_check(&tracer, &tracee).is_err());
}

#[test]
fn scope_capability_ignores_relations_entirely() {
    let _g = registry_test_lock();
    let _s = with_scope(SCOPE_CAPABILITY);
    let tracer = task(7071, 0);
    let tracee = task(7072, 0);
    ptracer_add(7072, None);
    assert!(ptrace_access_check(&tracer, &tracee).is_err(),
        "PR_SET_PTRACER is a RELATIONAL-scope exemption only");
    let capable = task(7073, CAP_PTRACE);
    assert!(ptrace_access_check(&capable, &tracee).is_ok());
    ptracer_del(7072);
}

#[test]
fn scope_no_attach_refuses_even_cap_sys_ptrace() {
    let _g = registry_test_lock();
    let _s = with_scope(SCOPE_NO_ATTACH);
    let capable = task(7081, CAP_PTRACE);
    let tracee  = task(7082, 0);
    assert!(ptrace_access_check(&capable, &tracee).is_err());
}

#[test]
fn traceme_is_restricted_only_by_the_two_highest_scopes() {
    let _g = registry_test_lock();
    let plain   = task(7091, 0);
    let capable = task(7092, CAP_PTRACE);
    {
        let _s = with_scope(SCOPE_DISABLED);
        assert!(ptrace_traceme(&plain).is_ok());
    }
    {
        // RELATIONAL does not restrict TRACEME: the tracee's own parent is
        // by definition a relation.
        let _s = with_scope(SCOPE_RELATIONAL);
        assert!(ptrace_traceme(&plain).is_ok());
    }
    {
        let _s = with_scope(SCOPE_CAPABILITY);
        assert!(ptrace_traceme(&plain).is_err());
        assert!(ptrace_traceme(&capable).is_ok());
    }
    {
        let _s = with_scope(SCOPE_NO_ATTACH);
        assert!(ptrace_traceme(&capable).is_err());
    }
}

#[test]
fn the_ancestry_walk_stops_at_an_unrooted_chain() {
    let _g = registry_test_lock();
    let child = task(7101, 0);
    // parent_tid 0: no parent recorded, so nothing is an ancestor of it.
    assert!(!task_is_descendant(1, &child));
    // A task is its own descendant, which is what makes a tracer's own group
    // pass the RELATIONAL test.
    assert!(task_is_descendant(7101, &child));
    assert!(!task_is_descendant(0, &child));
}

#[test]
fn attach_class_access_is_yama_gated_but_read_class_is_not() {
    // The distinction every ATTACH-class caller depends on. `pidfd_getfd(2)`
    // and `process_vm_readv/writev(2)` take something OUT of another process,
    // which is what `ptrace_scope` restricts — routing them through the
    // READ-class ladder let a same-uid process read another's memory at
    // `ptrace_scope=1`. `kcmp(2)` and `get_robust_list(2)` really are
    // READ-class and must stay ungated.
    use crate::ptrace_access::{may_access_full, Access, Mode};
    let _g = registry_test_lock();
    let _s = with_scope(SCOPE_RELATIONAL);
    let stranger = task(9101, 0);
    let victim = task(9102, 0);
    assert!(may_access_full(&stranger, &victim, Mode::RealCreds, Access::Read).is_ok(),
            "same credentials satisfy the READ-class ladder");
    assert!(may_access_full(&stranger, &victim, Mode::RealCreds, Access::Attach).is_err(),
            "ptrace_scope=1 refuses an unrelated ATTACH");
}

#[test]
fn a_refused_scope_write_is_reported_to_the_caller() {
    // The sysctl leaf turns `false` into EINVAL. Reporting success for a
    // refused lowering would tell a hardening script it had relaxed a
    // restriction that is still in force.
    let _g = registry_test_lock();
    let _s = with_scope(SCOPE_CAPABILITY);
    assert!(!set_scope(SCOPE_RELATIONAL as i64), "lowering is refused");
    assert!(!set_scope(SCOPE_MAX as i64 + 1), "out of range is refused");
    assert_eq!(scope(), SCOPE_CAPABILITY, "a refused write changes nothing");
}
