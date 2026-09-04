// Scheduler/setpriority capability scopes, target walks, and task LSM ordering.

use super::*;
use crate::sched_attr::SchedAttr;
use core::sync::atomic::Ordering;
use namespace_identity::NamespaceKind;
use syscall::errno::Errno;

const EACCES: i64 = -(Errno::Eacces as i32 as i64);
const EBUSY: i64 = -(Errno::Ebusy as i32 as i64);
const NICE_LSM_TID: u32 = 0x7fff_ff01;
const SCHED_LSM_TID: u32 = 0x7fff_ff02;
const NICE_CAP_TID: u32 = 0x7fff_ff03;
const SCHED_CAP_TID: u32 = 0x7fff_ff04;

const OP_MOV64_IMM: u8 = 0xb7;
const OP_LDX_MEM_W: u8 = 0x61;
const OP_LDX_MEM_DW: u8 = 0x79;
const OP_JEQ_IMM: u8 = 0x15;
const OP_EXIT: u8 = 0x95;

fn insn(opcode: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[0] = opcode;
    out[1] = dst & 0x0f | src << 4;
    out[2..4].copy_from_slice(&off.to_le_bytes());
    out[4..8].copy_from_slice(&imm.to_le_bytes());
    out
}

fn selective_task_refusal(first: u32, second: u32, refusal: i64) -> alloc::vec::Vec<u8> {
    [
        insn(OP_LDX_MEM_DW, 2, 1, 0, 0),
        insn(OP_LDX_MEM_W, 3, 2, security::bpf_lsm::task_struct::PID as i16, 0),
        insn(OP_JEQ_IMM, 3, 0, 3, first as i32),
        insn(OP_JEQ_IMM, 3, 0, 2, second as i32),
        insn(OP_MOV64_IMM, 0, 0, 0, 0),
        insn(OP_EXIT, 0, 0, 0, 0),
        insn(OP_MOV64_IMM, 0, 0, 0, refusal as i32),
        insn(OP_EXIT, 0, 0, 0, 0),
    ].into_iter().flatten().collect()
}

fn attach_task_refusal(hook: security::bpf_lsm::Hook, first: u32, second: u32,
                       refusal: i64)
{
    let body = selective_task_refusal(first, second, refusal);
    let prog = security::bpf::make_bpf_prog_inode(
        security::bpf::uapi::prog_type::LSM, body);
    security::bpf_lsm::register(hook, prog).expect("attach scheduler test BPF LSM program");
}

fn install_test_hooks() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // SAFETY: hosted initialization installs immutable framework order;
        // Once guarantees the process performs that installation once.
        unsafe { security::init().unwrap(); }
        attach_task_refusal(security::bpf_lsm::Hook::TaskSetNice,
            NICE_LSM_TID, NICE_CAP_TID, EBUSY);
        attach_task_refusal(security::bpf_lsm::Hook::TaskSetScheduler,
            SCHED_LSM_TID, SCHED_CAP_TID, EACCES);
    });
}

fn child_user(owner_euid: u32) -> namespace_identity::NamespaceRef {
    let init = namespace_identity::initial(NamespaceKind::User);
    let child = namespace_identity::allocate(NamespaceKind::User, init.clone(), Some(init))
        .expect("child user namespace");
    user_namespace::register_owner(&child, owner_euid).unwrap();
    child
}

#[test]
fn scheduler_privilege_requires_initial_user_namespace_capability() {
    install_test_hooks();
    let caller = normal(0x7fff_ff10, 1000);
    let target = normal(0x7fff_ff11, 2000);
    target.set_state(sched::TaskState::Sleeping);
    caller.security.creds.cap_effective.store(0, Ordering::Release);
    caller.security.creds.cap_permitted.store(0, Ordering::Release);
    target.security.creds.cap_permitted.store(1, Ordering::Release);
    assert!(target.replace_namespace(child_user(1000)).is_ok());

    assert_eq!(setattr(&caller, &target, &SchedAttr::default()), EPERM,
        "authority over the target namespace is not capable(CAP_SYS_NICE)");

    privileged(&caller);
    assert_eq!(setattr(&caller, &target, &SchedAttr::default()), 0,
        "CAP_SYS_NICE in the initial namespace overrides the privilege ladder");

    let sibling = child_user(3000);
    assert!(caller.replace_namespace(child_user(1000)).is_ok());
    assert!(target.replace_namespace(sibling).is_ok());
    privileged(&caller);
    assert_eq!(setattr(&caller, &target, &SchedAttr::default()), EPERM,
        "a capability in a sibling namespace grants nothing over the target");
}

#[test]
fn setpriority_privilege_is_checked_in_each_targets_user_namespace() {
    install_test_hooks();
    let caller = normal(0x7fff_ff12, 1000);
    let target = normal(0x7fff_ff13, 2000);
    caller.security.creds.cap_effective.store(0, Ordering::Release);
    caller.security.creds.cap_permitted.store(0, Ordering::Release);
    target.security.creds.cap_permitted.store(1, Ordering::Release);
    assert!(target.replace_namespace(child_user(1000)).is_ok());
    assert_eq!(setpriority_check(&caller, &target, 0), Ok(()));

    assert!(caller.replace_namespace(child_user(1000)).is_ok());
    assert!(target.replace_namespace(child_user(3000)).is_ok());
    privileged(&caller);
    assert_eq!(setpriority_check(&caller, &target, 0), Err(EPERM));
}

#[test]
fn zombie_target_keeps_credential_user_namespace_for_permission_checks() {
    install_test_hooks();
    let caller = normal(0x7fff_ff50, 1000);
    let target = normal(0x7fff_ff51, 2000);
    let user_ns = child_user(1000);
    assert!(caller.replace_namespace(user_ns.clone()).is_ok());
    assert!(target.replace_namespace(user_ns.clone()).is_ok());
    caller.security.creds.cap_effective.store(0, Ordering::Release);
    target.set_state(sched::TaskState::Sleeping);
    target.mark_done();
    assert!(target.namespace_snapshot().is_none(), "zombie drops namespace membership");
    assert_eq!(target.namespace_owner(NamespaceKind::User).unwrap().id(), user_ns.id(),
        "credentials retain user_ns through zombie lifetime");
    assert_eq!(setpriority_check(&caller, &target, 10), Err(EPERM));
    privileged(&caller);
    assert_eq!(setpriority_check(&caller, &target, 10), Ok(()),
        "target authority is checked in retained cred->user_ns, not init_user_ns fallback");
}

#[test]
fn setpriority_rlimit_bypass_requires_initial_user_namespace_capability() {
    install_test_hooks();
    let caller = normal(0x7fff_ff16, 1000);
    let target = normal(0x7fff_ff17, 1000);
    sched::hosted_test::set_nice(&target, 5);
    target.set_rlimit(sched::rlimit::rlim::NICE, (0, 0));
    assert!(target.replace_namespace(child_user(1000)).is_ok());
    caller.security.creds.cap_effective.store(0, Ordering::Release);

    assert_eq!(setpriority_check(&caller, &target, -5), Err(EACCES),
        "target-namespace authority does not bypass RLIMIT_NICE");
    privileged(&caller);
    assert_eq!(setpriority_check(&caller, &target, -5), Ok(()));
}

#[test]
fn same_task_is_safe_for_scheduler_policy_hook() {
    install_test_hooks();
    let task = normal(0x7fff_ff4a, 1000);
    task.set_state(sched::TaskState::Sleeping);
    assert_eq!(setattr(&task, &task, &SchedAttr::default()), 0);
}

#[test]
fn setpriority_lsm_runs_after_owner_and_rlimit_checks() {
    install_test_hooks();
    let caller = normal(0x7fff_ff14, 1000);
    let target = normal(NICE_LSM_TID, 2000);

    assert_eq!(setpriority_check(&caller, &target, 10), Err(EPERM));

    target.security.creds.ruid.store(1000, Ordering::Release);
    target.security.creds.euid.store(1000, Ordering::Release);
    sched::hosted_test::set_nice(&target, 5);
    target.set_rlimit(sched::rlimit::rlim::NICE, (0, 0));
    assert_eq!(setpriority_check(&caller, &target, -5), Err(EACCES));

    assert_eq!(setpriority_check(&caller, &target, 10), Err(EBUSY));
}

#[test]
fn setpriority_lsm_capability_module_rejects_a_target_with_added_permitted_caps() {
    install_test_hooks();
    let caller = normal(0x7fff_ff15, 1000);
    let target = normal(NICE_CAP_TID, 1000);
    caller.security.creds.cap_permitted.store(0, Ordering::Release);
    target.security.creds.cap_permitted.store(1, Ordering::Release);
    assert_eq!(setpriority_check(&caller, &target, 10), Err(EPERM));
}

#[test]
fn scheduler_lsm_runs_after_sugov_rejection_and_before_uclamp_validation() {
    install_test_hooks();
    let caller = normal(0x7fff_ff20, 0);
    privileged(&caller);
    let target = normal(SCHED_LSM_TID, 0);

    assert_eq!(setscheduler(&caller, &target, SCHED_FIFO as i32, 200, 0), EINVAL);

    let sugov = SchedAttr { flags: crate::sched_attr::FLAG_SUGOV, ..Default::default() };
    assert_eq!(setattr(&caller, &target, &sugov), EINVAL);

    let invalid_uclamp = SchedAttr {
        flags: crate::sched_attr::FLAG_UTIL_CLAMP_MAX,
        util_max: crate::sched_attr::CAPACITY_SCALE + 1,
        ..Default::default()
    };
    assert_eq!(setattr(&caller, &target, &invalid_uclamp), EACCES,
        "the task LSM answer precedes util-clamp validation");
    assert_eq!(task_policy(&target), SCHED_NORMAL);
}

#[test]
fn scheduler_lsm_capability_module_rejects_a_target_with_added_permitted_caps() {
    install_test_hooks();
    let caller = normal(0x7fff_ff30, 1000);
    let target = normal(SCHED_CAP_TID, 1000);
    caller.security.creds.cap_permitted.store(0, Ordering::Release);
    target.security.creds.cap_permitted.store(1, Ordering::Release);

    assert_eq!(setattr(&caller, &target, &SchedAttr::default()), EPERM);
    assert_eq!(task_policy(&target), SCHED_NORMAL);
}
