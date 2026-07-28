// The install permission ladder. Before B1478 there was NO gate at all: any
// unprivileged task could install a filter without `PR_SET_NO_NEW_PRIVS`,
// which is precisely how an unprivileged process shapes the behaviour of a
// privileged child it later execs.

use crate::seccomp::flags::*;
use crate::seccomp::install::*;
use crate::seccomp::uapi::*;
use syscall::errno::Errno;

fn ctx() -> InstallCtx {
    InstallCtx { flags: 0, len: 1, no_new_privs: false, cap_sys_admin: false,
                 cur_mode: SECCOMP_MODE_DISABLED }
}

#[test]
fn an_unprivileged_task_without_no_new_privs_is_denied() {
    assert_eq!(pre_verify_gate(&ctx()), Err(Errno::Eacces));
}

#[test]
fn no_new_privs_alone_is_enough() {
    assert_eq!(pre_verify_gate(&InstallCtx { no_new_privs: true, ..ctx() }), Ok(()));
}

#[test]
fn cap_sys_admin_alone_is_enough() {
    assert_eq!(pre_verify_gate(&InstallCtx { cap_sys_admin: true, ..ctx() }), Ok(()));
}

// `seccomp_prepare_filter` checks the length BEFORE the privilege test, so a
// zero-length program reports EINVAL even to a task that would also have
// failed EACCES.
#[test]
fn the_length_check_precedes_the_privilege_check() {
    assert_eq!(pre_verify_gate(&InstallCtx { len: 0, ..ctx() }), Err(Errno::Einval));
    assert_eq!(pre_verify_gate(&InstallCtx { len: BPF_MAXINSNS + 1, ..ctx() }), Err(Errno::Einval));
    assert_eq!(pre_verify_gate(&InstallCtx { len: BPF_MAXINSNS, no_new_privs: true, ..ctx() }), Ok(()));
}

// And the flag rules precede BOTH — they run before the `sock_fprog` is even
// copied in.
#[test]
fn the_flag_check_precedes_the_length_and_privilege_checks() {
    let bad = InstallCtx { flags: 1 << 40, len: 0, ..ctx() };
    assert_eq!(pre_verify_gate(&bad), Err(Errno::Einval));
    let combo = InstallCtx {
        flags: SECCOMP_FILTER_FLAG_TSYNC | SECCOMP_FILTER_FLAG_NEW_LISTENER, ..ctx() };
    assert_eq!(pre_verify_gate(&combo), Err(Errno::Einval));
}

// `seccomp_may_assign_mode`: "Once current->seccomp.mode is non-zero, it may
// not be changed."
#[test]
fn a_strict_task_cannot_become_a_filter_task() {
    assert!(!may_assign_mode(SECCOMP_MODE_STRICT, SECCOMP_MODE_FILTER));
    assert!(!may_assign_mode(SECCOMP_MODE_FILTER, SECCOMP_MODE_STRICT));
    assert_eq!(post_verify_gate(&InstallCtx { cur_mode: SECCOMP_MODE_STRICT, ..ctx() }),
               Err(Errno::Einval));
}

#[test]
fn re_asserting_the_same_mode_is_allowed() {
    assert!(may_assign_mode(SECCOMP_MODE_DISABLED, SECCOMP_MODE_FILTER));
    assert!(may_assign_mode(SECCOMP_MODE_FILTER, SECCOMP_MODE_FILTER));
    assert!(may_assign_mode(SECCOMP_MODE_STRICT, SECCOMP_MODE_STRICT));
}

// A task already latched MODE_DEAD by a RET_KILL is not allowed to re-arm.
#[test]
fn a_dead_task_cannot_assign_any_mode() {
    assert!(!may_assign_mode(SECCOMP_MODE_DEAD, SECCOMP_MODE_FILTER));
    assert!(!may_assign_mode(SECCOMP_MODE_DEAD, SECCOMP_MODE_STRICT));
}

// The notification transport is not built. NEW_LISTENER must therefore FAIL
// the install rather than hand back a filter the caller believes is
// supervised while its RET_USER_NOTIF silently ENOSYS-es.
#[test]
fn new_listener_fails_the_install_rather_than_faking_supervision() {
    assert_eq!(listener_unsupported(SECCOMP_FILTER_FLAG_NEW_LISTENER), Some(Errno::Enosys));
    assert_eq!(listener_unsupported(SECCOMP_FILTER_FLAG_TSYNC), None);
    assert_eq!(listener_unsupported(0), None);
}

#[test]
fn get_action_avail_knows_exactly_the_eight_defined_actions() {
    for a in [SECCOMP_RET_KILL_PROCESS, SECCOMP_RET_KILL_THREAD, SECCOMP_RET_TRAP,
              SECCOMP_RET_ERRNO, SECCOMP_RET_USER_NOTIF, SECCOMP_RET_TRACE,
              SECCOMP_RET_LOG, SECCOMP_RET_ALLOW] {
        assert_eq!(action_avail(a), Ok(()), "action {:#x}", a);
    }
    // The DATA bits are NOT masked off by `seccomp_get_action_avail`: it
    // compares the whole word, so an action carrying data is unavailable.
    for a in [SECCOMP_RET_ERRNO | 1, 0x0001_0000, 0xdead_0000] {
        assert_eq!(action_avail(a), Err(Errno::Eopnotsupp), "action {:#x}", a);
    }
}

// `MAX_INSNS_PER_PATH`: without a TOTAL-chain cap a task installs
// 4096-instruction filters until every syscall walks megabytes of cBPF.
#[test]
fn the_whole_chain_has_a_total_instruction_cap() {
    assert_eq!(MAX_INSNS_PER_PATH, 32768);
    assert!(!total_insns_exceeded(0, BPF_MAXINSNS));
    assert!(!total_insns_exceeded(MAX_INSNS_PER_PATH - 1, 1));
    assert!(total_insns_exceeded(MAX_INSNS_PER_PATH, 1));
    assert!(total_insns_exceeded(usize::MAX, 1), "the sum must not wrap");
    // Eight maximal filters plus their per-filter penalty overflow the cap.
    let eight = 8 * (BPF_MAXINSNS + FILTER_PENALTY_INSNS);
    assert!(total_insns_exceeded(eight, BPF_MAXINSNS));
}
