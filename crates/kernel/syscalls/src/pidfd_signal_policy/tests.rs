use super::*;

const EINVAL: i64 = -(Errno::Einval.as_i32() as i64);

#[test]
fn an_unknown_flag_bit_is_einval() {
    assert_eq!(validate_flags(0), Ok(()));
    assert_eq!(validate_flags(PIDFD_SIGNAL_THREAD), Ok(()));
    assert_eq!(validate_flags(1 << 3), Err(EINVAL));
    assert_eq!(validate_flags(u32::MAX), Err(EINVAL));
}

#[test]
fn two_scope_flags_at_once_are_einval() {
    assert_eq!(validate_flags(PIDFD_SIGNAL_THREAD | PIDFD_SIGNAL_THREAD_GROUP), Err(EINVAL));
    assert_eq!(validate_flags(PIDFD_SIGNAL_THREAD | PIDFD_SIGNAL_PROCESS_GROUP), Err(EINVAL));
    assert_eq!(validate_flags(PIDFD_SEND_SIGNAL_FLAGS), Err(EINVAL));
}

#[test]
fn the_self_pidfd_magic_values_need_no_fd_lookup() {
    assert_eq!(classify_target(PIDFD_SELF_THREAD), Target::SelfTask(Scope::Thread));
    assert_eq!(classify_target(PIDFD_SELF_THREAD_GROUP), Target::SelfTask(Scope::ThreadGroup));
    assert_eq!(classify_target(3), Target::Fd(3));
    // A negative fd that is NOT one of the two magic values is an ordinary
    // (bad) fd, not a self-reference.
    assert_eq!(classify_target(-1), Target::Fd(-1));
    assert_eq!(classify_target(-9999), Target::Fd(-9999));
}

#[test]
fn an_explicit_scope_flag_overrides_the_pidfds_own_kind() {
    assert_eq!(scope_for(PIDFD_SIGNAL_THREAD, Scope::ThreadGroup), Scope::Thread);
    assert_eq!(scope_for(PIDFD_SIGNAL_THREAD_GROUP, Scope::Thread), Scope::ThreadGroup);
    assert_eq!(scope_for(PIDFD_SIGNAL_PROCESS_GROUP, Scope::Thread), Scope::ProcessGroup);
}

#[test]
fn with_no_flag_the_pidfds_own_kind_decides_the_scope() {
    // A PIDFD_THREAD (O_EXCL) pidfd is thread-scoped; every other is process.
    assert_eq!(scope_for(0, Scope::Thread), Scope::Thread);
    assert_eq!(scope_for(0, Scope::ThreadGroup), Scope::ThreadGroup);
}

#[test]
fn a_kernel_origin_si_code_may_only_be_sent_to_yourself() {
    // SI_USER (0) and SI_KERNEL (0x80) are both >= 0.
    for code in [sched::signum::SI_USER, sched::signum::SI_KERNEL, sched::signum::SI_TKILL] {
        assert!(siginfo_forgery_rejected(code, false, Scope::ThreadGroup),
                "code {code} at another task must be EPERM");
        assert!(!siginfo_forgery_rejected(code, true, Scope::ThreadGroup),
                "code {code} at yourself is allowed");
    }
}

#[test]
fn an_app_supplied_negative_si_code_is_always_allowed() {
    // SI_QUEUE is what `sigqueue(3)` stamps; forging it is harmless.
    assert!(!siginfo_forgery_rejected(sched::signum::SI_QUEUE, false, Scope::ThreadGroup));
    assert!(!siginfo_forgery_rejected(sched::signum::SI_MESGQ, false, Scope::Thread));
}

#[test]
fn a_process_group_send_is_never_treated_as_targeting_yourself() {
    // Linux's `type > PIDTYPE_TGID` clause: even when the pidfd names the
    // caller, widening to the process group makes the forgery check apply.
    assert!(siginfo_forgery_rejected(sched::signum::SI_USER, true, Scope::ProcessGroup));
    assert!(!siginfo_forgery_rejected(sched::signum::SI_USER, true, Scope::Thread));
}
