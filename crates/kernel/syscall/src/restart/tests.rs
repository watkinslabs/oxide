// Hosted tests for the ERESTART* encodings and Linux's signal-delivery-time
// restart decision. Table values checked against linux-master
// `include/linux/errno.h`, `arch/x86/kernel/signal.c` `handle_signal` /
// `arch_do_signal_or_restart`, and `arch/arm64/kernel/signal.c` `do_signal`.

use super::*;

const EINTR: i64 = -(Errno::Eintr.as_i32() as i64);

#[test]
fn erestart_codes_match_linux_errno_h() {
    assert_eq!(ERESTARTSYS, 512);
    assert_eq!(ERESTARTNOINTR, 513);
    assert_eq!(ERESTARTNOHAND, 514);
    assert_eq!(ERESTART_RESTARTBLOCK, 516);
    assert_eq!(restart_sys(), -512);
    assert_eq!(restart_nointr(), -513);
    assert_eq!(restart_nohand(), -514);
    assert_eq!(restart_block(), -516);
}

#[test]
fn normalize_maps_every_restart_code_to_eintr() {
    assert_eq!(normalize_user_return(restart_sys()), EINTR);
    assert_eq!(normalize_user_return(restart_nointr()), EINTR);
    assert_eq!(normalize_user_return(restart_nohand()), EINTR);
    assert_eq!(normalize_user_return(restart_block()), EINTR);
    assert_eq!(normalize_user_return(-22), -22);
    assert_eq!(normalize_user_return(0), 0);
    // 515 (ERESTART_RESTARTBLOCK's neighbour) is not a restart code.
    assert_eq!(normalize_user_return(-515), -515);
}

#[test]
fn is_restart_code_only_claims_the_four_sentinels() {
    for rv in [-512i64, -513, -514, -516] { assert!(is_restart_code(rv)); }
    for rv in [-511i64, -515, -517, -4, 0, 512] { assert!(!is_restart_code(rv)); }
    assert!(is_restart_sys(-512));
    assert!(!is_restart_sys(-513));
}

#[test]
fn non_restart_return_is_never_touched() {
    for handler_ran in [false, true] {
        for sa_restart in [false, true] {
            assert_eq!(signal_restart_action(-4, handler_ran, sa_restart), RestartAction::None);
            assert_eq!(signal_restart_action(0, handler_ran, sa_restart), RestartAction::None);
            assert_eq!(signal_restart_action(1234, handler_ran, sa_restart), RestartAction::None);
        }
    }
}

#[test]
fn handler_path_matches_linux_handle_signal() {
    // ERESTARTSYS: restart only under SA_RESTART, else EINTR.
    assert_eq!(signal_restart_action(restart_sys(), true, true), RestartAction::RestartSame);
    assert_eq!(signal_restart_action(restart_sys(), true, false), RestartAction::Eintr);
    // ERESTARTNOINTR: unconditional restart, SA_RESTART irrelevant.
    assert_eq!(signal_restart_action(restart_nointr(), true, false), RestartAction::RestartSame);
    assert_eq!(signal_restart_action(restart_nointr(), true, true), RestartAction::RestartSame);
    // ERESTARTNOHAND + ERESTART_RESTARTBLOCK: always EINTR once a handler ran.
    for rv in [restart_nohand(), restart_block()] {
        assert_eq!(signal_restart_action(rv, true, true), RestartAction::Eintr);
        assert_eq!(signal_restart_action(rv, true, false), RestartAction::Eintr);
    }
}

#[test]
fn no_handler_path_matches_linux_arch_do_signal_or_restart() {
    // SA_RESTART is meaningless with no handler — every case restarts.
    for sa_restart in [false, true] {
        for rv in [restart_sys(), restart_nointr(), restart_nohand()] {
            assert_eq!(signal_restart_action(rv, false, sa_restart), RestartAction::RestartSame);
        }
        assert_eq!(signal_restart_action(restart_block(), false, sa_restart),
                   RestartAction::RestartBlockCall);
    }
}

#[test]
fn restart_block_never_restarts_the_same_call() {
    // The whole point of ERESTART_RESTARTBLOCK: re-entering the original
    // syscall would restart the FULL duration; only restart_syscall(2) can
    // resume against the stored absolute deadline.
    assert_ne!(signal_restart_action(restart_block(), false, false), RestartAction::RestartSame);
    assert_ne!(signal_restart_action(restart_block(), true, true), RestartAction::RestartSame);
}
