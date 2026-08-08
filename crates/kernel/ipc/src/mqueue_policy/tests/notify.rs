use crate::mqueue_policy::notify::{
    notify_action, notify_check, NotifyAction, NotifyKind, NSIG, SIGEV_NONE, SIGEV_SIGNAL,
    SIGEV_THREAD,
};
use syscall::errno::Errno;

#[test]
fn the_three_linux_notify_modes_are_all_accepted() {
    // The pre-audit implementation rejected SIGEV_NONE with EINVAL; a real
    // registration accepts it, holding the queue's single notification slot
    // even though delivery sends nothing.
    assert_eq!(notify_check(SIGEV_NONE, 0), Ok(NotifyKind::None));
    assert_eq!(notify_check(SIGEV_SIGNAL, 10), Ok(NotifyKind::Signal(10)));
    assert_eq!(notify_check(SIGEV_THREAD, 3), Ok(NotifyKind::Thread));
}

#[test]
fn an_unknown_notify_mode_is_einval() {
    for n in [-1, 3, 4, 1000] { assert_eq!(notify_check(n, 10), Err(Errno::Einval), "notify={n}"); }
}

#[test]
fn valid_signal_bounds_only_constrain_sigev_signal() {
    assert_eq!(notify_check(SIGEV_SIGNAL, NSIG), Ok(NotifyKind::Signal(NSIG as u32)));
    assert_eq!(notify_check(SIGEV_SIGNAL, NSIG + 1), Err(Errno::Einval));
    assert_eq!(notify_check(SIGEV_SIGNAL, -1), Err(Errno::Einval));
    // SIGEV_THREAD's `sigev_signo` is a SOCKET FD, so it is not signal-checked.
    assert_eq!(notify_check(SIGEV_THREAD, 4096), Ok(NotifyKind::Thread));
    assert_eq!(notify_check(SIGEV_NONE, -99), Ok(NotifyKind::None));
}

#[test]
fn signal_zero_is_accepted_and_delivers_nothing() {
    // A SIGEV_SIGNAL registration with `sigev_signo == 0` is accepted at
    // registration time, and delivery skips the send.
    assert_eq!(notify_check(SIGEV_SIGNAL, 0), Ok(NotifyKind::Signal(0)));
}

#[test]
fn a_second_registration_is_ebusy_even_for_the_owner() {
    assert_eq!(notify_action(true, None, 7), Ok(NotifyAction::Register));
    assert_eq!(notify_action(true, Some(9), 7), Err(Errno::Ebusy));
    assert_eq!(notify_action(true, Some(7), 7), Err(Errno::Ebusy));
}

#[test]
fn a_null_notification_only_clears_the_callers_own_registration() {
    // A foreign deregister is a silent success that must
    // NOT steal the slot — otherwise any process could disarm another's.
    assert_eq!(notify_action(false, Some(7), 7), Ok(NotifyAction::Deregister));
    assert_eq!(notify_action(false, Some(9), 7), Ok(NotifyAction::NoOp));
    assert_eq!(notify_action(false, None, 7), Ok(NotifyAction::NoOp));
}
