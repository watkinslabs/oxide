// Hosted proof of the signal-generation contract in the parent module. These
// encode behaviour verified against the reference kernel's `prepare_signal` /
// `__send_signal_locked` / `force_sig_info_to_task`; the tests ARE the
// provenance (CLAUDE.md "Semantic verification").

use super::*;

const SIGSEGV: u32 = Signum::Sigsegv as u32;
const SIGCHLD: u32 = Signum::Sigchld as u32;
const SIGTERM: u32 = Signum::Sigterm as u32;
const SIGCONT: u32 = Signum::Sigcont as u32;
const SIGSTOP: u32 = Signum::Sigstop as u32;
const SIGTSTP: u32 = Signum::Sigtstp as u32;
const SIGKILL: u32 = Signum::Sigkill as u32;
const SIGRTMIN: u32 = signum::RT_SIGNAL_MIN;
const HANDLER: u64 = 0x4000;

#[test]
fn a_noinfo_send_synthesises_si_user_with_the_senders_identity() {
    let i = build_info(SIGTERM, SigSource::User { pid: 42, uid: 1000 });
    assert_eq!((i.signo, i.code, i.pid, i.uid), (SIGTERM, SI_USER, 42, 1000));
    assert!(i.fault.is_none() && i.sys.is_none());
}

#[test]
fn a_priv_send_synthesises_si_kernel_with_no_identity() {
    let i = build_info(SIGTERM, SigSource::Kernel);
    assert_eq!((i.code, i.pid, i.uid), (SI_KERNEL, 0, 0));
}

#[test]
fn an_explicit_record_keeps_its_fields_but_takes_the_sent_signo() {
    let rec = fault_info(SIGSEGV, hal::siginfo::code::SEGV_ACCERR, 0xdead_b000, 0);
    let i = build_info(SIGSEGV, SigSource::Info(rec));
    assert_eq!(i.code, hal::siginfo::code::SEGV_ACCERR);
    assert_eq!(i.fault.unwrap().addr, 0xdead_b000);
    // si_signo always matches the signal actually sent, never the record's.
    let mismatched = SigInfo { signo: 99, ..rec };
    assert_eq!(build_info(SIGSEGV, SigSource::Info(mismatched)).signo, SIGSEGV);
}

#[test]
fn only_user_originated_sends_face_the_permission_check() {
    assert!(SigSource::User { pid: 1, uid: 0 }.from_user());
    assert!(!SigSource::Kernel.from_user());
    // SI_QUEUE (a negative, app-supplied code) is user-originated.
    let q = SigInfo { signo: SIGTERM, code: signum::SI_QUEUE, pid: 1, uid: 0, value: 0,
                      sys: None, fault: None };
    assert!(SigSource::Info(q).from_user());
    // SI_KERNEL is not.
    let k = SigInfo { code: SI_KERNEL, ..q };
    assert!(!SigSource::Info(k).from_user());
    assert!(SigSource::Info(k).force(), "a kernel-origin record forces past SIG_IGN");
}

#[test]
fn an_ignored_disposition_drops_the_send() {
    assert!(sig_ignored(SIG_IGN, SIGTERM, 0, false, false));
    // SIGCHLD's DEFAULT action is ignore, so SIG_DFL drops it too.
    assert!(sig_ignored(SIG_DFL, SIGCHLD, 0, false, false));
    // SIGTERM's default action is terminate — never dropped.
    assert!(!sig_ignored(SIG_DFL, SIGTERM, 0, false, false));
    // A handler is never a drop.
    assert!(!sig_ignored(HANDLER, SIGCHLD, 0, false, false));
}

#[test]
fn a_blocked_signal_is_never_dropped_even_with_sig_ign_installed() {
    // Blocked wins over ignored: the record must stay pending so sigwait /
    // signalfd can still collect it and a later unblock can deliver it.
    let blocked = Signum::Sigterm.bit();
    assert!(!sig_ignored(SIG_IGN, SIGTERM, blocked, false, false));
}

#[test]
fn sigkill_and_sigstop_are_never_dropped() {
    assert!(!sig_ignored(SIG_IGN, SIGKILL, u64::MAX, false, false));
    assert!(!sig_ignored(SIG_IGN, SIGSTOP, u64::MAX, false, false));
}

#[test]
fn a_traced_task_drops_nothing_but_sigkill() {
    assert!(!sig_ignored(SIG_IGN, SIGTERM, 0, false, true));
    assert!(!sig_ignored(SIG_IGN, SIGCHLD, 0, false, true));
    // SIGKILL is exempt from the ptrace exemption, but is unblockable anyway.
    assert!(!sig_ignored(SIG_IGN, SIGKILL, 0, false, true));
}

#[test]
fn a_kernel_forced_send_overrides_sig_ign() {
    assert!(!sig_ignored(SIG_IGN, SIGTERM, 0, true, false));
    assert!(!sig_ignored(SIG_DFL, SIGCHLD, 0, true, false));
}

#[test]
fn sigcont_and_the_stop_signals_flush_each_other() {
    assert_eq!(prepare_flush(SIGCONT), STOP_MASK);
    assert_eq!(prepare_flush(SIGSTOP), Signum::Sigcont.bit());
    assert_eq!(prepare_flush(SIGTSTP), Signum::Sigcont.bit());
    assert_eq!(prepare_flush(SIGTERM), 0);
    assert_eq!(STOP_MASK.count_ones(), 4);
}

#[test]
fn a_forced_fault_signal_keeps_an_installed_handler_when_unblocked() {
    let d = force_decision(HANDLER, SIGSEGV, 0, ForceMode::Current);
    assert_eq!(d, ForceOutcome { reset_to_dfl: false, unblock: false });
}

#[test]
fn a_forced_fault_signal_that_is_blocked_is_unblocked_and_reset_to_default() {
    // The whole point of force_sig: a process that blocked SIGSEGV must still
    // die on a wild pointer rather than loop faulting forever.
    let blocked = Signum::Sigsegv.bit();
    let d = force_decision(HANDLER, SIGSEGV, blocked, ForceMode::Current);
    assert_eq!(d, ForceOutcome { reset_to_dfl: true, unblock: true });
}

#[test]
fn a_forced_fault_signal_that_is_ignored_is_reset_to_default() {
    let d = force_decision(SIG_IGN, SIGSEGV, 0, ForceMode::Current);
    assert_eq!(d, ForceOutcome { reset_to_dfl: true, unblock: false });
}

#[test]
fn handler_exit_and_handler_sig_dfl_always_reset() {
    for m in [ForceMode::SigDfl, ForceMode::Exit] {
        let d = force_decision(HANDLER, SIGSEGV, 0, m);
        assert!(d.reset_to_dfl, "{:?} must not let a handler intercept", m);
        assert!(!d.unblock, "nothing was blocked, so nothing is unblocked");
    }
}

#[test]
fn a_standard_signal_already_pending_collapses_but_a_realtime_one_queues() {
    let pending = Signum::Sigterm.bit();
    assert!(legacy_queue(SIGTERM, pending));
    assert!(!legacy_queue(SIGTERM, 0));
    let rt_pending = 1u64 << (SIGRTMIN - 1);
    assert!(!legacy_queue(SIGRTMIN, rt_pending), "real-time signals queue, never collapse");
}

#[test]
fn only_a_user_queued_realtime_signal_can_fail_with_eagain() {
    // kill(2) must never report EAGAIN, so a standard signal always overrides
    // the pending-signal ceiling.
    assert!(override_rlimit(SIGTERM, &SigSource::User { pid: 1, uid: 0 }));
    assert!(override_rlimit(SIGTERM, &SigSource::Kernel));
    assert!(!override_rlimit(SIGRTMIN, &SigSource::User { pid: 1, uid: 0 }));

    assert!(!overflow_is_eagain(SIGTERM, &SigSource::User { pid: 1, uid: 0 }));
    assert!(!overflow_is_eagain(SIGRTMIN, &SigSource::User { pid: 1, uid: 0 }),
            "kill(2) of an RT signal loses the record rather than failing");
    let queued = SigInfo { signo: SIGRTMIN, code: signum::SI_QUEUE, pid: 1, uid: 0, value: 0,
                           sys: None, fault: None };
    assert!(overflow_is_eagain(SIGRTMIN, &SigSource::Info(queued)),
            "sigqueue(3) of an RT signal reports EAGAIN on overflow");
}

#[test]
fn a_fault_record_carries_the_faulting_address_not_a_sender_identity() {
    let i = fault_info(SIGSEGV, hal::siginfo::code::SEGV_MAPERR, 0x7fff_0000_1000, 12);
    assert_eq!(i.code, hal::siginfo::code::SEGV_MAPERR);
    assert_eq!((i.pid, i.uid, i.value), (0, 0, 0));
    let f = i.fault.expect("a fault record must select the _sigfault arm");
    assert_eq!((f.addr, f.addr_lsb), (0x7fff_0000_1000, 12));
}
