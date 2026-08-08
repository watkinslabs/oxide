use super::*;

/// The whole point of the 335 arm: the slot QUEUES a forced signal and returns,
/// leaving the default action, the core dump and the tracer's signal-delivery
/// stop to the ordinary return-to-user path.
///
/// This slot used to call the group-exit helper directly. SIGILL defaults to
/// Core, so the exit status it latched set the core-dumped bit while no core
/// was ever written, and a tracer never saw the signal at all. Encoding the
/// outcome as `ForceSignal` rather than a terminate is what pins that.
#[test]
fn uretprobe_forces_a_signal_instead_of_exiting_the_group() {
    match uretprobe_no_trampoline() {
        NoTrampoline::ForceSignal { sig, code, rv } => {
            assert_eq!(sig, sched::signum::Signum::Sigill,
                "the reference forces SIGILL for a call that did not come from a trampoline");
            assert_eq!(code, hal::siginfo::source::SI_KERNEL,
                "a forced signal with no faulting address is kernel-origin");
            assert_eq!(rv, -1, "the reference returns -1 after forcing the signal");
        }
        other => panic!("335 must force a signal through the normal delivery path, got {other:?}"),
    }
}

/// SIGILL's default action is Core, which is why the slot must not latch the
/// exit status itself: the status carries a core-dumped bit that only the
/// delivery path can honestly set.
#[test]
fn the_forced_signal_is_one_whose_default_action_dumps_core() {
    let NoTrampoline::ForceSignal { sig, .. } = uretprobe_no_trampoline() else {
        panic!("335 forces a signal");
    };
    assert_eq!(sched::signum::default_action(sig.as_u8() as u32), sched::signum::DefaultAction::Core,
        "SIGILL dumps core by default, so an open-coded exit here reports a core that never existed");
}

/// A forced fatal signal reaches a tracer as a kill-shaped record, not a fault
/// record: there is no faulting address to report.
#[test]
fn forced_si_code_selects_the_kill_siginfo_layout() {
    assert_eq!(hal::siginfo::layout(sched::signum::Signum::Sigill as u32, FORCED_SI_CODE),
               hal::siginfo::Layout::Kill);
}

/// 336 is an ordinary error, never a signal — the two injected slots are not
/// interchangeable.
#[test]
fn uprobe_reports_enxio_and_forces_nothing() {
    assert_eq!(uprobe_not_in_trampoline(), NoTrampoline::Errno(Errno::Enxio.as_i32()));
}

/// Userspace feature probes accept ENXIO and nothing else, so the near-miss
/// errnos must stay wrong.
#[test]
fn uprobe_errno_is_not_one_of_the_plausible_near_misses() {
    let NoTrampoline::Errno(e) = uprobe_not_in_trampoline() else { panic!("336 is an errno") };
    for wrong in [Errno::Enosys.as_i32(), Errno::Einval.as_i32(), Errno::Eperm.as_i32(),
                  Errno::Eopnotsupp.as_i32()] {
        assert_ne!(e, wrong, "a feature probe reading errno {wrong} would misdetect this syscall");
    }
}

/// The two slots answer a non-trampoline caller differently. Collapsing them
/// onto one outcome is the regression this pins.
#[test]
fn the_two_injected_slots_do_not_share_an_outcome() {
    assert_ne!(uretprobe_no_trampoline(), uprobe_not_in_trampoline());
}
