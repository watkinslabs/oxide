// Unresolved user fault -> Windows exception, for the NT personality.
//
// A POSIX thread that faults gets a signal; a Windows thread gets an
// EXCEPTION_RECORD delivered to its user exception dispatcher, and its
// __try/__except probes depend on that being the FIRST thing that happens —
// a signal handler in between resets the disposition and the thread dies at
// the re-fault instead of running its handler.
//
// The decision lives here, at the one funnel every unresolved user fault
// already passes through, so no second fault-reporting path exists. What it
// decides is only WHERE the fault is reported; the classification it reports
// comes from `sched::nt_exception::fault`, and the delivery from the
// return-to-user pass that owns the live trap frame.

use sched::nt_exception::fault::Raised;

/// Publish one classified hardware exception against the faulting thread, or
/// answer `false` so the caller reports the POSIX signal instead.
///
/// `false` for a thread with no NT personality, for a condition no Windows
/// exception describes, and for a thread that is ALREADY holding an
/// exception — a fault taken while dispatching one is not queued behind it,
/// because the dispatcher would then never see either.
/// # C: O(1)
pub(super) fn publish(raised: Option<Raised>) -> bool {
    let Some(raised) = raised else { return false; };
    let Some(current) = sched::live::current() else { return false; };
    if !current.is_nt_personality() { return false; }
    current.nt_exception.publish(sched::nt_exception::Pending::from_hardware(raised.record())).is_ok()
}
