// Linux `syscall_trace_enter`'s ORDER, as a decision the hosted tests can run.
//
// UNGATED on purpose. The order of the entry phases is itself the contract —
// getting it backwards is invisible to any test that only checks the phases
// individually — so the sequencing lives here, in a module `cargo test`
// reaches, and `dispatch/core.rs` only supplies the effects.
//
// The order is: syscall user dispatch, then the ptrace entry stop, then
// seccomp, then the call. seccomp runs AFTER ptrace specifically so it catches
// a tracer's changes: a debugger that rewrites the syscall number or arguments
// at a `PTRACE_SYSCALL` entry stop must have the REWRITTEN call filtered, not
// the original one. Running seccomp first lets a tracer substitute a call the
// filter would have refused.

/// What the entry work decided about the call.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum EntryOutcome {
    /// Run this syscall number — possibly not the one userspace asked for,
    /// since a tracer may have rewritten it at the entry stop.
    Run(u64),
    /// Do not run the syscall. This value goes to userspace, and the call
    /// still takes the normal exit path on the way there.
    Skip(u64),
}

/// A tracer that sets the syscall number NEGATIVE at the entry stop is asking
/// for the call to be cancelled. It is the documented way to make a
/// `PTRACE_SYSCALL` stop suppress a syscall entirely.
/// # C: O(1)
pub const fn tracer_cancelled(nr: u64) -> bool { (nr as i64) < 0 }

/// The entry sequence.
///
/// `aborted` is the ptrace entry stop's answer — `fatal_signal_pending`, i.e.
/// the tracee is dying and must not run the call. `nr_after_stop` is the
/// syscall number RE-READ from the entry frame once the stop returned, so a
/// tracer's rewrite is what everything downstream sees.
///
/// `seccomp` is invoked with that same post-stop number, which is the whole
/// point of the ordering: taking it as a closure rather than a precomputed
/// verdict is what makes the "seccomp sees the tracer's rewrite" property
/// testable instead of merely intended.
/// # C: O(1) plus the filter's own cost
pub fn entry_work<F>(aborted: bool, nr_after_stop: u64, cancelled_rv: u64, seccomp: F)
    -> EntryOutcome
where F: FnOnce(u64) -> Option<u64>
{
    // `if (ret) return -1L;` — a dying tracee never reaches the filter or the
    // call. Checked before the cancel test so a fatal signal wins over
    // whatever number happens to be in the frame.
    if aborted { return EntryOutcome::Skip(cancelled_rv); }
    if tracer_cancelled(nr_after_stop) { return EntryOutcome::Skip(cancelled_rv); }
    match seccomp(nr_after_stop) {
        Some(rv) => EntryOutcome::Skip(rv),
        None     => EntryOutcome::Run(nr_after_stop),
    }
}

#[cfg(test)]
#[path = "entry_order/tests.rs"] mod tests;
