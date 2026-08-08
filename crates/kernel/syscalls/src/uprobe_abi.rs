// Contract for the two kernel-injected uprobe syscall slots (335, 336) when
// no uprobe trampoline is mapped in the caller's address space.
//
// Module manifest:
// - this file: the `NoTrampoline` outcome each slot owes, plus the rule that
//   a forced fatal signal is QUEUED rather than applied by an open-coded exit.
// - `uprobe_abi/tests.rs`: hosted table tests for both slots.
//
// Deliberately NOT kernel-cfg'd: both slot files are
// `#![cfg(target_os = "oxide-kernel")]`, so a `#[cfg(test)]` block inside
// either compiles out silently and proves nothing. The decision lives here and
// the slots stay shims that apply it (`docs/53`).
//
// Neither slot is a userspace API. The kernel injects the call from a uprobe
// trampoline it mapped itself, with the probed frame staged on the user stack.
// A caller reaching either one from ordinary code therefore did not come from
// a trampoline, and the two slots answer that case DIFFERENTLY: `uretprobe`
// forces SIGILL, `uprobe` reports ENXIO. libbpf's feature probe depends on
// exactly the ENXIO value, so the two must not be collapsed.

use syscall::errno::Errno;

/// `si_code` a forced fatal signal with no faulting address carries. Kernel
/// origin, no `si_addr` — the siginfo layout that reaches a tracer is the
/// kill-shaped arm, not a fault record.
pub const FORCED_SI_CODE: i32 = hal::siginfo::source::SI_KERNEL;

/// Return value the slot leaves in the syscall register after forcing a fatal
/// signal. Userspace never observes it — the signal is delivered on the way
/// out — but a tracer that suppresses the signal does.
pub const FORCED_RETURN: i64 = -1;

/// What a slot owes a caller that did not arrive through a trampoline.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NoTrampoline {
    /// Queue `sig` against the calling thread with the disposition reset to
    /// SIG_DFL and the signal unblocked, then return `rv`. Delivery — the
    /// default-action triage, the core dump a core-defaulting signal owes, and
    /// the tracer's signal-delivery stop — belongs to the ordinary
    /// return-to-user path, NOT to the slot.
    ///
    /// The slot must not terminate the thread group itself. An open-coded
    /// group exit reports `WCOREDUMP` to the parent (SIGILL defaults to Core)
    /// while writing no core, and skips the tracer stop entirely.
    ForceSignal {
        /// Signal to force.
        sig: sched::signum::Signum,
        /// `si_code` the queued record carries.
        code: i32,
        /// Value left in the syscall return register.
        rv: i64,
    },
    /// Report an ordinary errno; no signal, no side effect.
    Errno(i32),
}

/// Slot 335 with no uprobe trampoline mapped.
///
/// The reference validates a trampoline exists, that the user PC equals the
/// single address allowed to make this call, and that the staged frame copies
/// in; every failure forces SIGILL. A kernel that maps no trampoline can only
/// ever take the first of those, so this is the whole reachable body.
///
/// Forcing — rather than sending — is what makes it terminal: the disposition
/// is reset and the signal unblocked, so a caller cannot catch, ignore or
/// block its way past a call it had no business making.
/// # C: O(1)
pub const fn uretprobe_no_trampoline() -> NoTrampoline {
    NoTrampoline::ForceSignal {
        sig: sched::signum::Signum::Sigill,
        code: FORCED_SI_CODE,
        rv: FORCED_RETURN,
    }
}

/// Slot 336 with the caller's PC outside any uprobe trampoline.
///
/// Unlike 335 this is a plain error rather than a forced signal, and the value
/// is load-bearing: userspace feature probes for this syscall accept ENXIO and
/// nothing else, so reporting ENOSYS or EINVAL here would advertise the wrong
/// capability.
/// # C: O(1)
pub const fn uprobe_not_in_trampoline() -> NoTrampoline {
    NoTrampoline::Errno(Errno::Enxio.as_i32())
}

#[cfg(test)]
#[path = "uprobe_abi/tests.rs"]
mod tests;
