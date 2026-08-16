// Test-only CPU identity and gate serialisation.
//
// Two process-global things make the `debug-preempt` tests interfere:
//
//   1. The held-lock trace is indexed by CPU, and with no CPU hook installed
//      every thread in the test binary is "CPU 0". The harness runs tests on
//      one thread each, so every sibling test's spinlock traffic lands in the
//      slot the trace tests are asserting about. Measured on `origin/main`:
//      2 of 5 runs of `cargo test -p sync --features debug-preempt --lib`
//      failed, always in `a_bh_section_is_visible_to_the_held_lock_trace`.
//   2. `OPS` and `CPU_HOOK` are installed and cleared by individual tests, so
//      one test's teardown uninstalls the gate under another's body.
//
// (1) is answered by giving each test THREAD its own CPU slot from a hook
// installed once and never removed — the trace then behaves as it does on a
// real machine, one stack per CPU. (2) is answered by `gate`.

use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, Once};

static SERIAL: Mutex<()> = Mutex::new(());
static NEXT: AtomicUsize = AtomicUsize::new(1);
static INSTALL: Once = Once::new();

std::thread_local! {
    static CPU: Cell<Option<usize>> = const { Cell::new(None) };
}

/// Slots at or above this are handed out only by [`pinned`], so a test that
/// names two CPUs can never draw one the lazy allocator also handed to a
/// sibling thread.
const PINNED_BASE: usize = crate::MAX_CPUS - 8;

/// The `n`th slot reserved for a test that pins its own CPU identities.
/// # C: O(1)
#[cfg(feature = "debug-preempt")]
pub(crate) fn pinned(n: usize) -> usize { PINNED_BASE + n % 8 }

/// This thread's CPU slot, assigned on first ask. Slot 0 is left to threads
/// that never ask, so a test that pins its own identity is never sharing with
/// the unclaimed crowd. # C: O(1)
pub(crate) fn cpu() -> usize {
    CPU.with(|c| match c.get() {
        Some(v) => v,
        None => {
            let v = 1 + NEXT.fetch_add(1, Ordering::Relaxed) % (PINNED_BASE - 1);
            c.set(Some(v));
            v
        }
    })
}

/// Pin this thread to `slot`, for a test that needs two named CPUs. # C: O(1)
#[cfg(feature = "debug-preempt")]
pub(crate) fn set_cpu(slot: usize) { CPU.with(|c| c.set(Some(slot))); }

/// Install the per-thread CPU hook once for the whole test binary. Never
/// uninstalled: a hook that comes and goes is the race it exists to remove.
/// # C: O(1)
#[cfg(feature = "debug-preempt")]
pub(crate) fn install_cpu_hook() {
    INSTALL.call_once(|| crate::preempt_gate::set_debug_cpu_hook(cpu));
}

/// Hold for the whole body of any test that installs the preempt gate.
/// A poisoned lock still hands the section over: a sibling that panicked while
/// holding it left the gate uninstalled, which is the state the next caller
/// installs over anyway. # C: O(1)
pub(crate) fn gate() -> MutexGuard<'static, ()> {
    #[cfg(feature = "debug-preempt")]
    install_cpu_hook();
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}
