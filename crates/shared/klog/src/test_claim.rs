// Ownership of the process-global console for hosted tests.
//
// A hosted test binary is ONE process and libtest runs its bodies on many
// threads, but the console this crate implements is global by contract: one
// byte sink, one clock thunk, one cpu thunk, one caller thunk, one
// `LINE_START` flag, one per-cpu line-assembly slot array, one initcall
// enable bit, one panic-on-warn bit. Two tests that both emit therefore see
// each other's bytes, and one that installs a thunk changes how another one's
// lines are assembled.
//
// A private `Mutex` cannot fix that on its own: a mutex excludes holders and
// can say nothing about a non-holder, so the next test written forgets to take
// it and the suite flakes months later under an unrelated change. Two measured
// instances of exactly that:
//
//   * a test that flipped the initcall enable bit without holding anything
//     turned it off between a peer's entry line and its return line, so the
//     peer saw `calling  stuck_step` with no completion;
//   * a test that emitted three level-macro lines without holding anything
//     consumed the shared `LINE_START` token, so a peer's next assembled line
//     carried no timestamp at all.
//
// So ownership is ASSERTED, not documented. `claim_console` takes the lock and
// returns the console to its boot state; `assert_claimed` runs at the two entry
// points every emit crosses (`emit_bytes_at`, `write_primary_raw`) and fails
// the forgetful test on its first byte rather than failing a random sibling one
// run in thirteen.
//
// Worker threads: a test that spawns emitters to prove they cannot splice each
// other still holds the claim on its parent thread. Each worker announces
// itself with `worker()`, which is valid only while the claim is held.

use core::cell::Cell;
use std::sync::{Mutex, MutexGuard};

static CONSOLE: Mutex<()> = Mutex::new(());

std::thread_local! {
    /// Depth of console ownership on THIS thread. Raised by `claim_console`
    /// and by a worker announcement, lowered on drop; nesting is real (a sink
    /// that itself logs re-enters the emit path on the claiming thread).
    static DEPTH: Cell<u32> = const { Cell::new(0) };
}

/// Live claim on the console. Held for the body of a test.
pub(crate) struct ConsoleClaim(#[allow(dead_code)] MutexGuard<'static, ()>);

impl Drop for ConsoleClaim {
    fn drop(&mut self) {
        reset();
        DEPTH.with(|d| d.set(d.get() - 1));
    }
}

/// A worker thread emitting under its parent's claim.
pub(crate) struct WorkerClaim;

impl Drop for WorkerClaim {
    fn drop(&mut self) { DEPTH.with(|d| d.set(d.get() - 1)); }
}

/// Take the console claim and return the console to its boot state: no sink,
/// no thunks, tracing off, no dump hook, a fresh line. # C: O(NR_SLOTS)
pub(crate) fn claim_console() -> ConsoleClaim {
    let g = CONSOLE.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    DEPTH.with(|d| d.set(d.get() + 1));
    ConsoleClaim(g)
}

/// Announce that this thread emits under a claim its parent holds. Valid only
/// while some thread holds the claim. # C: O(1)
pub(crate) fn worker() -> WorkerClaim {
    assert!(CONSOLE.try_lock().is_err(),
        "a worker announced console ownership while no test held the claim");
    DEPTH.with(|d| d.set(d.get() + 1));
    WorkerClaim
}

/// Every emit path crosses this. # C: O(1)
#[track_caller]
pub(crate) fn assert_claimed() {
    assert!(DEPTH.with(|d| d.get()) > 0,
        "this test emits to the process-global console without holding \
         klog::test_claim::claim_console(); it will corrupt whichever sibling \
         test runs beside it");
}

/// Console state a test can observe or change, put back the way a fresh
/// process finds it. Runs on claim AND on release, so neither a test that
/// forgets to undo its own thunk nor one that inherits a peer's leftovers can
/// see anything but the boot state.
fn reset() {
    crate::clear_byte_sink();
    // Publish and drop whatever a peer left half-assembled in a per-cpu slot,
    // so the next claim starts from an empty line buffer on every slot.
    crate::cont::flush();
    crate::clear_clock_fn();
    crate::clear_cpu_fn();
    crate::clear_caller_fn();
    crate::clear_kmsg_dump_hook();
    crate::initcall::set_enabled(false);
    crate::syslog::set_console_level(crate::syslog::CONSOLE_LOGLEVEL_DEBUG);
    crate::syslog::set_dmesg_restrict(false);
    crate::oops::set_panic_on_warn(false);
    crate::reset_line_start();
}
