//! `kflushd` and the reclaim wiring, on a machine that has a scheduler
//! (`17§4.3` step 5, `17§4.4`).
//!
//! The thread owns no policy: it parks, wakes, and calls the ungated
//! [`super::super::writeback::flush_pass`]. What it writes back and when is
//! decided by that function, which a hosted test drives directly.

extern crate alloc;

use core::sync::atomic::{AtomicBool, Ordering};

use crate::pagecache::global;
use crate::pagecache::writeback::flush_pass;

static FLUSH_WAIT: sched::live::WaitList = sched::live::WaitList::new();
/// A wake that arrived while the thread was running, so it does not park
/// through work that was queued a moment too early.
static PENDING: AtomicBool = AtomicBool::new(false);
static STARTED: AtomicBool = AtomicBool::new(false);

fn now_ns() -> u64 { timekeeper::monotonic_ns() }

/// Ask the flusher to run. Called whenever the machine crosses its background
/// dirty threshold. # C: O(waiters)
pub fn wake_flusher() {
    PENDING.store(true, Ordering::Release);
    FLUSH_WAIT.wake_one();
}

/// Start `kflushd` and publish the clock dirty ages are measured against.
/// Idempotent: a second call is a no-op rather than a second flusher.
/// # C: O(1)
pub fn spawn_daemons() -> Result<(), sched::live::SpawnError> {
    if STARTED.swap(true, Ordering::AcqRel) { return Ok(()); }
    global::install_clock(now_ns);
    let tid = sched::live::next_tid();
    // SAFETY: called from the boot path once the runqueue is installed, with
    // the allocator and per-arch HAL state up; the entry never returns and
    // takes no argument.
    unsafe { sched::live::spawn_kernel_thread(tid, "kflushd", kflushd, 0) }.map(|_| ())
}

extern "C" fn kflushd(_arg: usize) -> ! {
    loop {
        park();
        flush_pass(now_ns());
    }
}

/// Sleep until something dirties past the threshold, or until the periodic
/// interval expires so age-based writeback still happens on an idle machine.
fn park() {
    if PENDING.swap(false, Ordering::AcqRel) { return; }
    let deadline = now_ns().saturating_add(global::WRITEBACK_INTERVAL_NS);
    // SAFETY: process context, no cache or mapping lock held; the predicate
    // re-reads the pending flag that `wake_flusher` sets before it wakes.
    let _ = unsafe {
        sched::live::wait_event_uninterruptible_until(&FLUSH_WAIT, deadline, now_ns,
            || PENDING.load(Ordering::Acquire))
    };
    PENDING.store(false, Ordering::Release);
}
