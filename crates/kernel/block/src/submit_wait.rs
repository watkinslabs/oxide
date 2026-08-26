//! Submit one request and wait for it, the way the block layer's synchronous
//! helper does: the completion callback signals a condition the submitter is
//! parked on, and the wait has no failure exit of its own.
//!
//! The alternative already in the tree is the driver turnstile, which holds a
//! device-wide turn for the whole transfer and so admits one request at a
//! time. This path hands the request to the device's own queue and sleeps, so
//! several can be outstanding together.

extern crate alloc;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};
use crate::{BlockDevice, BlockRequest, KResult};

/// The submitter's side of one outstanding request: what the completion has to
/// hand back, and the flag it publishes when it has.
struct IoWait {
    done:   AtomicBool,
    slot:   sync::Spinlock<Option<(BlockRequest, KResult<()>)>, sync::TaskList>,
    #[cfg(target_os = "oxide-kernel")]
    wait:   sched::live::WaitList,
}

impl IoWait {
    fn new() -> Self {
        Self {
            done: AtomicBool::new(false),
            slot: sync::Spinlock::new(None),
            #[cfg(target_os = "oxide-kernel")]
            wait: sched::live::WaitList::new(),
        }
    }

    /// Publish the result, then the flag. The submitter loads the flag with
    /// `Acquire`, so a task that observes it set also observes the slot.
    fn complete(&self, request: BlockRequest, result: KResult<()>) {
        *self.slot.lock() = Some((request, result));
        self.done.store(true, Ordering::Release);
        #[cfg(target_os = "oxide-kernel")]
        self.wait.wake_all();
    }
}

/// Submit `request` to `dev` and wait for its completion.
///
/// The wait does not time out. A synchronous transfer either completes or the
/// machine has a bug worth finding, and a wait that gives up reports an I/O
/// error the device never raised -- which a filesystem turns into a failed
/// read and the fault path into SIGBUS.
/// # C: one device round-trip
/// # Ctx: process
/// # Sleeps: yes
pub fn submit_and_wait<D: BlockDevice + ?Sized>(dev: &D, request: BlockRequest)
    -> (BlockRequest, KResult<()>)
{
    let state = Arc::new(IoWait::new());
    let signal = state.clone();
    dev.submit(request, alloc::boxed::Box::new(move |request, result| {
        signal.complete(request, result);
    }));
    wait_done(&state);
    // The completion has published the slot and the flag; nothing else takes
    // this slot, so a request that completed always leaves one here.
    let taken = state.slot.lock().take();
    taken.expect("completed request leaves its result")
}

/// Park until the completion lands, reporting a transfer that is taking an
/// unreasonable time exactly once rather than abandoning it.
/// # C: one device round-trip
#[cfg(target_os = "oxide-kernel")]
fn wait_done(state: &Arc<IoWait>) {
    const REWAIT_NS: u64 = 5_000_000_000;
    const WARN_NS:   u64 = 10_000_000_000;
    let started = sched::deadline::clock::now_ns();
    let mut warned = false;
    while !state.done.load(Ordering::Acquire) {
        // Root is mounted before there is anything to schedule, so a caller
        // here can be the idle task itself, and parking it is a scheduler
        // fault rather than a wait. Anything that cannot sleep polls the
        // completion instead: it is published by the block softirq, which
        // still runs on the interrupt return this spin permits.
        if !can_sleep() {
            core::hint::spin_loop();
            continue;
        }
        let deadline = sched::deadline::clock::now_ns().saturating_add(REWAIT_NS);
        // SAFETY: process context holding no lock; the predicate only loads an
        // atomic the completion publishes after filling the result slot.
        let _ = unsafe {
            sched::live::wait_event_uninterruptible_until(
                &state.wait, deadline, sched::deadline::clock::now_ns,
                || state.done.load(Ordering::Acquire))
        };
        if warned || state.done.load(Ordering::Acquire) { continue; }
        if sched::deadline::clock::now_ns().saturating_sub(started) < WARN_NS { continue; }
        warned = true;
        // Name it once and keep waiting. The counters say whether the device
        // stopped notifying us or the completion softirq stopped running.
        klog::write_raw(b"[BLK-IOWAIT] outstanding past 10s irq=");
        klog::write_dec_u64(crate::IRQ_RAISES.load(Ordering::Relaxed));
        klog::write_raw(b" bh_runs=");
        klog::write_dec_u64(crate::BH_RUNS.load(Ordering::Relaxed));
        klog::write_raw(b" bh_reaped=");
        klog::write_dec_u64(crate::BH_REAPED.load(Ordering::Relaxed));
        klog::write_raw(b" pending=");
        klog::write_dec_u64(crate::RING_PENDING.load(Ordering::Relaxed));
        klog::write_raw(b" deferred=");
        klog::write_dec_u64(crate::RING_DEFERRED.load(Ordering::Relaxed));
        klog::write_raw(b" free=");
        klog::write_dec_u64(crate::RING_FREE.load(Ordering::Relaxed));
        klog::write_raw(b"\n");
    }
}

/// Whether this context may block. A caller with no current task is early
/// boot or an interrupt, and one holding a preemption count is atomic;
/// neither can be taken off-CPU.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
fn can_sleep() -> bool { sched::current().is_some() && !sched::preempt::in_atomic() }

/// Hosted: completions run inline on the submitting thread.
/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
fn wait_done(state: &Arc<IoWait>) {
    while !state.done.load(Ordering::Acquire) { core::hint::spin_loop(); }
}
