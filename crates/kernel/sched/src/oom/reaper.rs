//! The reaper kthread: the queue's only consumer.
//
// Policy lives in `reap.rs` and is proved hosted. This file is the loop that
// applies it — park until the earliest victim is due, walk its reapable
// mappings, retry, and mark the mm skippable when the reaping ends however it
// ends.
//
// Wake/park wiring follows the in-tree background-reclaim shape (`kswapd`):
// one waiter, woken on publication, with a deadline backstop so a wake that
// races the park costs a delay rather than a lost victim.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use alloc::vec::Vec;

use vmm::AddressSpace;

use super::reap::{self, ReapStep, REAP_DELAY_NS, REAP_RETRY_NS};
use crate::live::WaitList;

static WAIT: WaitList = WaitList::new();

/// Rouse the reaper after a victim has been published to the queue.
/// # C: O(1)
pub(super) fn wake_oom_reaper() { WAIT.wake_one(); }

/// One pass over a victim's mm. Returns whether the reaping is finished with
/// it — either its reapable mappings were torn down, or the mm has already
/// been written off by the victim's own exit.
///
/// A core dump in progress is the one thing that defers rather than proceeds:
/// an image of this address space is being written, and pulling the mappings
/// out from under it would produce a half-written dump of memory that no
/// longer exists.
/// # C: O(N_vmas + pages_reaped)
fn reap_once(mm: &Arc<AddressSpace>) -> bool {
    if mm.oom_skip() { return true; }
    if mm.coredumping() { return false; }
    let Some(zap) = reap::oom_zapper() else { return false; };
    let guard = mm.vmas_for_test();
    let ranges: Vec<(u64, u64)> = guard.iter()
        .filter(|vma| reap::reapable_vma(vma))
        .map(|vma| (vma.start.as_u64(), vma.end.as_u64().saturating_sub(vma.start.as_u64())))
        .filter(|(_, len)| *len != 0)
        .collect();
    // From the far end. The victim's own exit tears the same tables down from
    // the low end, and meeting it head-on is page-table lock contention for
    // nothing.
    for (start, len) in ranges.into_iter().rev() { zap(mm, start, len); }
    drop(guard);
    true
}

/// Reap one queued victim to a terminal answer.
///
/// Whichever answer it is, the mm ends up marked skippable. That mark is the
/// point: it is what lets a later exhaustion select somebody else instead of
/// waiting forever on a process that is never going to release anything.
/// # C: O(MAX_REAP_ATTEMPTS · N_vmas)
fn reap_victim(entry: reap::Queued) {
    let mut attempts: u32 = 0;
    loop {
        attempts = attempts.saturating_add(1);
        let reaped = reap_once(&entry.mm);
        match reap::after_attempt(attempts, reaped) {
            ReapStep::Retry => {
                let deadline = timekeeper::monotonic_ns().saturating_add(REAP_RETRY_NS);
                // SAFETY: the reaper is a schedulable kthread holding no
                // subsystem lock here — the vma read guard was dropped with
                // the pass that took it.
                unsafe { WAIT.park_with_deadline(deadline); crate::live::schedule(); }
            }
            step => {
                entry.mm.set_oom_skip();
                report(&entry.task, step);
                return;
            }
        }
    }
}

extern "C" fn oom_reaper(_arg: usize) -> ! {
    loop {
        let now = timekeeper::monotonic_ns();
        match reap::take_due(now) {
            Some(entry) => reap_victim(entry),
            // Nothing due: sleep to the moment the earliest victim becomes so.
            // The backstop covers a wake that raced this park — the cost is a
            // late reap, never a victim left on the queue.
            None => {
                let deadline = reap::next_due_ns().unwrap_or_else(|| now.saturating_add(REAP_DELAY_NS));
                // SAFETY: schedulable kthread, no subsystem lock held; the
                // queue lock was released by `next_due_ns` before this call.
                unsafe { WAIT.park_with_deadline(deadline); }
            }
        }
        // SAFETY: after a reap pass, or after publication to WAIT, this is a
        // runnable kthread with no subsystem lock held.
        unsafe { crate::live::schedule(); }
    }
}

/// Name a victim the reaping finished with. Console output is `cfg`-elidable
/// per `04§4.0`; the skippable mark itself is the observable outcome.
#[cfg(feature = "debug-sched")]
fn report(task: &Arc<crate::Task>, step: ReapStep) {
    klog::write_raw(match step {
        ReapStep::GaveUp => b"[OOM] unable to reap pid=" as &[u8],
        _ => b"[OOM] reaped pid=" as &[u8],
    });
    klog::write_dec_u64(u64::from(task.visible_pid()));
    klog::write_raw(b"\n");
}

#[cfg(not(feature = "debug-sched"))]
fn report(_task: &Arc<crate::Task>, _step: ReapStep) {}

/// Spawn the reaper after the runqueue exists. One worker: the queue is
/// machine-wide, exactly as the victim list it drains is.
/// # C: O(1)
pub fn spawn_oom_reaper() -> Result<(), crate::live::SpawnError> {
    let tid = crate::live::next_tid();
    // SAFETY: called from kernel init after runqueue installation; the entry is
    // static and takes no argument-owned memory.
    unsafe { crate::live::spawn_kernel_thread(tid, "oom_reaper", oom_reaper, 0) }.map(|_| ())
}
