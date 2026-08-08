// One worker thread's loop.
//
// Take a request, borrow its submitter's context, run it, give the context
// back. Between requests, fire whatever the clock has made due and then sleep
// until either new work arrives or the next armed deadline — a worker is the
// only thing that can notice a deadline, so it must never sleep past one.

use core::sync::atomic::Ordering;

use super::pool::{acct, WQ};

/// The monotonic clock every deadline in the pool is stated on. # C: O(1)
pub fn now_ns() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}

/// Whether this worker has anything at all to do right now. # C: O(1)
fn has_work(class: usize) -> bool { !WQ.acct[class].queue.lock().is_empty() }

/// One worker thread. `arg` is the work class it serves.
/// # C: unbounded — the thread runs for the life of the system
extern "C" fn worker(arg: usize) -> ! {
    let class = if arg < acct::NR { arg } else { acct::BOUND };
    loop {
        // The clock first: a request whose deadline has passed must not wait
        // behind a queue of work that could take arbitrarily long.
        let (fired, _) = WQ.expired(now_ns());
        for req in fired { super::run::expire(&req); }

        if let Some(req) = WQ.take(class) {
            super::run::issue(&req);
            req.ring.iowq_release(class);
            // Draining a burst must stay preemptible.
            // SAFETY: running worker thread in process context, holding no lock; schedule re-enqueues this still-runnable task.
            unsafe { sched::live::schedule(); }
            continue;
        }

        let deadline = WQ.park_deadline(now_ns());
        // SAFETY: running worker thread on its own CPU in process context, holding no lock across the park; the matching schedule yields immediately per the WaitList contract.
        unsafe {
            WQ.acct[class].wait.park_with_deadline(deadline);
            if has_work(class) { WQ.acct[class].wait.cancel_current_park(); continue; }
            sched::live::schedule();
        }
    }
}

/// Start one worker thread for `class`, pinned to the registered processor
/// mask if one was registered. # C: O(1)
pub fn spawn(class: usize) -> Result<(), sched::live::SpawnError> {
    let tid = sched::live::next_tid();
    // SAFETY: called from process context after the runqueue is installed; entry is a 'static extern "C" fn and the argument is a work-class index.
    let task = unsafe { sched::live::spawn_kernel_thread(tid, "iou-wrk", worker, class) }?;
    let mask = super::pool::cpu_mask();
    if mask != 0 { task.cpus_allowed.store(mask, Ordering::Release); }
    drop(task);
    Ok(())
}
