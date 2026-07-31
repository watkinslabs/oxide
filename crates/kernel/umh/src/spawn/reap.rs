// Waiting for a helper to terminate.
//
// The worker thread that started the helper is its parent, so it reaps the
// helper the same way any parent does. Not reaping would leave a terminated
// helper queued forever, and a system that runs a helper per crash would
// accumulate them.

use syscall::errno::Errno;

/// Options for "wait for this one child to terminate": no stopped-state
/// reporting, no polling.
const WAIT_FOR_EXIT: u64 = 0;

/// Block until `vpid` terminates and return its `wait(2)`-encoded status.
/// `-ECHILD` if it is not (or no longer) our child.
/// # C: O(N_wakeups)
pub fn wait_for(vpid: u32) -> i32 {
    let Some(me) = sched::live::current() else { return -(Errno::Echild.as_i32()) };
    let tid = me.tid;
    let tgid = me.tgid.load(core::sync::atomic::Ordering::Acquire);
    let pgid = me.pgid();
    let pid = vpid as i32;
    loop {
        if let Some((_child, code)) = sched::live::reap_one(tid, tgid, pid, pgid, WAIT_FOR_EXIT) {
            return sched::exit::status::wait_status(code);
        }
        if !sched::live::registry::has_wait_children(tid, tgid, pid, pgid, WAIT_FOR_EXIT) {
            return -(Errno::Echild.as_i32());
        }
        // SAFETY: worker-thread process context with the runqueue installed and no lock held; park then schedule per the wait4 contract.
        unsafe { sched::live::park_for_wait4(); }
        // The child can terminate between the reap above and the park, which
        // would fire the parent wake against an empty waiter list. Re-check
        // before yielding rather than sleeping on a wake that already happened.
        if let Some((_child, code)) = sched::live::reap_one(tid, tgid, pid, pgid, WAIT_FOR_EXIT) {
            sched::live::unpark_self_from_wait4();
            return sched::exit::status::wait_status(code);
        }
        // SAFETY: worker-thread process context with the runqueue installed and no lock held.
        unsafe { sched::live::schedule(); }
    }
}
