// Kernel-thread termination — Linux `kthread_exit` / `kthread_stop`.
//
// `kthread_stop` used to be a bare request with no join, and there was no way
// at all for a thread to END: every entry point is `-> !`, so a loop that saw
// `should_stop()` had nowhere to go but a spin. That blocks every design that
// needs a thread per object — a per-ring submission poller, a per-request
// worker — because such a thread must die with the object it serves.
//
// The reference lifecycle, kept exactly:
//   - the thread's body returns a value; the wrapper hands it to
//     `kthread_exit(result)`, which stores the result and then exits the task;
//   - `kthread_stop` sets the stop request, releases any park, wakes the
//     thread, WAITS for its exit to be published, and returns that result;
//   - the exit is published from the incoming task's post-switch tail, once
//     the dying thread is off its own stack — never by the dying thread
//     itself, whose stack the joiner would otherwise be free to free while it
//     is still executing on it;
//   - a kernel thread leaves no waitable zombie, because its parent ignores
//     child signals (`ParentSigchld::kernel_thread_parent`).

extern crate alloc;

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use crate::Task;
use crate::task::{WaitOutcome, WaitState};
use super::super::WaitList;

/// Joiners wait here; the post-switch tail wakes them once a thread's exit is
/// published. One list for every kernel thread: exits are rare and each joiner
/// re-tests its own thread's flag, exactly as a completion's waiters do.
static EXIT_WAIT: WaitList = WaitList::new();

/// Publish `task`'s exit to any joiner. Called from the post-switch tail on the
/// INCOMING task, so the dying thread is provably off its own stack and a
/// joiner that drops the last reference cannot free a stack still in use.
/// # C: O(N_joiners)
pub fn note_kthread_exited(task: &Task) {
    if !task.kernel_thread.load(Ordering::Acquire) { return; }
    task.kthread_exited.store(true, Ordering::Release);
    EXIT_WAIT.wake_all();
}

/// Has `task` finished exiting? # C: O(1)
pub fn has_exited(task: &Task) -> bool { task.kthread_exited.load(Ordering::Acquire) }

/// The value `task` passed to [`exit`]. Only meaningful once [`has_exited`].
/// # C: O(1)
pub fn result(task: &Task) -> i32 { task.kthread_result.load(Ordering::Acquire) }

/// Linux `kthread_exit`: end the running kernel thread, handing `result` to
/// whoever joins it. Does not return.
///
/// # SAFETY: caller is the running kernel thread on its own CPU, holds no lock
/// and owns no in-flight I/O — the same contract every `schedule()` site has.
/// A task that is not a kernel thread must not call this: user-task exit runs
/// the full exit path (address space, files, notification) that this skips.
/// # C: O(log N) final pick
/// # Ctx: kthread
/// # Sleeps: terminally
pub unsafe fn exit(result: i32) -> ! {
    if let Some(me) = super::super::schedule::current() {
        me.kthread_result.store(result, Ordering::Release);
        // Zombie takes the thread off the runnable set, so `schedule()`'s
        // re-enqueue gate declines to put it back and the pick below can never
        // select it again. The post-switch tail then retires it.
        super::super::schedule::mark_done(me);
    }
    loop {
        // SAFETY: per this fn's contract — running kthread, no lock held. The
        // task is Zombie, so nothing re-enqueues it and this never returns;
        // the loop exists only because `schedule` is not itself `-> !`.
        unsafe { super::super::schedule(); }
        core::hint::spin_loop();
    }
}

/// Linux `kthread_stop`: ask `task` to exit, wait until it has, and return the
/// value it passed to [`exit`].
///
/// # SAFETY: process or kernel-thread context on the caller's own CPU, holding
/// no lock the dying thread also takes; the caller must not be `task` itself.
/// # C: O(1) + the wait
/// # Ctx: process|kthread
/// # Sleeps: until the thread exits
pub unsafe fn stop_and_join(task: &Arc<Task>) -> i32 {
    super::stop(task);
    // The reference joins with an UNINTERRUPTIBLE completion wait: a
    // half-stopped kernel thread has no valid state to leave behind, so the
    // joiner must not abandon the wait. The loop re-enters on every non-Ready
    // exit, which is what turns the interruptible primitive into that wait.
    loop {
        // SAFETY: per this fn's contract — process context, runqueue
        // installed, and `EXIT_WAIT`'s only waker is the post-switch tail,
        // which takes no lock this caller can hold.
        let outcome = unsafe {
            crate::live::wait_event(&EXIT_WAIT, WaitState::Killable, 0, || 0,
                                    || has_exited(task))
        };
        if matches!(outcome, WaitOutcome::Ready) || has_exited(task) { break; }
    }
    result(task)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exit::notify::{exit_notify, ParentSigchld, SIG_DFL, SIG_IGN};
    use crate::signum::Signum;
    use crate::task::SchedClass;

    fn kthread(tid: u32) -> Arc<Task> {
        Arc::new(Task::new(tid, "kth", SchedClass::Normal { weight: 1024 }))
    }

    #[test]
    fn a_task_built_without_an_address_space_is_a_kernel_thread() {
        assert!(kthread(7101).kernel_thread.load(Ordering::Acquire));
    }

    #[test]
    fn an_exit_is_not_published_until_the_post_switch_tail_runs() {
        let t = kthread(7102);
        t.kthread_result.store(9, Ordering::Release);
        assert!(!has_exited(&t), "a joiner must not observe an exit the switch has not completed");
        note_kthread_exited(&t);
        assert!(has_exited(&t));
        assert_eq!(result(&t), 9, "the joiner reads the value the thread passed to exit");
    }

    #[test]
    fn a_user_task_never_publishes_a_kernel_thread_exit() {
        // The tail hook runs for every retiring task; only kernel threads own
        // this completion, so a user task must not appear to have joined.
        let t = kthread(7103);
        t.kernel_thread.store(false, Ordering::Release);
        note_kthread_exited(&t);
        assert!(!has_exited(&t));
    }

    #[test]
    fn a_kernel_threads_exit_auto_reaps_instead_of_parking_a_zombie() {
        // The reference's kernel-thread parent ignores child signals, so the
        // thread is released at exit and no `wait4` is owed one.
        let d = exit_notify(true, true, Some(Signum::Sigchld as u32),
                            ParentSigchld::kernel_thread_parent());
        assert!(d.autoreap, "a kernel thread must not leave a zombie nothing can collect");
        assert_eq!(d.signal, None, "an ignored SIGCHLD is not posted");
    }

    #[test]
    fn a_parentless_user_task_still_parks_a_zombie() {
        // Positive control for the row above: the auto-reap comes from the
        // kernel-thread parent's disposition, not from having no parent.
        let d = exit_notify(true, true, Some(Signum::Sigchld as u32),
                            ParentSigchld { handler: SIG_DFL, flags: 0 });
        assert!(!d.autoreap);
        assert_eq!(d.signal, Some(Signum::Sigchld as u32));
        assert_eq!(ParentSigchld::kernel_thread_parent().handler, SIG_IGN);
    }
}
