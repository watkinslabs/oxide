// seccomp user notification: the supervisor protocol behind
// `SECCOMP_FILTER_FLAG_NEW_LISTENER` and `SECCOMP_RET_USER_NOTIF`.
//
// A filter installed with a listener hands every syscall its program answers
// `SECCOMP_RET_USER_NOTIF` to a supervising process, which decides the
// syscall's fate through the listener descriptor. This file is the NOTIFIED
// task's side: queue, sleep, perform any descriptor injection asked of it,
// and turn the reply into the syscall's outcome.
//
// Module manifest (`08§7`):
//   uapi     — ioctl numbers, response/addfd flags, wire codecs
//   state    — the queue and its transition rules (pure, hosted-tested)
//   listener — the listener object, the wait queue, the id registry
//   wait     — the sleeping half, with its hosted stand-in
//   fd       — the listener descriptor: anon inode, poll, last-close detach
//   ioctl    — the supervisor's commands
//   addfd    — descriptor injection, performed by the notified task
//
// The filter records the listener's ID, not the object: a filter is copied by
// value onto every `TSYNC`-reached thread and every forked child, and all of
// those copies must reach the same listener. `listener::lookup` is the single
// owner of that mapping, so a filter whose listener has been closed finds
// nothing and takes the no-listener answer — which is exactly what a closed
// listener means.

extern crate alloc;

use alloc::sync::Arc;

use crate::seccomp::insn::SeccompData;

pub mod uapi;
pub mod state;
pub mod listener;
pub mod wait;
pub mod fd;
pub mod ioctl;
pub mod addfd;

pub use fd::{install, is_listener_inode, uninstall};
pub use state::Outcome;

/// `SECCOMP_RET_USER_NOTIF` on a filter that owns a listener: hand the
/// syscall to the supervisor and wait for its answer.
///
/// A filter whose listener has been closed, or that never had one, takes the
/// ENOSYS-and-skip answer instead — a denial, never a pass, because a filter
/// that meant to have the call examined must not let it through unexamined.
/// # Ctx: process
/// # Sleeps: yes
/// # C: O(N_notifications) + wait
pub fn do_user_notification(listener_id: u64, data: &SeccompData) -> Outcome {
    let Some(l) = listener::lookup(listener_id) else { return no_listener() };
    let Some(tid) = current_tid() else { return no_listener() };
    let Some(id) = l.inner.lock().queue(tid, *data) else { return no_listener() };
    // A notification is now waiting to be picked up: the listener is readable.
    l.wake();

    loop {
        if let Some((val, error, flags)) = l.inner.lock().take_reply(id) {
            l.wake();
            return state::outcome(val, error, flags);
        }
        // A supervisor asked for one of its descriptors to be installed here.
        // Only this task can do that, so it happens before the next sleep.
        let pending = l.inner.lock().addfd_take(id);
        if let Some(a) = pending {
            let ret = addfd::perform(&a);
            l.inner.lock().addfd_complete(id, &a, ret);
            l.wake();
            continue;
        }
        let killable = l.inner.lock().sleep_killable(id);
        // SAFETY: syscall process context on the running task's own CPU; the listener lock is not held across the park.
        let woke = unsafe {
            wait::wait_until(&l.wq, killable, || l.inner.lock().actionable(id))
        };
        if woke == wait::Woke::Interrupted {
            // A supervisor may have picked the notification up in the same
            // instant: the wait then becomes killable and an ordinary signal
            // no longer ends it. Re-testing here is what stops a plain signal
            // from pulling the task out from under a supervisor already
            // acting on it.
            if !killable && l.inner.lock().sleep_killable(id) { continue; }
            let mut g = l.inner.lock();
            g.addfd_abandon(id);
            g.drop_notif(id);
            drop(g);
            l.wake();
            return Outcome::Skip(syscall::restart::restart_sys());
        }
    }
}

/// The answer a `SECCOMP_RET_USER_NOTIF` gets when no supervisor can see it.
/// # C: O(1)
fn no_listener() -> Outcome {
    Outcome::Skip(-(syscall::errno::Errno::Enosys.as_i32() as i64))
}

fn current_tid() -> Option<u32> { sched::current().map(|c| c.tid) }

/// Route a listener descriptor's ioctl. `None` when the descriptor is not a
/// listener, so a foreign inode reusing these command numbers is untouched.
/// # C: O(N_notifications)
pub fn handle_ioctl(file: &Arc<vfs::File>, cmd: u64, arg: u64) -> Option<i64> {
    let l = fd::listener_of_inode(file.inode())?;
    Some(ioctl::dispatch(&l, cmd as u32, arg))
}
