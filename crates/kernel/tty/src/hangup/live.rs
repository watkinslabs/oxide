// The live half of `tty_signal_session_leader` (`drivers/tty/tty_jobctrl.c:196-238`):
// walk the tasks whose session owns the tty, drop the terminal from each of
// them, and SIGHUP+SIGCONT the session leaders.
//
// Lives in `tty` rather than in the syscall slot because the rule is shared by
// every hangup source (vhangup(2), TIOCVHANGUP, carrier loss, session-leader
// exit) and must not drift between them; the slot supplies the tty identity it
// resolved and performs the tty-side state change.

use core::sync::atomic::Ordering;

use super::decide::session_member_action;

/// Run the session walk for the tty whose controlling session is `tty_sid` and
/// whose device inode is `tty_ino`.
///
/// `tty_sid == 0` means the tty is nobody's controlling terminal, so there is
/// no session to walk — Linux guards the whole loop with
/// `if (tty->ctrl.session)`.
///
/// Returns the number of tasks that lost this tty as their controlling
/// terminal (Linux's `refs`, which it uses to drop the matching tty krefs).
/// # Ctx: syscall path, current task on this CPU; no tty/driver lock held.
/// # C: O(N_tasks)
pub fn hangup_session(tty_ino: vfs::Ino, tty_sid: u32) -> usize {
    if tty_sid == 0 { return 0; }
    let mut refs = 0;
    for tid in sched::live::registry::live_tids() {
        let Some(task) = sched::live::registry::lookup(tid) else { continue };
        if task.sid() != tty_sid { continue; }
        // SAFETY: `ctty` is single-mutator per `13§5` — only the owning task on its own CPU writes it, and a hangup runs in syscall context on one CPU.
        let owns = unsafe { (*task.ctty.get()).as_ref().map(|i| i.ino()) } == Some(tty_ino);
        // `p->signal->leader`: the session leader is the thread group whose
        // leader's pid IS the session id.
        let leader = task.tgid.load(Ordering::Acquire) == tty_sid;
        let action = session_member_action(owns, leader);
        if action.clear_ctty {
            // SAFETY: same single-mutator slot as the read above; the hangup is the revoke Linux performs with `p->signal->tty = NULL`, and no other CPU writes this task's ctty.
            unsafe { *task.ctty.get() = None; }
            refs += 1;
        }
        if action.sighup {
            task.sigpending.fetch_or(sched::Signum::Sighup.bit(), Ordering::Release);
        }
        if action.sigcont {
            // SIGCONT accompanies the SIGHUP so a stopped leader resumes and
            // can act on it (`tty_jobctrl.c:218-219`).
            task.sigpending.fetch_or(sched::Signum::Sigcont.bit(), Ordering::Release);
        }
        if action.sighup || action.sigcont { sched::live::signal_wake_up(&task); }
    }
    refs
}

/// Linux `session_clear_tty` (`drivers/tty/tty_jobctrl.c:175-182`): every task
/// in `sid` loses `tty_ino` as its controlling terminal, with no signals. This
/// is the `disassociate_ctty` / TIOCNOTTY half — detaching a terminal from a
/// session is not a hangup and must not revoke or signal anything.
/// # Ctx: syscall path, current task on this CPU.
/// # C: O(N_tasks)
pub fn clear_session_ctty(tty_ino: vfs::Ino, sid: u32) -> usize {
    if sid == 0 { return 0; }
    let mut cleared = 0;
    for tid in sched::live::registry::live_tids() {
        let Some(task) = sched::live::registry::lookup(tid) else { continue };
        if task.sid() != sid { continue; }
        // SAFETY: `ctty` is single-mutator per `13§5` — only the owning task on its own CPU writes it, and this runs in syscall context on one CPU.
        let owns = unsafe { (*task.ctty.get()).as_ref().map(|i| i.ino()) } == Some(tty_ino);
        if !owns { continue; }
        // SAFETY: same single-mutator slot; Linux performs the identical clear in `proc_clear_tty` for each session member.
        unsafe { *task.ctty.get() = None; }
        cleared += 1;
    }
    cleared
}
