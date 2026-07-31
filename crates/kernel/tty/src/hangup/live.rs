// The live half of the hangup rules: walk the tasks whose session owns the
// tty, drop the terminal from each of them, and SIGHUP+SIGCONT the session
// leaders.
//
// Lives in `tty` rather than in the syscall slot because the rules are shared
// by every hangup source (vhangup(2), TIOCVHANGUP, carrier loss, session-leader
// exit) and must not drift between them; the slot supplies the tty identity it
// resolved and performs the tty-side state change.

use core::sync::atomic::Ordering;

use super::decide::session_member_action;
use super::disassociate::PgrpSignal;

/// Run the session walk for the tty whose controlling session is `tty_sid`,
/// whose device inode is `tty_ino`, and whose foreground process group is
/// `tty_pgrp` (0 when unset).
///
/// `tty_sid == 0` means the tty is nobody's controlling terminal, so there is
/// no session to walk.
///
/// Every session leader records `tty_pgrp` as its saved foreground group: the
/// terminal is about to stop being anybody's, and a leader that later exits
/// with no terminal left owes that group its SIGHUP+SIGCONT.
///
/// Returns the number of tasks that lost this tty as their controlling
/// terminal, which is the count of terminal references released.
/// # Ctx: syscall path, current task on this CPU; no tty/driver lock held.
/// # C: O(N_tasks)
pub fn hangup_session(tty_ino: vfs::Ino, tty_sid: u32, tty_pgrp: u32) -> usize {
    if tty_sid == 0 { return 0; }
    let mut refs = 0;
    for tid in sched::live::registry::live_tids() {
        let Some(task) = sched::live::registry::lookup(tid) else { continue };
        if task.sid() != tty_sid { continue; }
        let owns = task.ctty_ino() == Some(tty_ino);
        let leader = sched::session::is_session_leader(&task);
        let action = session_member_action(owns, leader);
        if action.clear_ctty {
            // The task loses its controlling terminal.
            task.set_ctty(None);
            refs += 1;
        }
        // Linux `__group_send_sig_info(SIGHUP/SIGCONT, SEND_SIG_PRIV, p)`:
        // kernel-generated and PROCESS-directed, so a session leader that
        // blocked SIGHUP in its main thread still loses the terminal, and the
        // SIGCONT arm runs `prepare_signal`'s stop-flush + group resume rather
        // than merely setting a bit on one thread.
        if leader && tty_pgrp != 0 { task.thread_group.set_tty_old_pgrp(tty_pgrp); }
        if action.sighup {
            sched::live::send_sig_priv_group(&task, sched::Signum::Sighup as u32);
        }
        if action.sigcont {
            // SIGCONT accompanies the SIGHUP so a stopped leader resumes and
            // can act on it.
            sched::live::send_sig_priv_group(&task, sched::Signum::Sigcont as u32);
        }
    }
    refs
}

/// Every task in `sid` loses `tty_ino` as its controlling terminal, with no
/// signals. This is the `disassociate_ctty` / TIOCNOTTY half — detaching a
/// terminal from a session is not a hangup and must not revoke or signal
/// anything.
/// # Ctx: syscall path, current task on this CPU.
/// # C: O(N_tasks)
pub fn clear_session_ctty(tty_ino: vfs::Ino, sid: u32) -> usize {
    if sid == 0 { return 0; }
    let mut cleared = 0;
    for tid in sched::live::registry::live_tids() {
        let Some(task) = sched::live::registry::lookup(tid) else { continue };
        if task.sid() != sid { continue; }
        if task.ctty_ino() != Some(tty_ino) { continue; }
        task.set_ctty(None);
        cleared += 1;
    }
    cleared
}

/// Post a [`PgrpSignal`] to every member of `pgrp` and wake it, so a member
/// already parked in an interruptible sleep reaches its signal-dispatch tail
/// instead of sitting on the pending bit.
/// # Ctx: syscall / exit path, current task on this CPU.
/// # C: O(pgrp size)
pub fn signal_pgrp(pgrp: u32, signals: PgrpSignal) {
    if pgrp == 0 || !signals.hup() { return; }
    let mut bits = sched::Signum::Sighup.bit();
    if signals.cont() { bits |= sched::Signum::Sigcont.bit(); }
    for task in sched::live::registry::tasks_in_pgrp(pgrp) {
        task.sigpending.fetch_or(bits, Ordering::Release);
        sched::live::signal_wake_up(&task);
    }
}
