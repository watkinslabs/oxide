// Device routing for controlling-terminal hangup / disassociation. ONE
// resolver shared by `vhangup(2)` (slot 153) and the `TIOCNOTTY` ioctl, so the
// two cannot disagree about what "the caller's controlling terminal" is.
//
// Kernel-gated because it reaches `console`, `devpts` and `sched::live`; every
// rule it applies is imported from `tty::hangup`, which is host-tested.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;

use tty::HangupKind;

/// The tty object a controlling-terminal inode names.
pub(crate) enum CttyTarget {
    /// The serial system console (`/dev/ttyS0`, `/dev/console` on a serial
    /// boot).
    Serial,
    /// A numbered video VT.
    Vt(u8),
    /// A pty slave (`/dev/pts/<n>`).
    Pts(Arc<devpts::LockedPair>),
}

/// Inode band devpts allocates its pty inodes from (`016_ioctl/tty_ioctl.rs`
/// applies the same split).
const PTS_INO_BAND: u64 = 0x6000_0000;
const PTS_INO_BAND_MASK: u64 = 0xFFFF_0000;
const PTS_INDEX_MASK: u64 = 0x7FFF;

/// Resolve a controlling-terminal inode to its tty object.
/// # C: O(1)
pub(crate) fn resolve(ino: u64) -> Option<CttyTarget> {
    if ino & PTS_INO_BAND_MASK == PTS_INO_BAND {
        return devpts::pair_for((ino & PTS_INDEX_MASK) as u32).map(CttyTarget::Pts);
    }
    if !console::is_console_tty_ino(ino) { return None; }
    Some(match console::route(ino) {
        console::TtyTarget::Serial => CttyTarget::Serial,
        console::TtyTarget::Vt(vt) => CttyTarget::Vt(vt),
    })
}

/// Whether the target is a pty slave. A session leader's exit hangs a REAL
/// terminal up but never a pty: the pty dies with its master, and revoking it
/// from the slave side tears down a line the master may still be draining.
/// # C: O(1)
pub(crate) fn is_pty(target: &CttyTarget) -> bool {
    matches!(target, CttyTarget::Pts(_))
}

/// `tty->ctrl.session` — the session this tty is the controlling terminal of,
/// or 0 when it is nobody's.
/// # C: O(1)
pub(crate) fn session(target: &CttyTarget) -> u32 {
    match target {
        CttyTarget::Serial => console::static_console::session(),
        CttyTarget::Vt(vt) => console::vt_tty::vt_tty(*vt).sid(),
        CttyTarget::Pts(pair) => pair.with_pair(|p| p.session_pid),
    }
}

/// `tty->ctrl.pgrp` — the foreground process group, or 0.
/// # C: O(1)
pub(crate) fn foreground_pgrp(target: &CttyTarget) -> u32 {
    match target {
        CttyTarget::Serial => console::static_console::foreground_pgid(),
        CttyTarget::Vt(vt) => console::vt_tty::vt_tty(*vt).fg_pgrp(),
        CttyTarget::Pts(pair) => pair.with_pair(|p| p.foreground_pgid),
    }
}

/// `__tty_hangup(tty, kind)`: revoke the line (reads → EOF, writes → EIO) and
/// clear `tty->ctrl.session` / `tty->ctrl.pgrp`. The SESSION walk is separate
/// (`tty::hangup::hangup_session`) because it needs the task list.
/// # C: O(W) waiters
pub(crate) fn hangup(target: &CttyTarget, kind: HangupKind) {
    match target {
        CttyTarget::Serial => console::static_console::hangup(kind),
        CttyTarget::Vt(vt) => console::vt_tty::hangup(*vt, kind),
        CttyTarget::Pts(pair) => pair.with_pair(|p| {
            // `pty_close` hangs the slave up through the same `tty_vhangup`
            // path (`drivers/tty/pty.c:77`); `master_hangup` is that state
            // change — EOF on slave read, EIO on slave write.
            p.master_hangup();
            p.session_pid = 0;
            p.foreground_pgid = 0;
        }),
    }
}

/// `disassociate_ctty`'s `tty->ctrl.session = NULL; tty->ctrl.pgrp = NULL`
/// WITHOUT revoking the line — TIOCNOTTY detaches the terminal from the
/// session, it does not hang it up.
/// # C: O(1)
pub(crate) fn clear_linkage(target: &CttyTarget) {
    match target {
        CttyTarget::Serial => console::static_console::notty(),
        CttyTarget::Vt(vt) => console::vt_tty::notty(*vt),
        CttyTarget::Pts(pair) => pair.with_pair(|p| {
            p.session_pid = 0;
            p.foreground_pgid = 0;
        }),
    }
}

/// `disassociate_ctty(1)` for a dying process, in the shape
/// `sched::live::set_disassociate_ctty_hook` installs. The group-dead test is
/// the hook's; a `pthread_exit` from a non-final thread never reaches here.
/// # Ctx: exit path, `task` running on this CPU.
/// # C: O(N_tasks)
pub fn disassociate_ctty_on_exit(task: &sched::Task) {
    disassociate_ctty(task, tty::hangup::DisassociateCause::Exit);
}

/// `disassociate_ctty(on_exit)` — drop `task`'s session's controlling
/// terminal. The ONE implementation behind both callers: the last thread of a
/// process exiting (`DisassociateCause::Exit`) and the `TIOCNOTTY` ioctl
/// (`DisassociateCause::Notty`).
///
/// Every rule comes from `tty::hangup::disassociate_ctty` (host-tested); this
/// fn only resolves the device, supplies the live facts, and performs the
/// actions the rule selected, in the order it lists them.
/// # Ctx: syscall / exit path, `task` running on this CPU.
/// # C: O(N_tasks)
pub(crate) fn disassociate_ctty(task: &sched::Task, cause: tty::hangup::DisassociateCause) {
    use tty::hangup::CttyFacts;
    let ctty_ino = task.ctty_ino();
    let target = ctty_ino.and_then(resolve);
    let facts = ctty_ino.map(|_| match &target {
        Some(t) => CttyFacts { is_pty: is_pty(t), fg_pgrp: foreground_pgrp(t) },
        // The terminal inode names no device we can reach any more. There is
        // nothing to revoke or signal, but the session still loses it — the
        // pty-shaped facts select exactly that (no vhangup, no foreground
        // group), so the clears below still run.
        None => CttyFacts { is_pty: true, fg_pgrp: 0 },
    });
    let saved_pgrp = task.thread_group.tty_old_pgrp();
    let act = tty::hangup::disassociate_ctty(
        cause, sched::session::is_session_leader(task), facts, saved_pgrp);

    if act.vhangup_session {
        if let (Some(ino), Some(t)) = (ctty_ino, target.as_ref()) {
            // The session walk runs BEFORE the tty state change: it reads
            // `tty->ctrl.session` and `tty->ctrl.pgrp`, which the hangup then
            // clears. `SessionExit` is what carries the foreground group's
            // SIGHUP, so the rule leaves `fg_pgrp` unset on this branch.
            let sid = session(t);
            let fg = foreground_pgrp(t);
            tty::hangup::hangup_session(ino, sid, fg);
            hangup(t, HangupKind::SessionExit);
        }
    }
    if let Some(f) = facts { tty::hangup::signal_pgrp(f.fg_pgrp, act.fg_pgrp); }
    tty::hangup::signal_pgrp(saved_pgrp, act.old_pgrp);
    if act.clear_linkage {
        if let Some(t) = target.as_ref() { clear_linkage(t); }
    }
    if act.clear_old_pgrp { task.thread_group.set_tty_old_pgrp(0); }
    if act.clear_session_ctty {
        if let Some(ino) = ctty_ino { tty::hangup::clear_session_ctty(ino, task.sid()); }
    }
    if act.clear_own_ctty { task.set_ctty(None); }
}
