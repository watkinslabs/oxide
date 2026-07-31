// Live resolution of a console tty inode: `binding → target`, plus the
// open-time controlling-terminal acquisition. Kernel-gated — the foreground VT
// and the calling task come from `tty::live` / `sched::live`. The DECISION of
// whether an inode is a console tty at all lives in `crate::identity`, which is
// host-tested.

use alloc::sync::Arc;

use vfs::{Inode, InodeRef, OpenFlags};

use crate::identity::{binding_of, TtyBinding, TtyTarget};
use crate::serial;
use crate::vt_tty;

/// The backing tty `inode` speaks for right now, or `None` when it is not a
/// console tty. Linux's `tty_ioctl` is reachable only through `tty_fops`, so a
/// non-tty description must decline rather than resolve to a fabricated VT.
/// # C: O(1)
pub fn route(inode: &Inode) -> Option<TtyTarget> {
    Some(match binding_of(inode)? {
        TtyBinding::Serial => TtyTarget::Serial,
        TtyBinding::ForegroundVt => TtyTarget::Vt(foreground_vt()),
        TtyBinding::Vt(n) => TtyTarget::Vt(n),
        // `/dev/console` follows the preferred console — the same resolution
        // its read/write/poll already use, so its ioctls cannot disagree with
        // its I/O about which line it is.
        TtyBinding::PreferredConsole => match cmdline::preferred_console() {
            cmdline::ConsoleKind::Serial => TtyTarget::Serial,
            cmdline::ConsoleKind::Vt(_) => TtyTarget::Vt(foreground_vt()),
        },
    })
}

/// The current foreground video VT (1-based). `/dev/console` + the keyboard
/// follow this. # C: O(1)
pub fn foreground_vt() -> u8 {
    tty::live::foreground().max(1)
}

/// Linux `tty_open` controlling-terminal acquisition (`tty_open` →
/// `__proc_set_tty`, POSIX §11.1.3). Called from the open(2) path after a
/// console/serial/VT tty char-device inode has been resolved.
///
/// When the caller is a session leader with NO controlling terminal, the open
/// flags do NOT carry `O_NOCTTY`, and the tty has no owning session, make this
/// tty the session's controlling terminal: record the inode on the calling
/// task (`task.ctty`) so `/dev/tty` resolves to it, claim the tty for the
/// leader's session (`tty->session`), and seed the tty's foreground process
/// group with the leader's pgrp (without which a job-control shell trips
/// SIGTTIN on its first read). No-op when O_NOCTTY is set, the inode is not a
/// console tty, the caller is not a session leader, the caller already owns a
/// ctty, or the tty already belongs to a session (a plain open never steals —
/// that needs TIOCSCTTY).
/// # C: O(1)
pub fn acquire_ctty_on_open(inode: &InodeRef, flags: u32) {
    use core::sync::atomic::Ordering;

    let Some(tgt) = route(inode) else { return; };
    let o_noctty = flags & OpenFlags::O_NOCTTY.bits() != 0;
    let cur = match sched::live::current() {
        Some(c) => c,
        None => return,
    };
    let vpid = cur.vtgid.load(Ordering::Acquire);
    let my_pid = if vpid != 0 { vpid } else { cur.tid };
    let sid = cur.sid();
    let is_leader = sid != 0 && sid == my_pid;
    let has_ctty = cur.ctty_ino().is_some();
    let tty_sid = match tgt {
        TtyTarget::Serial => serial::session(),
        TtyTarget::Vt(vt) => vt_tty::vt_tty(vt).sid(),
    };
    // Every inode this resolver owns is an ordinary terminal line as far as
    // Linux's `noctty` term goes. The pty halves are classified by
    // `devpts::acquire_ctty_on_open`, which owns those inodes.
    let kind = tty::ctty::TtyKind::Terminal;
    if !tty::ctty::should_acquire_ctty(
        tty::ctty::kind_can_be_ctty(kind), o_noctty, is_leader, has_ctty, tty_sid != 0)
    {
        return;
    }
    let pgid = cur.pgid();
    cur.set_ctty(Some(Arc::clone(inode)));
    match tgt {
        TtyTarget::Serial => serial::set_session_and_fg(sid, pgid),
        TtyTarget::Vt(vt) => vt_tty::set_session_and_fg(vt, sid, pgid),
    }
}
