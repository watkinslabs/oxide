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
/// (`drivers/tty/tty_jobctrl.c:305-311`) WITHOUT revoking the line — TIOCNOTTY
/// detaches the terminal from the session, it does not hang it up.
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
