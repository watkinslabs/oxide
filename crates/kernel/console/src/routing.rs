use alloc::sync::Arc;

use vfs::{Ino, InodeRef, OpenFlags};

use crate::serial;
use crate::vt_tty;

/// Console char-device ino base (low byte = device selector).
pub const TTY_INO_BASE: Ino = 0x7400;
/// Low-byte selector for the serial tty (`/dev/ttyS0`).
pub const SERIAL_INO_LB: u8 = 0xFE;
/// Low-byte selector for the foreground video VT (`/dev/console`/tty0).
pub const FG_VT_INO_LB: u8 = 0xFD;
/// Low-byte selector for the `/dev/tty` controlling-terminal alias.  This is
/// distinct from `/dev/tty0`: both may follow the foreground VT for I/O, but
/// only the former has Linux device number 5:0 and open-time ctty semantics.
pub const TTY_ALIAS_INO_LB: u8 = 0xFC;
/// Low-byte selector for the preferred-console inode.
pub const SYSTEM_CONSOLE_INO_LB: u8 = 0x01;

/// Which backing tty a console char-device ino maps to.
pub enum TtyTarget {
    /// The serial UART tty (`static_console`).
    Serial,
    /// Video VT `n` (1-based) — `vt_tty(n)`.
    Vt(u8),
}

/// Resolve a console char-device ino to its backing tty (the Linux device
/// split). `0xFE` → serial; `0xFC`/`0xFD` → foreground video VT; `1..63` →
/// VT n.
/// # C: O(1)
pub fn route(ino: u64) -> TtyTarget {
    match (ino & crate::ids::TTY_INO_MASK) as u8 {
        SERIAL_INO_LB => TtyTarget::Serial,
        TTY_ALIAS_INO_LB | FG_VT_INO_LB => TtyTarget::Vt(tty::live::foreground().max(1)),
        n => TtyTarget::Vt(n),
    }
}

/// The current foreground video VT (1-based). `/dev/console` + the keyboard
/// follow this. # C: O(1)
pub fn foreground_vt() -> u8 {
    tty::live::foreground().max(1)
}

/// True when `ino` is a console / serial / numbered-VT tty char-device inode
/// (the `0x7400..=0x74FF` band — `/dev/console`, `/dev/tty`, `/dev/tty0`,
/// `/dev/tty1..63`, `/dev/ttyS0`). Excludes vcs (`0x7600`/`0x7700`), pts
/// (`0x6000_0000`), fbdev, vcsa, and pidfd ranges. # C: O(1)
pub fn is_console_tty_ino(ino: Ino) -> bool {
    (ino & !crate::ids::TTY_INO_MASK) == TTY_INO_BASE
}

/// Linux `tty_open` controlling-terminal acquisition (`drivers/tty/tty_io.c`
/// `tty_open` → `__proc_set_tty`, POSIX §11.1.3). Called from the open(2)
/// path after a console/serial/VT tty char-device inode has been resolved.
///
/// When the caller is a session leader with NO controlling terminal, the
/// open flags do NOT carry `O_NOCTTY`, and the tty has no owning session,
/// make this tty the session's controlling terminal: record the inode on the
/// calling task (`task.ctty`) so `/dev/tty` resolves to it, claim the tty for
/// the leader's session (`tty->session`), and seed the tty's foreground
/// process group with the leader's pgrp (without which a job-control shell
/// trips SIGTTIN on its first read). No-op when O_NOCTTY is set, the inode is
/// not a console tty, the caller is not a session leader, the caller already
/// owns a ctty, or the tty already belongs to a session (a plain open never
/// steals — that needs TIOCSCTTY).
/// # C: O(1)
pub fn acquire_ctty_on_open(inode: &InodeRef, flags: u32) {
    use core::sync::atomic::Ordering;

    let ino = inode.ino();
    if !is_console_tty_ino(ino) {
        return;
    }
    let o_noctty = flags & OpenFlags::O_NOCTTY.bits() != 0;
    let cur = match sched::live::current() {
        Some(c) => c,
        None => return,
    };
    let vpid = cur.vtgid.load(Ordering::Acquire);
    let my_pid = if vpid != 0 { vpid } else { cur.tid };
    let sid = cur.sid();
    let is_leader = sid != 0 && sid == my_pid;
    // SAFETY: single-mutator per `13§5` — running task on this CPU is the sole writer of ctty.
    let has_ctty = unsafe { (*cur.ctty.get()).is_some() };
    let tty_sid = match route(ino) {
        TtyTarget::Serial => serial::session(),
        TtyTarget::Vt(vt) => vt_tty::vt_tty(vt).sid(),
    };
    if !tty::ctty::should_acquire_ctty(true, o_noctty, is_leader, has_ctty, tty_sid != 0) {
        return;
    }
    let pgid = cur.pgid();
    // SAFETY: single-mutator per `13§5` — running task on this CPU is the sole writer of ctty.
    unsafe { *cur.ctty.get() = Some(Arc::clone(inode)); }
    match route(ino) {
        TtyTarget::Serial => serial::set_session_and_fg(sid, pgid),
        TtyTarget::Vt(vt) => vt_tty::set_session_and_fg(vt, sid, pgid),
    }
}
