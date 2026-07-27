// Controlling-terminal acquisition when a pty half is opened — Linux
// `tty_open`'s `tty_open_proc_set_tty` arm (`drivers/tty/tty_io.c:2163-2169`,
// `drivers/tty/tty_jobctrl.c:132-160`), POSIX §11.1.3.
//
// Linux's `noctty` term excludes only the pty MASTER half
// (`TTY_DRIVER_TYPE_PTY` + `PTY_TYPE_MASTER`, `tty_io.c:2166-2167`); the SLAVE
// half takes the ordinary rule. Oxide had no pts arm at all — `console`'s
// `acquire_ctty_on_open` short-circuits on anything outside the console
// char-device band — so a session leader opening `/dev/pts/<n>` never made it
// its ctty, `tty_check_change` short-circuited on `is_ctty == false`, and a
// backgrounded read of a pty neither raised SIGTTIN nor resumed after `fg`.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use tty::ctty::{kind_can_be_ctty, should_acquire_ctty, TtyKind};
use vfs::{InodeRef, OpenFlags};

use crate::LockedPair;

/// Linux `tty_open` ctty acquisition for a pty inode. Called from the open(2)
/// path alongside `console::acquire_ctty_on_open`, which owns the console
/// char-device band; each classifies only the inodes it allocates. No-op for
/// non-pty inodes, the master half, `O_NOCTTY`, a non-leader, a caller that
/// already owns a ctty, or a pair already claimed by a session (stealing one
/// needs `TIOCSCTTY`).
/// # C: O(1)
pub fn acquire_ctty_on_open(inode: &InodeRef, flags: u32) {
    let Some(pair) = inode.private::<LockedPair>() else { return; };
    let kind = if inode.ino() == pair.ino_slave { TtyKind::PtySlave } else { TtyKind::PtyMaster };
    let o_noctty = flags & OpenFlags::O_NOCTTY.bits() != 0;
    let Some(cur) = sched::live::current() else { return; };
    let vpid = cur.vtgid.load(Ordering::Acquire);
    let my_pid = if vpid != 0 { vpid } else { cur.tid };
    let sid = cur.sid();
    let is_leader = sid != 0 && sid == my_pid;
    // SAFETY: single-mutator per `13§5` — running task on this CPU is the sole writer of ctty.
    let has_ctty = unsafe { (*cur.ctty.get()).is_some() };
    let tty_sid = pair.with_pair(|p| p.session_pid);
    if !should_acquire_ctty(kind_can_be_ctty(kind), o_noctty, is_leader, has_ctty, tty_sid != 0) {
        return;
    }
    let pgid = cur.pgid();
    // SAFETY: single-mutator per `13§5` — running task on this CPU is the sole writer of ctty.
    unsafe { *cur.ctty.get() = Some(Arc::clone(inode)); }
    // `__proc_set_tty` claims the tty for the leader's session AND seeds the
    // foreground process group with the leader's, without which `tcgetpgrp`
    // reads 0 and every subsequent job-control decision is unanchored.
    pair.with_pair(|p| { p.session_pid = sid; p.foreground_pgid = pgid; });
}
