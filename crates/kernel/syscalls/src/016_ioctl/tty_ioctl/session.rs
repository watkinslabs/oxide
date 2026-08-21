#![cfg(target_os = "oxide-kernel")]

// Session / controlling-terminal and modem-control ioctls, split out of
// `tty_ioctl` at the file-length boundary (`08§7`). Every arm here resolves its
// tty from the caller's already-resolved pty pair or console target — never
// from the inode's number.

use alloc::sync::Arc;

use syscall::errno::Errno;
use tty::ioctl::req as tty_req;

use crate::userbuf::validate_user_buf;

const TIOCSCTTY: u64 = tty_req::TIOCSCTTY as u64;
const TIOCNOTTY: u64 = tty_req::TIOCNOTTY as u64;
const TIOCGSID: u64 = tty_req::TIOCGSID as u64;
const TIOCMGET: u64 = tty_req::TIOCMGET as u64;
const TIOCMBIS: u64 = tty_req::TIOCMBIS as u64;
const TIOCMSET: u64 = tty_req::TIOCMSET as u64;

/// Width of the `int` a `TIOCGSID` / modem-control argument points at.
const INT_BYTES: u64 = tty_req::INT_BYTES;

fn enotty() -> i64 { -(Errno::Enotty.as_i32() as i64) }

/// Dispatch the session/modem arms. `con` is the console tty the fd speaks
/// for, `None` when the fd is a pty endpoint instead.
/// # C: O(N_tasks) for TIOCNOTTY, else O(1)
pub(super) fn handle(
    file: &vfs::File,
    con: Option<console::TtyTarget>,
    pty_pair: &Option<Arc<devpts::LockedPair>>,
    req: u64,
    arg: u64,
) -> i64 {
    match req {
        TIOCSCTTY => sctty(file, con, pty_pair),
        TIOCGSID => gsid(con, pty_pair, arg),
        TIOCNOTTY => notty(file),
        TIOCMGET => mget(con, pty_pair, arg),
        _ => mset(con, pty_pair, req, arg),
    }
}

/// `TIOCSCTTY` — make this fd's tty the caller's controlling terminal, and
/// seed the tty's foreground process group with the session leader's pgrp.
/// Without the seed `tcgetpgrp` returns 0, a job-control shell decides it is a
/// background job, every stdin read trips SIGTTIN, and login respawns getty
/// forever. # C: O(1)
fn sctty(
    file: &vfs::File,
    con: Option<console::TtyTarget>,
    pty_pair: &Option<Arc<devpts::LockedPair>>,
) -> i64 {
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Eperm.as_i32() as i64),
    };
    // Store the inode on the calling PROCESS so a `/dev/tty` open can redirect
    // to it from any of its threads.
    cur.set_ctty(Some(file.inode().clone()));
    let pgrp = cur.pgrp();
    let session = cur.session();
    if let Some(pair) = pty_pair {
        pair.with_pair(|p| { p.foreground_pgrp = Some(pgrp); p.session = Some(session); });
        return 0;
    }
    match con {
        Some(console::TtyTarget::Serial) => console::static_console::set_session_and_fg(session, pgrp),
        Some(console::TtyTarget::Vt(vt)) => console::vt_tty::set_session_and_fg(vt, session, pgrp),
        None => return enotty(),
    }
    0
}

/// `TIOCGSID` — the session id that owns this tty, or ENOTTY when none does.
/// getty calls `tcgetsid(STDIN_FILENO)` to decide whether to TIOCSCTTY-steal.
/// # C: O(1)
fn gsid(
    con: Option<console::TtyTarget>,
    pty_pair: &Option<Arc<devpts::LockedPair>>,
    arg: u64,
) -> i64 {
    if let Err(rv) = validate_user_buf(arg, INT_BYTES, INT_BYTES) { return rv; }
    let sid: u32 = if let Some(pair) = pty_pair {
        let ns = sched::live::registry::reader_pid_ns();
        pair.with_pair(|p| p.session.as_ref().map_or(0, |id| id.nr_in_or_tid(&ns)))
    } else {
        match con {
            Some(console::TtyTarget::Serial) => console::static_console::session_identity()
                .map_or(0, |id| id.nr_in_or_tid(&sched::live::registry::reader_pid_ns())),
            Some(console::TtyTarget::Vt(vt)) => console::vt_tty::vt_tty(vt).session()
                .map_or(0, |id| id.nr_in_or_tid(&sched::live::registry::reader_pid_ns())),
            None => return enotty(),
        }
    };
    if sid == 0 { return enotty(); }
    if let Err(rv) = crate::ioctl_user::put_u32(arg, sid) { return rv; }
    0
}

/// `TIOCNOTTY` — Linux `tty_jobctrl_ioctl`: ENOTTY unless this IS the caller's
/// controlling terminal, then `disassociate_ctty(0)` plus the unconditional
/// `proc_clear_tty(current)`. agetty runs TIOCNOTTY, closes every fd, then
/// calls `vhangup(2)` expecting a no-op — which only holds once `task.ctty` is
/// cleared too. # C: O(N_tasks)
fn notty(file: &vfs::File) -> i64 {
    let cur = match sched::live::current() { Some(c) => c, None => return enotty() };
    if cur.ctty_ino() != Some(file.inode().ino()) { return enotty(); }
    crate::tty_hangup::disassociate_ctty(&cur, tty::hangup::DisassociateCause::Notty);
    cur.set_ctty(None);
    0
}

/// `TIOCMGET` — Linux answers only from a driver with `tiocmget`. The serial
/// console has one (software MCR); a VT and a pty have none → ENOTTY.
/// # C: O(1)
fn mget(
    con: Option<console::TtyTarget>,
    pty_pair: &Option<Arc<devpts::LockedPair>>,
    arg: u64,
) -> i64 {
    if let Err(rv) = validate_user_buf(arg, INT_BYTES, INT_BYTES) { return rv; }
    if pty_pair.is_some() { return enotty(); }
    let bits = match con {
        Some(console::TtyTarget::Serial) => console::static_console::modem_get(),
        Some(console::TtyTarget::Vt(_)) | None => return enotty(),
    };
    if let Err(rv) = crate::ioctl_user::put_u32(arg, bits) { return rv; }
    0
}

/// `TIOCMSET`/`TIOCMBIS`/`TIOCMBIC` — same driver rule as [`mget`]. # C: O(1)
fn mset(
    con: Option<console::TtyTarget>,
    pty_pair: &Option<Arc<devpts::LockedPair>>,
    req: u64,
    arg: u64,
) -> i64 {
    if let Err(rv) = validate_user_buf(arg, INT_BYTES, INT_BYTES) { return rv; }
    if pty_pair.is_some() { return enotty(); }
    match con {
        Some(console::TtyTarget::Serial) => {
            let v = match crate::ioctl_user::get_u32(arg) { Ok(v) => v, Err(rv) => return rv };
            match req {
                TIOCMSET => console::static_console::modem_set(v),
                TIOCMBIS => console::static_console::modem_bis(v),
                // TIOCMBIC — the only remaining member of the family.
                _        => console::static_console::modem_bic(v),
            }
            0
        }
        Some(console::TtyTarget::Vt(_)) | None => enotty(),
    }
}
