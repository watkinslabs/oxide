// Live job-control gate for a controlling tty: gather the calling task's
// context (pgrp, ctty match, stop-signal disposition, orphan status) and
// apply the pure decision from `tty::jobctl::decide` (Linux
// `tty_check_change`, `28§6`). On a Stop decision, send SIGTTIN/SIGTTOU to
// the pgrp (default-stops it) and fail the syscall with EINTR.
//
// The check applies ONLY when the tty IS the caller's controlling tty and
// the caller's pgrp differs from the tty's foreground pgrp, so session
// leaders / foreground jobs (PID 1, login, getty, the active shell) are
// never gated.

use core::sync::atomic::Ordering;
use tty::jobctl::{decide, Decision};
use tty::pty::lflag;
use tty::Sig;
use vfs::{Ino, KResult, VfsError};

pub use tty::jobctl::Access;

/// Run the job-control check for `this_ino` (the tty being accessed) given
/// its foreground pgrp + controlling session + current `c_lflag`. Returns
/// `Ok(())` to proceed, or `Err(Eio)` / `Err(Eintr)` to fail the syscall
/// (after signalling the pgrp in the EINTR case). # C: O(pgrp size).
pub fn check(
    fg_pgrp: u32,
    tty_sid: u32,
    this_ino: Ino,
    lflag_bits: u32,
    access: Access,
) -> KResult<()> {
    let cur = match sched::live::current() {
        Some(c) => c,
        None => return Ok(()),
    };
    // SAFETY: single-mutator per `13§5`; current task on this CPU, ctty read-only here.
    let ctty_ino = unsafe { (*cur.ctty.get()).as_ref().map(|i| i.ino()) };
    let is_ctty = ctty_ino == Some(this_ino);
    let pgid = cur.pgid.load(Ordering::Acquire);
    let sig = match access {
        Access::Read => Sig::Ttin,
        Access::Write => Sig::Ttou,
    };
    let signo = sig.signo();
    let Some(bit) = sched::bit_for(signo as u32) else { return Ok(()); };
    let ignored = cur.sigactions_ref().get(signo as u32).handler == 1;
    let blocked = cur.sigmask.load(Ordering::Acquire) & bit != 0;
    let tostop = lflag_bits & lflag::TOSTOP != 0;
    // Orphan scan is O(pgrp); only run it when the decision would otherwise
    // be Stop (background, not ignored/blocked, TOSTOP-gated for writes).
    let could_stop = is_ctty
        && fg_pgrp != 0
        && pgid != 0
        && pgid != fg_pgrp
        && !(access == Access::Write && !tostop)
        && !(ignored || blocked);
    let orphaned = could_stop && is_orphaned(pgid, tty_sid);
    match decide(is_ctty, pgid, fg_pgrp, tostop, access, ignored, blocked, orphaned) {
        Decision::Proceed => Ok(()),
        Decision::Eio => Err(VfsError::Eio),
        Decision::Stop => {
            // Stop the whole pgrp (default disposition of SIGTTIN/SIGTTOU);
            // the signal core flips each member to Stopped until SIGCONT.
            for t in sched::live::registry::tasks_in_pgrp(pgid) {
                t.sigpending.fetch_or(bit, Ordering::Release);
            }
            Err(VfsError::Eintr)
        }
    }
}

/// A process group is orphaned when no member has a parent in a DIFFERENT
/// process group of the SAME session (Linux `will_become_orphaned_pgrp`):
/// such a pgrp has no shell to continue it, so the kernel must not stop it.
/// # C: O(pgrp size).
fn is_orphaned(pgid: u32, sid: u32) -> bool {
    for t in sched::live::registry::tasks_in_pgrp(pgid) {
        // SAFETY: single-mutator per `13§5`; reading the parent weak-ref of a live task.
        let parent = unsafe { (*t.parent_arc.get()).as_ref().and_then(|w| w.upgrade()) };
        if let Some(p) = parent {
            let ppgid = p.pgid.load(Ordering::Acquire);
            let psid = p.sid.load(Ordering::Acquire);
            if ppgid != pgid && psid == sid {
                return false;
            }
        }
    }
    true
}
