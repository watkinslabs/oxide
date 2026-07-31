// 153 vhangup — one syscall, one file (docs/53 §0).
//
// ABI shim only: every rule comes from `tty::hangup` (host-tested); the device
// routing comes from `crate::tty_hangup`.
//
// What this syscall is FOR: `login`/`agetty` call it between sessions so that
// nothing the previous session left running can still reach the terminal. That
// makes two properties load-bearing, and the previous implementation had
// neither — it posted SIGHUP to every task sharing the caller's session id and
// never touched a tty at all:
//   * the line is REVOKED (`__tty_hangup` swaps every opener's `f_op` to
//     `hung_up_tty_fops`), so a process that ignores SIGHUP still loses the
//     terminal. Signalling alone leaves it holding the next user's tty.
//   * only the caller's CONTROLLING terminal is affected, and only the session
//     LEADER is signalled — SIGHUP'ing the whole session kills background jobs
//     Linux leaves alone, and a caller with no controlling terminal must be a
//     silent no-op rather than a session-wide massacre.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// `sys_vhangup()` — slot 153. `capable(CAP_SYS_TTY_CONFIG)` then
/// `tty_vhangup_self()` (`fs/open.c:1530-1537`).
/// # C: O(N_tasks)
pub fn sys_vhangup(_args: &SyscallArgs) -> i64 {
    let cur = match sched::live::current() { Some(c) => c, None => return 0 };
    let cap = cur.has_cap(sched::cap::SYS_TTY_CONFIG);
    // SAFETY: `ctty` is single-mutator per `13§5` — the running task on this CPU is its sole writer, and this read stays in syscall context.
    let ctty_ino = cur.ctty_ino();
    match tty::hangup::vhangup_decision(cap, ctty_ino.is_some()) {
        tty::hangup::VhangupOutcome::Eperm => -(Errno::Eperm.as_i32() as i64),
        // `get_current_tty()` returned NULL: `tty_vhangup_self` returns without
        // doing anything and the syscall still succeeds.
        tty::hangup::VhangupOutcome::NoControllingTty => 0,
        tty::hangup::VhangupOutcome::Hangup => {
            let ino = match ctty_ino { Some(i) => i, None => return 0 };
            let Some(target) = crate::tty_hangup::resolve(ino) else { return 0 };
            // Signal + revoke the session BEFORE the tty state change: the walk
            // needs `tty->ctrl.session`, which `__tty_hangup` then clears.
            let sid = crate::tty_hangup::session(&target);
            tty::hangup::hangup_session(ino, sid);
            crate::tty_hangup::hangup(&target, tty::HangupKind::Vhangup);
            0
        }
    }
}
