// `__tty_hangup` state transitions on the tty core (Linux's tty_io
// hangup path). The SESSION-scoped half of a hangup — who
// loses the controlling terminal, who is signalled — lives in
// `crate::hangup` and is tested there.

use super::{cooked_tty, Sig};
use crate::ReadOutcome;

#[test]
fn hangup_raises_sighup_resets_ldisc_and_clears_linkage() {
    let tty = cooked_tty();
    tty.set_ctty(7);
    tty.set_fg_pgrp(7);
    tty.receive_from_driver(b"line\n"); // a cooked line waiting
    assert!(tty.readable());
    // `exit_session = 1` (`tty_vhangup_session`): the session leader is going
    // away, so `kill_pgrp(tty_pgrp, SIGHUP, 1)` runs.
    tty.hangup(crate::HangupKind::SessionExit);
    // SIGHUP raised on the fg pgrp + driver.hangup() fired.
    tty.with_driver(|d| {
        assert_eq!(d.signals.last(), Some(&Sig::Hup), "SIGHUP on hangup");
        assert_eq!(d.hangups, 1, "driver.hangup() fired");
    });
    // Ldisc dropped to hung-up: read returns EOF (0), not the queued line.
    assert!(tty.is_hung_up());
    let mut buf = [0u8; 64];
    assert_eq!(tty.read(&mut buf), ReadOutcome::Eof, "hung-up read → Eof");
    // Controlling linkage cleared (Linux clears tty->session/pgrp).
    assert_eq!(tty.sid(), 0);
    assert_eq!(tty.fg_pgrp(), 0);
}

#[test]
fn hangup_makes_writes_drop() {
    let tty = cooked_tty();
    tty.hangup(crate::HangupKind::Vhangup);
    let n = tty.write(b"after hangup");
    assert_eq!(n, 12, "write reports consumed (EIO mapped at syscall layer)");
    tty.with_driver(|d| assert!(d.out.is_empty(), "nothing reaches a hung-up driver"));
}

#[test]
fn a_vhangup_does_not_signal_the_foreground_process_group() {
    // `__tty_hangup(tty, exit_session = 0)`: `tty_signal_session_leader` only
    // runs `kill_pgrp(tty_pgrp, SIGHUP)` when `exit_session` is set.
    // vhangup(2) passes 0, so the
    // foreground job is NOT killed by the hangup itself — only the session
    // leader is signalled, and that walk lives in `tty::hangup`.
    let tty = cooked_tty();
    tty.set_ctty(7);
    tty.set_fg_pgrp(7);
    tty.hangup(crate::HangupKind::Vhangup);
    tty.with_driver(|d| {
        assert!(!d.signals.contains(&Sig::Hup), "vhangup must not kill the fg pgrp");
        assert_eq!(d.hangups, 1, "the line is still revoked");
    });
    assert!(tty.is_hung_up());
    assert_eq!(tty.sid(), 0);
    assert_eq!(tty.fg_pgrp(), 0);
}

#[test]
fn reopening_a_hung_up_tty_clears_the_hangup() {
    // Linux `tty_open` ends with `clear_bit(TTY_HUPPED, &tty->flags)`
    // on every successful open. agetty runs TIOCNOTTY -> close every fd
    // -> vhangup(2) -> REOPEN the same line; without this clear, oxide's
    // long-lived console tty would stay at permanent EOF and no later login
    // could ever read a keystroke.
    let tty = cooked_tty();
    tty.hangup(crate::HangupKind::Vhangup);
    assert!(tty.is_hung_up());
    tty.open();
    assert!(!tty.is_hung_up(), "a fresh open revives the line");
    tty.receive_from_driver(b"hi\n");
    let mut buf = [0u8; 8];
    assert_eq!(tty.read(&mut buf), ReadOutcome::Bytes(3));
}

// ---- per-OPEN revocation (`hung_up_tty_fops`) ------------------------
//
// The reference revokes each descriptor that was open across the hangup by
// pointing its `f_op` at a dead vtable, and separately clears the tty's own
// hung-up flag on the next open. The two are independent, which is the whole
// contract: a new session gets a working line, the dead session keeps a dead
// descriptor. A single shared flag on the tty passes the first two tests
// below and fails the third.

use crate::hangup::revoke;

#[test]
fn a_hangup_revokes_the_descriptions_open_across_it() {
    let tty = cooked_tty();
    let gen = tty.open_revocable(false).expect("open");
    tty.receive_from_driver(b"secret\n");
    tty.hangup(crate::HangupKind::Vhangup);

    let mut buf = [0u8; 64];
    // `hung_up_tty_read` — end of file, and NOT the queued line.
    assert_eq!(tty.read_open(gen, &mut buf), ReadOutcome::Bytes(0));
    // `hung_up_tty_write` — EIO.
    assert_eq!(tty.write_open(gen, b"x"), Err(vfs::VfsError::Eio));
    // `hung_up_tty_poll` — POLLHUP, immediately.
    assert_ne!(tty.poll_open(gen) & vfs::POLL_HUP, 0, "revoked poll reports POLLHUP");
    assert_eq!(tty.poll_open(gen), revoke::HUNG_UP_POLL);
}

#[test]
fn an_open_taken_after_the_hangup_works_normally() {
    let tty = cooked_tty();
    let _stale = tty.open_revocable(false).expect("open");
    tty.hangup(crate::HangupKind::Vhangup);

    // The next `login` opens the same line: `clear_bit(TTY_HUPPED)` revives it.
    let fresh = tty.open_revocable(false).expect("reopen");
    assert!(!tty.hung_up_open(fresh), "a post-hangup open is live");
    tty.receive_from_driver(b"hi\n");
    let mut buf = [0u8; 8];
    assert_eq!(tty.read_open(fresh, &mut buf), ReadOutcome::Bytes(3));
    assert_eq!(tty.write_open(fresh, b"ok"), Ok(2));
    assert_eq!(tty.poll_open(fresh) & vfs::POLL_HUP, 0, "a live open is not hung up");
}

#[test]
fn a_new_open_does_not_resurrect_the_revoked_descriptions() {
    // THE regression: `vhangup(2)` is a security boundary. A process that
    // survived the hangup still holding an fd must never read the next user's
    // keystrokes or write to their screen, no matter how many times the line
    // is reopened.
    let tty = cooked_tty();
    let stale = tty.open_revocable(false).expect("open");
    tty.hangup(crate::HangupKind::Vhangup);
    let fresh = tty.open_revocable(false).expect("reopen");

    // The new session's input is queued and readable through the NEW open.
    tty.receive_from_driver(b"password\n");
    assert!(tty.hung_up_open(stale), "the pre-hangup open stays revoked");

    let mut buf = [0u8; 64];
    assert_eq!(tty.read_open(stale, &mut buf), ReadOutcome::Bytes(0),
               "a revoked fd must not read the new session's input");
    assert_eq!(tty.write_open(stale, b"spoof"), Err(vfs::VfsError::Eio),
               "a revoked fd must not write to the new session's terminal");
    assert_ne!(tty.poll_open(stale) & vfs::POLL_HUP, 0, "revoked stays POLLHUP");

    // ... while the fresh open is unaffected by any of it.
    assert_eq!(tty.read_open(fresh, &mut buf), ReadOutcome::Bytes(9));

    // Still dead after further reopens.
    let _third = tty.open_revocable(false).expect("reopen again");
    assert!(tty.hung_up_open(stale), "revocation is permanent");
}

#[test]
fn a_revoked_nonblocking_read_is_eof_not_eagain() {
    let tty = cooked_tty();
    let gen = tty.open_revocable(false).expect("open");
    let mut buf = [0u8; 8];
    // A live but empty line is EAGAIN.
    assert_eq!(tty.read_nonblock_open(gen, &mut buf), Err(vfs::VfsError::Eagain));
    tty.hangup(crate::HangupKind::Vhangup);
    // A revoked one is at end of file.
    assert_eq!(tty.read_nonblock_open(gen, &mut buf), Ok(0));
}

#[test]
fn a_description_not_bound_to_a_tty_is_never_revoked() {
    // The boot `/dev/console` fd table is built before any tty open hook runs,
    // so it carries no generation; a later hangup must not kill the kernel's
    // own console.
    let tty = cooked_tty();
    tty.hangup(crate::HangupKind::Vhangup);
    tty.hangup(crate::HangupKind::Vhangup);
    assert!(!tty.hung_up_open(revoke::NOT_BOUND));
}
