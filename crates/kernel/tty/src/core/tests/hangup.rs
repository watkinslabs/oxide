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
