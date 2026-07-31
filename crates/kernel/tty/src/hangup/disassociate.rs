// `disassociate_ctty` — dropping a session's controlling terminal, from the
// two callers that do it: a session leader's LAST thread exiting (`on_exit`),
// and the `TIOCNOTTY` ioctl (`!on_exit`).
//
// Pure and ungated so the whole ladder is provable from `cargo test -p tty`;
// the live half needs the task list (`super::live`) and the device routing
// (kernel side), neither of which is host-testable.
//
// The four branches differ in ways that are easy to collapse by accident and
// each collapse is a real regression:
//   * a NON-leader does nothing at all — no SIGHUP anywhere. Its own terminal
//     reference goes away with it, and SIGHUP'ing on a non-leader exit kills
//     every job the still-live session leader owns.
//   * a leader exiting on a REAL terminal revokes the line (vhangup), so a
//     process that ignores SIGHUP still loses the terminal. A leader exiting
//     on a pty does NOT revoke — the pty goes away with its master.
//   * SIGCONT accompanies the SIGHUP only when the leader is NOT exiting.
//     On the exit path the foreground group gets SIGHUP alone.
//   * a leader exiting with NO controlling terminal still owes SIGHUP+SIGCONT
//     to the group that was in the foreground when the terminal was hung up
//     out from under it (`tty_old_pgrp`) — otherwise a job stopped at the
//     moment of a carrier drop stays stopped forever.

/// Signals a process group is sent, in order.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub enum PgrpSignal {
    /// Not signalled.
    #[default]
    None,
    /// SIGHUP alone (the exiting-leader form).
    Hup,
    /// SIGHUP then SIGCONT, so a stopped group runs its handler.
    HupThenCont,
}

impl PgrpSignal {
    /// Whether SIGHUP goes out. # C: O(1)
    pub const fn hup(self) -> bool { !matches!(self, PgrpSignal::None) }
    /// Whether SIGCONT follows the SIGHUP. # C: O(1)
    pub const fn cont(self) -> bool { matches!(self, PgrpSignal::HupThenCont) }
}

/// Everything one `disassociate_ctty` call must do, in the order the fields
/// are listed.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct DisassociateActions {
    /// Revoke the line for every opener (reads → EOF, writes → EIO) and run
    /// the session walk: each member loses this terminal, each session leader
    /// gets SIGHUP+SIGCONT, the foreground group gets SIGHUP. Set only for a
    /// leader exiting on a terminal that is not a pty.
    pub vhangup_session: bool,
    /// Signals owed to the terminal's foreground group by the branches that do
    /// NOT vhangup (the vhangup walk sends its own).
    pub fg_pgrp: PgrpSignal,
    /// Signals owed to the saved `tty_old_pgrp` — the no-controlling-terminal
    /// exit branch only.
    pub old_pgrp: PgrpSignal,
    /// Clear the terminal's controlling-session and foreground-group linkage
    /// without revoking it.
    pub clear_linkage: bool,
    /// Forget the saved `tty_old_pgrp`.
    pub clear_old_pgrp: bool,
    /// Every task in the session loses this controlling terminal.
    pub clear_session_ctty: bool,
    /// The caller alone loses its controlling terminal. The non-leader form —
    /// a leader's clear is covered by `clear_session_ctty`, which includes it.
    pub clear_own_ctty: bool,
}

/// Which caller this is.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum DisassociateCause {
    /// The last thread of a session leader is exiting (`on_exit = 1`).
    Exit,
    /// `TIOCNOTTY` (`on_exit = 0`).
    Notty,
}

/// The controlling terminal a session leader holds, as far as this decision
/// needs to know it.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct CttyFacts {
    /// The terminal is a pty slave, which is never revoked here.
    pub is_pty: bool,
    /// The terminal's foreground process group, 0 when unset.
    pub fg_pgrp: u32,
}

/// The whole `disassociate_ctty` ladder.
///
/// `ctty` is the caller's controlling terminal, `None` when it has none;
/// `tty_old_pgrp` is the foreground group saved when the terminal was hung up
/// under the caller (0 when none was saved).
/// # C: O(1)
pub const fn disassociate_ctty(
    cause: DisassociateCause,
    is_session_leader: bool,
    ctty: Option<CttyFacts>,
    tty_old_pgrp: u32,
) -> DisassociateActions {
    let on_exit = matches!(cause, DisassociateCause::Exit);
    if !is_session_leader {
        // Returns before touching the terminal, the session, or any signal.
        // The caller's own reference is all that goes away.
        return DisassociateActions { clear_own_ctty: true, ..blank() };
    }
    let Some(tty) = ctty else {
        if !on_exit {
            // TIOCNOTTY on a leader with no controlling terminal: the ioctl
            // itself has already refused unless the terminal matched, so this
            // shape only arises from a racing clear. Nothing is owed.
            return DisassociateActions { clear_own_ctty: true, ..blank() };
        }
        // The terminal was hung up under us. Whatever was in the foreground
        // then is still owed its wake-up, and nothing else runs — not even
        // the session walk.
        let old_pgrp = if tty_old_pgrp != 0 { PgrpSignal::HupThenCont } else { PgrpSignal::None };
        return DisassociateActions { old_pgrp, clear_old_pgrp: true, ..blank() };
    };
    let vhangup_session = on_exit && !tty.is_pty;
    let fg_pgrp = if vhangup_session || tty.fg_pgrp == 0 {
        PgrpSignal::None
    } else if on_exit {
        PgrpSignal::Hup
    } else {
        PgrpSignal::HupThenCont
    };
    DisassociateActions {
        vhangup_session,
        fg_pgrp,
        old_pgrp: PgrpSignal::None,
        clear_linkage: true,
        clear_old_pgrp: true,
        clear_session_ctty: true,
        clear_own_ctty: false,
    }
}

/// All-quiet actions, the base every branch overrides fields on. # C: O(1)
const fn blank() -> DisassociateActions {
    DisassociateActions {
        vhangup_session: false,
        fg_pgrp: PgrpSignal::None,
        old_pgrp: PgrpSignal::None,
        clear_linkage: false,
        clear_old_pgrp: false,
        clear_session_ctty: false,
        clear_own_ctty: false,
    }
}

#[cfg(test)]
mod tests {
    use super::{disassociate_ctty, CttyFacts, DisassociateCause, PgrpSignal};

    const TERMINAL: Option<CttyFacts> = Some(CttyFacts { is_pty: false, fg_pgrp: 42 });
    const PTS: Option<CttyFacts> = Some(CttyFacts { is_pty: true, fg_pgrp: 42 });

    #[test]
    fn a_non_leader_exit_signals_nobody_and_touches_no_session_state() {
        // The expensive mistake: SIGHUP'ing the session because a background
        // member of it exited. Every job of a live shell would die.
        for ctty in [TERMINAL, PTS, None] {
            let a = disassociate_ctty(DisassociateCause::Exit, false, ctty, 7);
            assert!(!a.vhangup_session);
            assert_eq!(a.fg_pgrp, PgrpSignal::None);
            assert_eq!(a.old_pgrp, PgrpSignal::None);
            assert!(!a.clear_linkage);
            assert!(!a.clear_session_ctty);
            assert!(a.clear_own_ctty, "it still drops its own reference");
        }
    }

    #[test]
    fn a_leader_exiting_on_a_real_terminal_vhangs_the_session_up() {
        let a = disassociate_ctty(DisassociateCause::Exit, true, TERMINAL, 0);
        assert!(a.vhangup_session, "the line must be revoked, not merely signalled");
        // The vhangup walk carries the foreground SIGHUP itself; issuing it
        // here too would double-post it.
        assert_eq!(a.fg_pgrp, PgrpSignal::None);
        assert!(a.clear_linkage);
        assert!(a.clear_session_ctty);
        assert!(a.clear_old_pgrp);
    }

    #[test]
    fn a_leader_exiting_on_a_pty_signals_but_never_revokes() {
        let a = disassociate_ctty(DisassociateCause::Exit, true, PTS, 0);
        assert!(!a.vhangup_session, "a pty is not revoked by its session leader's exit");
        assert_eq!(a.fg_pgrp, PgrpSignal::Hup, "SIGHUP alone on the exit path");
        assert!(a.clear_linkage);
        assert!(a.clear_session_ctty);
    }

    #[test]
    fn sigcont_accompanies_sighup_only_when_the_leader_is_not_exiting() {
        // TIOCNOTTY pairs them so a stopped foreground job runs its handler;
        // an exiting leader sends SIGHUP alone.
        assert_eq!(
            disassociate_ctty(DisassociateCause::Notty, true, TERMINAL, 0).fg_pgrp,
            PgrpSignal::HupThenCont);
        assert_eq!(
            disassociate_ctty(DisassociateCause::Notty, true, PTS, 0).fg_pgrp,
            PgrpSignal::HupThenCont);
        assert_eq!(
            disassociate_ctty(DisassociateCause::Exit, true, PTS, 0).fg_pgrp,
            PgrpSignal::Hup);
    }

    #[test]
    fn tiocnotty_never_revokes_the_line() {
        // Detaching a terminal from a session is not a hangup: another session
        // may legitimately claim the same line afterwards.
        let a = disassociate_ctty(DisassociateCause::Notty, true, TERMINAL, 0);
        assert!(!a.vhangup_session);
        assert!(a.clear_linkage);
        assert!(a.clear_session_ctty);
    }

    #[test]
    fn an_exiting_leader_with_no_terminal_wakes_the_group_that_lost_it() {
        // A carrier drop hung the line up and stopped the foreground job; the
        // leader then exits. Without this the job stays stopped forever.
        let a = disassociate_ctty(DisassociateCause::Exit, true, None, 9);
        assert_eq!(a.old_pgrp, PgrpSignal::HupThenCont);
        assert!(a.clear_old_pgrp);
        // Nothing else runs on this branch — there is no terminal to clear and
        // no session walk.
        assert!(!a.vhangup_session);
        assert!(!a.clear_linkage);
        assert!(!a.clear_session_ctty);
    }

    #[test]
    fn no_saved_group_means_no_signal_on_the_terminal_less_exit() {
        let a = disassociate_ctty(DisassociateCause::Exit, true, None, 0);
        assert_eq!(a.old_pgrp, PgrpSignal::None);
        assert!(a.clear_old_pgrp);
    }

    #[test]
    fn an_unset_foreground_group_is_never_signalled() {
        let none_fg = Some(CttyFacts { is_pty: true, fg_pgrp: 0 });
        assert_eq!(
            disassociate_ctty(DisassociateCause::Exit, true, none_fg, 0).fg_pgrp,
            PgrpSignal::None);
        assert_eq!(
            disassociate_ctty(DisassociateCause::Notty, true, none_fg, 0).fg_pgrp,
            PgrpSignal::None);
    }

    #[test]
    fn the_saved_group_is_only_consulted_when_there_is_no_terminal() {
        // Holding a terminal, the saved group is dropped without a signal.
        let a = disassociate_ctty(DisassociateCause::Exit, true, TERMINAL, 9);
        assert_eq!(a.old_pgrp, PgrpSignal::None);
        assert!(a.clear_old_pgrp);
    }

    #[test]
    fn signal_shapes_decode_to_the_right_pair() {
        assert!(!PgrpSignal::None.hup() && !PgrpSignal::None.cont());
        assert!(PgrpSignal::Hup.hup() && !PgrpSignal::Hup.cont());
        assert!(PgrpSignal::HupThenCont.hup() && PgrpSignal::HupThenCont.cont());
    }
}
