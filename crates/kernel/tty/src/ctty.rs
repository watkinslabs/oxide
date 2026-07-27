// Controlling-terminal acquisition decision — the pure core of Linux
// `tty_open` → `tty_open_proc_set_tty` / `__proc_set_tty`
// (`drivers/tty/tty_io.c`, `28§4`). Kept in the tty crate (host-testable)
// so the rule is verified by oracle tests; the kernel open path supplies
// the live context (is-the-inode-a-tty, O_NOCTTY, session-leader, current
// ctty, tty's owning session) and acts on the outcome by wiring
// task.ctty + tty->session + tty->pgrp.
//
// Linux contract (POSIX §11.1.3): when a session leader that has NO
// controlling terminal opens a tty WITHOUT O_NOCTTY, and that tty is not
// already some session's controlling terminal, the tty becomes the
// session's controlling terminal — tty->session = leader's session,
// tty->pgrp = leader's process group, and task->ctty = the tty. With
// O_NOCTTY, or for a non-leader, or when the caller already owns a ctty, or
// when the tty already belongs to a session, the open does NOT acquire.

/// Which tty an open resolved to. Linux computes its `noctty` term in
/// `tty_open` from the device number plus the driver type/subtype
/// (`drivers/tty/tty_io.c:2163-2167`); this is that classification reduced to
/// the distinctions oxide's device numbering can make.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum TtyKind {
    /// An ordinary terminal line: a numbered VT (`/dev/tty<N>`) or the serial
    /// tty (`/dev/ttyS0`).
    Terminal,
    /// pty master half (`/dev/ptmx`) — Linux `TTY_DRIVER_TYPE_PTY` +
    /// `PTY_TYPE_MASTER`, folded into `noctty` at `tty_io.c:2166-2167`, so it
    /// can NEVER become a controlling terminal.
    PtyMaster,
    /// pty slave half (`/dev/pts/<n>`) — absent from Linux's `noctty` term, so
    /// it takes the ordinary POSIX §11.1.3 rule below. This is what makes job
    /// control work on a pty: without a ctty the slave is nobody's controlling
    /// terminal, `tty_check_change` short-circuits, and a background read
    /// neither stops on SIGTTIN nor resumes after `fg`.
    PtySlave,
}

/// Whether a tty of this kind can become a controlling terminal on open at
/// all, before the O_NOCTTY / session-leader / ownership conditions in
/// [`should_acquire_ctty`] are applied (Linux `tty_open`'s `noctty` term minus
/// its O_NOCTTY and device-alias clauses, `drivers/tty/tty_io.c:2163-2167`).
/// # C: O(1)
pub const fn kind_can_be_ctty(kind: TtyKind) -> bool {
    match kind {
        TtyKind::PtyMaster => false,
        TtyKind::Terminal | TtyKind::PtySlave => true,
    }
}

/// Decide whether opening a tty should make it the caller's session's
/// controlling terminal (Linux `tty_open` ctty acquisition). Inputs:
///   `is_tty`            — the opened inode is a console/serial/VT tty
///   `o_noctty`          — the open flags carried `O_NOCTTY`
///   `is_session_leader` — caller's session id == its own (v)pid
///   `has_ctty`          — caller already owns a controlling terminal
///   `tty_has_session`   — the tty already belongs to a session (sid != 0)
/// Returns `true` iff all of: it is a tty, no O_NOCTTY, the caller is a
/// session leader with no ctty, and the tty is unclaimed.
/// # C: O(1)
pub fn should_acquire_ctty(
    is_tty: bool,
    o_noctty: bool,
    is_session_leader: bool,
    has_ctty: bool,
    tty_has_session: bool,
) -> bool {
    is_tty && !o_noctty && is_session_leader && !has_ctty && !tty_has_session
}

#[cfg(test)]
mod tests {
    use super::{kind_can_be_ctty, should_acquire_ctty, TtyKind};

    #[test]
    fn a_pty_slave_is_a_ctty_candidate_and_the_master_never_is() {
        // `tty_io.c:2166-2167` folds ONLY the master half into `noctty`.
        assert!(kind_can_be_ctty(TtyKind::PtySlave));
        assert!(kind_can_be_ctty(TtyKind::Terminal));
        assert!(!kind_can_be_ctty(TtyKind::PtyMaster));
    }

    #[test]
    fn a_session_leader_opening_a_pts_slave_acquires_it() {
        // The probe's session child: setsid() then open("/dev/pts/<n>").
        assert!(should_acquire_ctty(
            kind_can_be_ctty(TtyKind::PtySlave), false, true, false, false));
        // Same call on the master half must not.
        assert!(!should_acquire_ctty(
            kind_can_be_ctty(TtyKind::PtyMaster), false, true, false, false));
    }

    #[test]
    fn session_leader_no_ctty_unclaimed_acquires() {
        // The getty path: a session leader (post-setsid) opens an unclaimed
        // console tty without O_NOCTTY → it becomes the ctty.
        assert!(should_acquire_ctty(true, false, true, false, false));
    }

    #[test]
    fn o_noctty_suppresses_acquisition() {
        assert!(!should_acquire_ctty(true, true, true, false, false));
    }

    #[test]
    fn non_leader_never_acquires() {
        assert!(!should_acquire_ctty(true, false, false, false, false));
    }

    #[test]
    fn caller_with_existing_ctty_does_not_acquire() {
        assert!(!should_acquire_ctty(true, false, true, true, false));
    }

    #[test]
    fn already_claimed_tty_is_not_stolen() {
        assert!(!should_acquire_ctty(true, false, true, false, true));
    }

    #[test]
    fn non_tty_inode_never_acquires() {
        assert!(!should_acquire_ctty(false, false, true, false, false));
    }
}
