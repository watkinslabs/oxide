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
    use super::should_acquire_ctty;

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
