// Pure hangup rules. Kept out of the syscall slot (kernel-gated, untestable)
// and out of the driver (which cannot see the task list).

/// Linux `__tty_hangup`'s `exit_session` argument
/// (`drivers/tty/tty_io.c:568`).
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum HangupKind {
    /// `tty_vhangup` — `vhangup(2)` and carrier loss (`exit_session = 0`).
    /// The foreground process group is NOT signalled wholesale.
    Vhangup,
    /// `tty_vhangup_session` — the session leader is exiting
    /// (`exit_session = 1`), so `kill_pgrp(tty_pgrp, SIGHUP, 1)` runs too
    /// (`drivers/tty/tty_jobctrl.c:232-236`).
    SessionExit,
}

/// What happens to ONE member of the hung-up tty's session
/// (`tty_signal_session_leader`, `drivers/tty/tty_jobctrl.c:202-227`).
#[derive(Copy, Clone, Eq, PartialEq, Debug, Default)]
pub struct SessionMemberAction {
    /// `p->signal->tty = NULL` — the task loses its controlling terminal.
    pub clear_ctty: bool,
    /// `send_signal_locked(SIGHUP, SEND_SIG_PRIV, p, PIDTYPE_TGID)`.
    pub sighup: bool,
    /// `send_signal_locked(SIGCONT, ...)` — paired with the SIGHUP so a
    /// STOPPED session leader actually runs its handler instead of staying
    /// parked with a pending signal it can never take.
    pub sigcont: bool,
}

/// Per-task hangup rule.
///
/// The two conditions are INDEPENDENT and Linux applies them in the same
/// iteration: `p->signal->tty == tty` decides the ctty clear, `p->signal->
/// leader` decides the signals. A session member that is not the leader loses
/// its terminal SILENTLY — SIGHUP'ing the whole session instead (which is
/// cheap and looks equivalent) kills every background process the session
/// owns, including ones the hangup was never meant to disturb.
/// # C: O(1)
pub const fn session_member_action(owns_this_tty: bool, is_session_leader: bool) -> SessionMemberAction {
    SessionMemberAction {
        clear_ctty: owns_this_tty,
        sighup: is_session_leader,
        sigcont: is_session_leader,
    }
}

/// Outcome of `SYSCALL_DEFINE0(vhangup)` (`fs/open.c:1530-1537`).
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum VhangupOutcome {
    /// `return -EPERM` — no CAP_SYS_TTY_CONFIG.
    Eperm,
    /// `tty_vhangup_self()` found no `current->signal->tty`: nothing happens
    /// and the syscall still returns 0.
    NoControllingTty,
    /// Hang up the caller's controlling terminal, then return 0.
    Hangup,
}

/// `vhangup(2)`'s whole admission ladder. CAP_SYS_TTY_CONFIG — NOT
/// CAP_SYS_ADMIN, which is what the `TIOCVHANGUP` ioctl uses
/// (`drivers/tty/tty_io.c:2729-2733`) — and the target is the CALLER's
/// controlling terminal, never "every task in my session".
/// # C: O(1)
pub const fn vhangup_decision(cap_sys_tty_config: bool, has_ctty: bool) -> VhangupOutcome {
    if !cap_sys_tty_config { return VhangupOutcome::Eperm; }
    if !has_ctty { return VhangupOutcome::NoControllingTty; }
    VhangupOutcome::Hangup
}
