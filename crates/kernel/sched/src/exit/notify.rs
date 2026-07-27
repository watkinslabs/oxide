// `exit_notify` + `do_notify_parent` (Linux `kernel/exit.c`, `kernel/signal.c`):
// which signal the real parent gets, and whether a zombie is left behind at all.
//
// POSIX.1 gives `SIGCHLD` set to `SIG_IGN`, and `SA_NOCLDWAIT`, special
// meaning: the child is reaped automatically and never becomes a zombie
// (`do_notify_parent`: `autoreap = true`). With `SIG_IGN` the notification is
// suppressed entirely (`sig = 0`); with `SA_NOCLDWAIT` plus a real handler
// Linux still sends the signal ("implementation-defined: we do").
// Either way a blocked `wait4` is woken so it can return `ECHILD`.

use crate::signum::Signum;

/// `sa_handler == SIG_DFL`.
pub const SIG_DFL: u64 = 0;
/// `sa_handler == SIG_IGN`.
pub const SIG_IGN: u64 = 1;
/// `SA_NOCLDWAIT` (`<asm-generic/signal.h>`): never leave a zombie.
pub const SA_NOCLDWAIT: u64 = 0x0000_0002;

/// The reaping parent's `SIGCHLD` disposition (Linux
/// `psig->action[SIGCHLD-1].sa`).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ParentSigchld {
    pub handler: u64,
    pub flags:   u64,
}

impl ParentSigchld {
    /// Untouched disposition — a plain `SIG_DFL` with no flags. # C: O(1)
    pub const fn default_action() -> Self { Self { handler: SIG_DFL, flags: 0 } }

    /// POSIX auto-reap request: `SIG_IGN` or `SA_NOCLDWAIT`. # C: O(1)
    pub const fn discards_children(&self) -> bool {
        self.handler == SIG_IGN || self.flags & SA_NOCLDWAIT != 0
    }
}

/// What the exiting task owes its parent.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ExitNotify {
    /// Signal to post to the real parent, `None` for a silent exit.
    pub signal: Option<u32>,
    /// Release immediately instead of parking a `wait4`-reapable zombie.
    pub autoreap: bool,
    /// Wake a `wait4`-blocked parent even when no signal is posted, so it can
    /// re-evaluate and return `ECHILD` (Linux `__wake_up_parent`).
    pub wake_parent: bool,
}

/// Linux `exit_notify` for an untraced task, folded together with
/// `do_notify_parent`'s autoreap answer.
///
/// * a non-leader thread never notifies and never leaves a zombie
///   (`autoreap = true`, "untraced sub-thread");
/// * a leader with live siblings notifies nothing yet — it stays a deferred
///   zombie until the group empties (`thread_group_empty(tsk)` is false);
/// * a leader of an empty group notifies `exit_signal`, and autoreaps when
///   that signal is `SIGCHLD` and the parent discards children.
///
/// `exit_signal` is the `clone(2)`-selected notification signal, `None` for
/// `CLONE_THREAD` / a `clone` that asked for no notification.
/// # C: O(1)
pub const fn exit_notify(
    is_group_leader: bool,
    thread_group_empty: bool,
    exit_signal: Option<u32>,
    parent: ParentSigchld,
) -> ExitNotify {
    if !is_group_leader {
        return ExitNotify { signal: None, autoreap: true, wake_parent: false };
    }
    if !thread_group_empty {
        return ExitNotify { signal: None, autoreap: false, wake_parent: false };
    }
    let Some(sig) = exit_signal else {
        // `do_notify_parent` rejects an invalid signal and returns false, so
        // the zombie stays for `wait4(__WALL)`.
        return ExitNotify { signal: None, autoreap: false, wake_parent: false };
    };
    if sig != Signum::Sigchld as u32 || !parent.discards_children() {
        return ExitNotify { signal: Some(sig), autoreap: false, wake_parent: true };
    }
    let signal = if parent.handler == SIG_IGN { None } else { Some(sig) };
    ExitNotify { signal, autoreap: true, wake_parent: true }
}
