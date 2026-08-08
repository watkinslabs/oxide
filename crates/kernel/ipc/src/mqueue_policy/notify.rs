//! `mq_notify(2)`'s sigevent gate: validates a registration request and
//! decides register/deregister/no-op against the currently-registered owner.

use syscall::errno::Errno;

/// `SIGEV_SIGNAL`.
pub const SIGEV_SIGNAL: i32 = 0;
/// `SIGEV_NONE`.
pub const SIGEV_NONE: i32 = 1;
/// `SIGEV_THREAD`.
pub const SIGEV_THREAD: i32 = 2;
/// `_NSIG` — the inclusive ceiling a signal number must fall within.
pub const NSIG: i32 = 64;

/// How a registered notification fires.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NotifyKind {
    /// `SIGEV_NONE`: registration is real (it holds the queue's single slot,
    /// so a second `mq_notify` is `EBUSY`) but delivery sends nothing and
    /// still unregisters.
    None,
    /// `SIGEV_SIGNAL`: queue `signo` with `si_code == SI_MESGQ`. `signo == 0`
    /// is accepted and delivers nothing.
    Signal(u32),
    /// `SIGEV_THREAD`: `sigev_signo` is a NETLINK SOCKET FD and
    /// `sigev_value.sival_ptr` points at a `NOTIFY_COOKIE_LEN` cookie the
    /// kernel echoes back on that socket when the queue goes non-empty.
    Thread,
}

/// Validation of a non-NULL `struct sigevent`:
///
/// * `sigev_notify` outside `{SIGEV_NONE, SIGEV_SIGNAL, SIGEV_THREAD}` → `EINVAL`
/// * `SIGEV_SIGNAL` with an out-of-range `sigev_signo` → `EINVAL`.
///   The validity check treats the signal number as unsigned, so a negative
///   `sigev_signo` fails, while `0` PASSES — signal 0 is accepted and simply
///   skips the send at delivery time.
/// # C: O(1)
pub fn notify_check(sigev_notify: i32, sigev_signo: i32) -> Result<NotifyKind, Errno> {
    match sigev_notify {
        SIGEV_NONE => Ok(NotifyKind::None),
        SIGEV_THREAD => Ok(NotifyKind::Thread),
        SIGEV_SIGNAL => {
            if sigev_signo < 0 || sigev_signo > NSIG { return Err(Errno::Einval); }
            Ok(NotifyKind::Signal(sigev_signo as u32))
        }
        _ => Err(Errno::Einval),
    }
}

/// The registration decision, as a
/// verdict over the currently-registered owner:
///
/// * NULL notification deregisters ONLY when the caller's thread group already
///   owns the registration; another process's `mq_notify(fd, NULL)` is a
///   silent no-op returning 0 — it must NOT steal the
///   slot.
/// * a non-NULL notification when any owner is registered is `EBUSY`, even
///   when the caller is that owner.
/// # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NotifyAction { Register, Deregister, NoOp }

/// # C: O(1)
pub fn notify_action(registering: bool, owner_tgid: Option<u32>, caller_tgid: u32)
    -> Result<NotifyAction, Errno>
{
    if !registering {
        return Ok(if owner_tgid == Some(caller_tgid) { NotifyAction::Deregister }
                  else { NotifyAction::NoOp });
    }
    if owner_tgid.is_some() { return Err(Errno::Ebusy); }
    Ok(NotifyAction::Register)
}
