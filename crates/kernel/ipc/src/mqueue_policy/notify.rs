//! `mq_notify(2)`'s sigevent gate — Linux `do_mq_notify`
//! (`ipc/mqueue.c:1278-1290`) and `__do_notify` (`:777-836`).

use syscall::errno::Errno;

/// `SIGEV_SIGNAL` (`include/uapi/asm-generic/siginfo.h`).
pub const SIGEV_SIGNAL: i32 = 0;
/// `SIGEV_NONE`.
pub const SIGEV_NONE: i32 = 1;
/// `SIGEV_THREAD`.
pub const SIGEV_THREAD: i32 = 2;
/// `_NSIG` — `valid_signal()`'s inclusive ceiling (`include/linux/signal.h`).
pub const NSIG: i32 = 64;

/// How a registered notification fires.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NotifyKind {
    /// `SIGEV_NONE`: registration is real (it holds the queue's single slot,
    /// so a second `mq_notify` is `EBUSY`) but delivery sends nothing and
    /// still unregisters (`ipc/mqueue.c:787-788, :829-833`).
    None,
    /// `SIGEV_SIGNAL`: queue `signo` with `si_code == SI_MESGQ`. `signo == 0`
    /// is accepted by Linux and delivers nothing (`mqueue.c:793-795`).
    Signal(u32),
    /// `SIGEV_THREAD`: `sigev_signo` is a NETLINK SOCKET FD and
    /// `sigev_value.sival_ptr` points at a `NOTIFY_COOKIE_LEN` cookie the
    /// kernel echoes back on that socket when the queue goes non-empty.
    Thread,
}

/// Linux `do_mq_notify`'s validation of a non-NULL `struct sigevent`
/// (`ipc/mqueue.c:1278-1290`):
///
/// * `sigev_notify` outside `{SIGEV_NONE, SIGEV_SIGNAL, SIGEV_THREAD}` → `EINVAL`
/// * `SIGEV_SIGNAL` with `!valid_signal(sigev_signo)` → `EINVAL`.
///   `valid_signal` takes an `unsigned long`, so a negative `sigev_signo`
///   fails, while `0` PASSES — Linux accepts signal 0 and simply skips the
///   send at delivery time.
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

/// Linux `do_mq_notify`'s registration arm (`ipc/mqueue.c:1336-1367`), as a
/// verdict over the currently-registered owner:
///
/// * NULL notification deregisters ONLY when the caller's thread group already
///   owns the registration; another process's `mq_notify(fd, NULL)` is a
///   silent no-op returning 0 (`mqueue.c:1336-1341`) — it must NOT steal the
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
