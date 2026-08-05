// One rule every
// interrupted socket wait uses:
//
//     /* Alas, with timeout socket operations are not restartable.
//      * Compare this to poll().
//      */
//     static inline int sock_intr_errno(long timeo)
//     {
//         return timeo == MAX_SCHEDULE_TIMEOUT ? -ERESTARTSYS : -EINTR;
//     }
//
// Every blocking socket path routes its interrupted exit through it:
// `__skb_wait_for_more_packets` (`net/core/datagram.c:128`), `tcp_recvmsg_locked`
// (`net/ipv4/tcp.c:2784`), `sk_stream_wait_memory` (`net/core/stream.c:184`),
// `sock_alloc_send_pskb` (`net/core/sock.c:3010`), `inet_wait_for_connect`
// applies to every blocking INET, AF_UNIX, VSOCK, and netlink socket path.
//
// ~30 oxide sites each hard-coded `Eintr`, which is right ONLY for the
// SO_RCVTIMEO/SO_SNDTIMEO case and drops the restart for every untimed wait.

use crate::NetError;

/// Linux `MAX_SCHEDULE_TIMEOUT` as this kernel spells it: waits carry an
/// ABSOLUTE monotonic deadline in ns and reserve `0` for "no timeout", where
/// Linux reserves `MAX_SCHEDULE_TIMEOUT`.
pub const NO_TIMEOUT: u64 = 0;

/// Which code an interrupted socket wait reports.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SockIntr {
    /// No SO_{RCV,SND}TIMEO — the call is restartable.
    Restartsys,
    /// A socket timeout was set, so the remaining time cannot be carried
    /// across a restart and the call is not restartable.
    Eintr,
}

/// Linux `sock_intr_errno(timeo)`.
/// # C: O(1)
pub const fn sock_intr(deadline_ns: u64) -> SockIntr {
    if deadline_ns == NO_TIMEOUT { SockIntr::Restartsys } else { SockIntr::Eintr }
}

impl SockIntr {
    /// This verdict as a `NetError`. # C: O(1)
    pub const fn net(self) -> NetError {
        match self { SockIntr::Restartsys => NetError::Erestartsys, SockIntr::Eintr => NetError::Eintr }
    }

    /// This verdict as a `VfsError`, for the socket paths reached through the
    /// VFS `read`/`write` file ops. # C: O(1)
    pub const fn vfs(self) -> vfs::VfsError {
        match self {
            SockIntr::Restartsys => vfs::VfsError::Erestartsys,
            SockIntr::Eintr => vfs::VfsError::Eintr,
        }
    }
}

/// A SO_{RCV,SND}TIMEO value in ns as the ABSOLUTE monotonic deadline the wait
/// sites compare against, preserving `0` = unset so it reaches [`sock_intr`] as
/// [`NO_TIMEOUT`] — Linux's `MAX_SCHEDULE_TIMEOUT`. One owner, so the families
/// that plumb these options cannot each invent their own conversion.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn deadline_from_timeo(timeo_ns: u64) -> u64 {
    if timeo_ns == NO_TIMEOUT { return NO_TIMEOUT; }
    crate::sock_io::monotonic_ns_safe().saturating_add(timeo_ns).max(1)
}

/// Hosted builds have no monotonic source; an unset timeout is the only
/// reachable state there. # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub fn deadline_from_timeo(_timeo_ns: u64) -> u64 { NO_TIMEOUT }

/// `sock_intr_errno` straight to a `NetError`. # C: O(1)
pub const fn sock_intr_net(deadline_ns: u64) -> NetError { sock_intr(deadline_ns).net() }

/// `sock_intr_errno` straight to a `VfsError`. # C: O(1)
pub const fn sock_intr_vfs(deadline_ns: u64) -> vfs::VfsError { sock_intr(deadline_ns).vfs() }

/// What an interruptible socket data wait does next once the queue cannot make
/// progress. Kept out of any target-gated module so the ladder is decided in
/// ONE tested place instead of once per `#[cfg]` arm.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum WaitVerdict {
    /// Direction is shut down; no amount of waiting can admit the transfer.
    Shutdown,
    /// Caller asked not to block.
    NoWait,
    /// A signal is deliverable, so the wait ends with the restart-or-EINTR
    /// verdict [`sock_intr`] picks from the wait's deadline.
    Interrupted(SockIntr),
    /// Nothing forbids sleeping: park on the socket's wait list.
    Park,
}

/// What an empty accept queue does before its family-specific wait is armed.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AcceptWaitVerdict {
    /// The caller may not block, or its receive timeout has expired.
    Eagain,
    /// A deliverable signal interrupts the wait with the deadline's verdict.
    Interrupted(SockIntr),
    /// The caller must arm its listener-specific wait and retry.
    Park,
}

/// Empty-queue accept ladder: O_NONBLOCK precedes a signal, a signal precedes
/// SO_RCVTIMEO expiry, and only the remaining case parks. # C: O(1)
pub const fn accept_wait_verdict(nonblock: bool, signal_pending: bool, timed_out: bool,
                                 deadline_ns: u64) -> AcceptWaitVerdict
{
    if nonblock { return AcceptWaitVerdict::Eagain; }
    if signal_pending { return AcceptWaitVerdict::Interrupted(sock_intr(deadline_ns)); }
    if timed_out { return AcceptWaitVerdict::Eagain; }
    AcceptWaitVerdict::Park
}

/// Ladder every interruptible socket data wait follows before it sleeps: a
/// shut direction outranks everything (the transfer can never be admitted), a
/// non-blocking caller never sleeps, and a deliverable signal ends the wait
/// before it parks. # C: O(1)
pub const fn wait_verdict(shut: bool, nonblock: bool, signal_pending: bool, deadline_ns: u64)
    -> WaitVerdict
{
    if shut { return WaitVerdict::Shutdown; }
    if nonblock { return WaitVerdict::NoWait; }
    if signal_pending { return WaitVerdict::Interrupted(sock_intr(deadline_ns)); }
    WaitVerdict::Park
}

/// Whether the calling task has a signal that would interrupt a sleep.
/// # C: O(pending sets)
#[cfg(target_os = "oxide-kernel")]
pub fn signal_pending_self() -> bool { sched::live::deliverable_signals_self() != 0 }

/// Hosted builds have no task carrying signals, so no wait is interruptible.
/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub fn signal_pending_self() -> bool { false }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_untimed_wait_is_restartable() {
        // `timeo == MAX_SCHEDULE_TIMEOUT` — a plain blocking recv/send/connect
        // with no SO_RCVTIMEO/SO_SNDTIMEO.
        assert_eq!(sock_intr(NO_TIMEOUT), SockIntr::Restartsys);
        assert_eq!(sock_intr_net(NO_TIMEOUT), NetError::Erestartsys);
        assert_eq!(sock_intr_vfs(NO_TIMEOUT), vfs::VfsError::Erestartsys);
    }

    #[test]
    fn a_timed_wait_is_not_restartable() {
        // "Alas, with timeout socket operations are not restartable."
        for dl in [1u64, 1_000, u64::MAX] {
            assert_eq!(sock_intr(dl), SockIntr::Eintr, "deadline={dl}");
            assert_eq!(sock_intr_net(dl), NetError::Eintr);
            assert_eq!(sock_intr_vfs(dl), vfs::VfsError::Eintr);
        }
    }

    #[test]
    fn every_socket_family_now_supplies_a_real_deadline() {
        // F752 plumbed SO_{RCV,SND}TIMEO for AF_VSOCK and netlink, so the
        // `sock_intr_untimed_family_*` markers B1447 added are gone: no caller
        // depends on a timeout field being ABSENT any more. An unset timeout
        // still reaches here as NO_TIMEOUT, which is the correct
        // `MAX_SCHEDULE_TIMEOUT` reading rather than a standing assumption.
        assert_eq!(sock_intr_vfs(NO_TIMEOUT), vfs::VfsError::Erestartsys);
        assert_eq!(sock_intr_net(NO_TIMEOUT), NetError::Erestartsys);
    }

    #[test]
    fn a_shut_direction_outranks_every_other_wait_reason() {
        // EPIPE is reported even for a non-blocking caller with a signal
        // queued: the transfer can never be admitted, so there is no wait to
        // interrupt and nothing for a retry to accomplish.
        for nonblock in [false, true] {
            for signal in [false, true] {
                assert_eq!(wait_verdict(true, nonblock, signal, NO_TIMEOUT),
                    WaitVerdict::Shutdown, "nonblock={nonblock} signal={signal}");
            }
        }
    }

    #[test]
    fn a_non_blocking_caller_reports_eagain_even_with_a_signal_queued() {
        assert_eq!(wait_verdict(false, true, true, NO_TIMEOUT), WaitVerdict::NoWait);
        assert_eq!(wait_verdict(false, true, false, 1_000), WaitVerdict::NoWait);
    }

    #[test]
    fn a_blocking_wait_with_a_signal_takes_the_deadlines_restart_verdict() {
        // Untimed: restartable. Timed: the remaining time cannot be carried
        // across a restart, so EINTR.
        assert_eq!(wait_verdict(false, false, true, NO_TIMEOUT),
            WaitVerdict::Interrupted(SockIntr::Restartsys));
        assert_eq!(wait_verdict(false, false, true, 1_000),
            WaitVerdict::Interrupted(SockIntr::Eintr));
    }

    #[test]
    fn accept_empty_queue_uses_the_linux_break_order() {
        assert_eq!(accept_wait_verdict(true, true, true, NO_TIMEOUT), AcceptWaitVerdict::Eagain);
        assert_eq!(accept_wait_verdict(false, true, true, NO_TIMEOUT),
                   AcceptWaitVerdict::Interrupted(SockIntr::Restartsys));
        assert_eq!(accept_wait_verdict(false, true, true, 1),
                   AcceptWaitVerdict::Interrupted(SockIntr::Eintr));
        assert_eq!(accept_wait_verdict(false, false, true, 1), AcceptWaitVerdict::Eagain);
        assert_eq!(accept_wait_verdict(false, false, false, NO_TIMEOUT), AcceptWaitVerdict::Park);
    }

    #[test]
    fn an_uninterrupted_blocking_wait_parks() {
        assert_eq!(wait_verdict(false, false, false, NO_TIMEOUT), WaitVerdict::Park);
        assert_eq!(wait_verdict(false, false, false, 1_000), WaitVerdict::Park);
    }

    #[test]
    fn a_hosted_task_never_reports_a_pending_signal() {
        // Hosted builds carry no task state; a hosted wait therefore parks
        // rather than inventing an interrupt the kernel build would not see.
        assert!(!signal_pending_self());
    }

    #[test]
    fn the_restart_code_is_linux_erestartsys_not_an_errno() {
        // 512 is `ERESTARTSYS`; it must never collide with a real errno, and
        // the syscall tail folds it to EINTR only when no restart happens.
        assert_eq!(vfs::VfsError::Erestartsys as i32, 512);
        assert_ne!(vfs::VfsError::Erestartsys as i32, vfs::VfsError::Eintr as i32);
    }
}
