// Linux `sock_intr_errno` (`include/net/sock.h:2755-2761`) — the ONE rule every
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
// (`net/ipv4/af_inet.c:713`), `inet_csk_wait_for_connect`
// (`net/ipv4/inet_connection_sock.c:635`), `unix_stream_connect`
// (`net/unix/af_unix.c:1705`), `unix_dgram_sendmsg` (`af_unix.c:2258`),
// `unix_stream_read_generic` (`af_unix.c:2997`), `vsock_connect`
// (`net/vmw_vsock/af_vsock.c:1829`), `netlink_attachskb`
// (`net/netlink/af_netlink.c:1250`).
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
    fn the_restart_code_is_linux_erestartsys_not_an_errno() {
        // 512 is `ERESTARTSYS`; it must never collide with a real errno, and
        // the syscall tail folds it to EINTR only when no restart happens.
        assert_eq!(vfs::VfsError::Erestartsys as i32, 512);
        assert_ne!(vfs::VfsError::Erestartsys as i32, vfs::VfsError::Eintr as i32);
    }
}
