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

/// `sock_intr_errno` for a socket family that plumbs **no** SO_RCVTIMEO /
/// SO_SNDTIMEO at all, so its waits are structurally untimed and the answer is
/// unconditionally `-ERESTARTSYS`.
///
/// # This is conditional correctness — read before changing a socket option
///
/// Callers of this are correct ONLY while their family has no timeout fields.
/// Linux DOES honour both options on these paths:
/// `af_vsock.c:2267` (send) and `:2384` (recv) take `sock_{snd,rcv}timeo`, and
/// netlink receives via `skb_recv_datagram` -> `__skb_wait_for_more_packets`
/// (`net/core/datagram.c:128`). The moment SO_{RCV,SND}TIMEO is plumbed for
/// AF_VSOCK or netlink — a perfectly reasonable change made in socket-option
/// code, nowhere near these waits — every caller of this function silently
/// starts reporting ERESTARTSYS where Linux reports EINTR, and a timed wait
/// will wrongly restart instead of surfacing the interruption.
///
/// **When you add those options: delete this call and pass the real deadline
/// to [`sock_intr_vfs`] / [`sock_intr_net`].** The named call sites are
/// `net::vsock_socket` (stream recv), `net::vsock_socket::io` (seqpacket recv,
/// send) and `netlink::inode` (recv).
///
/// AF_VSOCK *connect* is deliberately NOT one of them: it waits on
/// `vsk->connect_timeout`, which is always finite (`af_vsock.c:1777`, default
/// `2*HZ`, and `:2095-2099` forces a 0 back to the default), so Linux gives it
/// `-EINTR` (`af_vsock.c:1829`).
/// # C: O(1)
pub const fn sock_intr_untimed_family_vfs() -> vfs::VfsError { sock_intr_vfs(NO_TIMEOUT) }

/// [`sock_intr_untimed_family_vfs`] for callers on the `NetError` side. Read
/// that function's contract before using this.
/// # C: O(1)
pub const fn sock_intr_untimed_family_net() -> NetError { sock_intr_net(NO_TIMEOUT) }

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
    fn the_untimed_family_helper_is_exactly_the_no_timeout_verdict() {
        // It exists to be greppable and self-documenting at the call site, not
        // to behave differently — if these ever diverge the marker is a lie.
        assert_eq!(sock_intr_untimed_family_vfs(), sock_intr_vfs(NO_TIMEOUT));
        assert_eq!(sock_intr_untimed_family_net(), sock_intr_net(NO_TIMEOUT));
        assert_eq!(sock_intr_untimed_family_vfs(), vfs::VfsError::Erestartsys);
        assert_eq!(sock_intr_untimed_family_net(), NetError::Erestartsys);
    }

    #[test]
    fn the_restart_code_is_linux_erestartsys_not_an_errno() {
        // 512 is `ERESTARTSYS`; it must never collide with a real errno, and
        // the syscall tail folds it to EINTR only when no restart happens.
        assert_eq!(vfs::VfsError::Erestartsys as i32, 512);
        assert_ne!(vfs::VfsError::Erestartsys as i32, vfs::VfsError::Eintr as i32);
    }
}
