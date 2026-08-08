// Receive admission and protocol selection for one message.
//
// The security decision and the choice of protocol owner are one step, and the
// route is only obtainable from it: a receive cannot reach a protocol without
// having been admitted, because there is no other way to name where it should
// go. Keeping both here also keeps the receive shim in `recvmsg::dispatch` a
// pin-and-route with no policy of its own.

use net::socket_security::MsgSock;
use net::uapi::MSG_ERRQUEUE;

/// Concrete socket family a pinned receive target carries.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum RecvFamily {
    /// The shared internet-socket object, which also carries AF_UNIX.
    Inet { unix: bool },
    Netlink,
    Vsock,
}

/// Protocol owner one admitted receive is routed to.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum RecvRoute { InetErrqueue, Inet, Unix, Netlink, Vsock }

/// Admit one receive transaction, then name its protocol owner.
///
/// The error queue is a receive on the same socket by another name, so it is
/// admitted by the same decision rather than by one of its own; only the
/// internet families keep a queue that a receive can be diverted to.
/// # C: O(1)
pub(crate) fn admit_and_route(sock: MsgSock, family: RecvFamily, flags: u64)
    -> Result<RecvRoute, i64>
{
    net::socket_security::recvmsg(sock, flags).map_err(crate::net_errno::errno_from_neterr)?;
    Ok(match family {
        RecvFamily::Netlink => RecvRoute::Netlink,
        RecvFamily::Vsock => RecvRoute::Vsock,
        RecvFamily::Inet { unix: true } => RecvRoute::Unix,
        RecvFamily::Inet { unix: false } =>
            if flags & MSG_ERRQUEUE != 0 { RecvRoute::InetErrqueue } else { RecvRoute::Inet },
    })
}

#[cfg(all(test, not(target_os = "oxide-kernel")))]
#[path = "recv_admit/tests.rs"]
mod tests;
