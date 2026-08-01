// The transmit half of level 17: the only part that needs the live UDP send
// path, so the only part that cannot be exercised hosted. Every decision it
// acts on is made in `table`, `cork`, or `segment`.
#![cfg(target_os = "oxide-kernel")]

use crate::NetError;
use crate::sock::{InetSocket, RemoteAddr};

use super::cork::{self, CorkAction};
use super::state::{CorkDest, CorkPending};
use super::table::{SetEffect, set};

/// The pinned destination an explicit `sendto` address names, if any. An
/// address that names no IP destination cannot pin a cork. # C: O(1)
pub fn cork_dest(dest: &Option<RemoteAddr>) -> Result<Option<CorkDest>, NetError> {
    match dest {
        None => Ok(None),
        Some(RemoteAddr::Inet { ip, port }) => Ok(Some(CorkDest::V4 { ip: *ip, port: *port })),
        Some(RemoteAddr::Inet6 { ip, port, scope_id }) =>
            Ok(Some(CorkDest::V6 { ip: *ip, port: *port, scope_id: *scope_id })),
        Some(RemoteAddr::Unspec) | Some(RemoteAddr::Unix(_)) => Err(NetError::Einval),
    }
}

/// Transmit one accumulated cork as a single datagram. # C: O(pending bytes)
pub fn flush(sock: &InetSocket, pending: CorkPending) -> Result<usize, NetError> {
    match pending.dest {
        CorkDest::V4 { ip, port } => crate::sock::socket_sendto(sock, ip, port, &pending.payload),
        CorkDest::V6 { ip, port, scope_id } =>
            crate::sock_v6::sendto_v6(sock, ip, port, scope_id, &pending.payload),
    }
}

/// The `sendto` interception a UDP socket runs before it builds a datagram.
/// `Ok(None)` means the caller sends normally. # C: O(payload + pending bytes)
pub fn intercept(sock: &InetSocket, dest: &Option<RemoteAddr>, payload: &[u8])
    -> Result<Option<usize>, NetError>
{
    match cork::decide(sock, cork_dest(dest)?, payload)? {
        CorkAction::Passthrough => Ok(None),
        CorkAction::Held(n) => Ok(Some(n)),
        CorkAction::Push { pending, accepted } => { flush(sock, pending)?; Ok(Some(accepted)) }
    }
}

/// `setsockopt(fd, IPPROTO_UDP, ...)` work function: validate, store, and run
/// whatever transmit-side effect the new value implies. # C: O(pending bytes)
pub fn setsockopt(sock: &InetSocket, optname: u64, val: i32) -> Result<(), NetError> {
    match set(&sock.opts.udp, optname, val)? {
        SetEffect::None => Ok(()),
        SetEffect::Push => {
            // A push that cannot be routed still clears the cork, matching a
            // send whose datagram is dropped: the option itself succeeded.
            if let Some(pending) = cork::take(sock) { let _ = flush(sock, pending); }
            Ok(())
        }
    }
}
