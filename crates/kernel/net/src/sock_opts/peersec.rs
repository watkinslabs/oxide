// Which peer label a socket reports for `SO_PEERSEC`.
//
// No target gate: the decision must run under hosted tests. The syscall shim
// above this only moves bytes (`docs/53`), so every choice about WHICH label a
// socket reports — and whether it reports one at all — is made here.

use crate::sock::{InetSocket, SockKind};
use crate::sock_opts::sol_socket::varlen::reports_peer_label;

/// The peer label this socket recorded, or `None` when its class reports none.
/// # C: O(1)
///
/// A socket bound to an AF_UNIX pair reads the OPPOSITE end's recorded label.
/// The pair is where a connection's labelling lives because the server end
/// exists there before any socket is accepted onto it, so a socket cannot be the
/// only home for the label its peer must read.
///
/// Every other socket recorded nothing and reports the labelling module's
/// "unlabelled" — a real label, not the absence of one. Reporting nothing there
/// would make an unconnected socket indistinguishable from one on a kernel where
/// nothing labels sockets at all.
pub fn recorded_peer_label(sock: &InetSocket) -> Option<u32> {
    use core::sync::atomic::Ordering;
    let family = u32::from(sock.family.load(Ordering::Acquire));
    // Both helpers take the kind lock themselves, so they run before it is held
    // below.
    let socket_type = crate::sock_opts::identity::socket_type(sock) as u32;
    let protocol = crate::sock_opts::identity::socket_protocol(sock) as u32;
    if !reports_peer_label(family, socket_type, protocol) { return None; }
    Some(match &*sock.kind.lock() {
        SockKind::Unix(pair, end) => pair.peer_sid(*end),
        SockKind::UnixMsgPair(pair, end) => pair.peer_sid(*end),
        _ => security::network::unlabeled_socket_label(),
    })
}

#[cfg(test)]
#[path = "peersec/tests.rs"]
mod tests;
