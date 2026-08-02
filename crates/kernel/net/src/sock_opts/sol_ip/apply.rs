// Applying an admitted `IPPROTO_IP` result to the socket AND to whatever
// transport state derives from it. Storage alone is not application: the
// sticky option area is network-protocol overhead, so installing one has to
// re-derive the MSS of a connection already sending under the old length.

use alloc::sync::Arc;

use crate::ipv4_options::Compiled;
use crate::sock::{InetSocket, SockKind};

/// Install a compiled `IP_OPTIONS` area on the socket, then re-derive the
/// send MSS of a connection that is already established: the area rides ahead
/// of the TCP header on every segment, so the connection has that many fewer
/// bytes of payload per path MTU. # C: O(optlen + route lookup)
pub fn install_options(sock: &Arc<InetSocket>, compiled: Compiled) {
    sock.opts.ip.set_options(compiled);
    let entry = match &*sock.kind.lock() {
        SockKind::TcpConn(entry) => Some(entry.clone()),
        _ => None,
    };
    if let Some(entry) = entry { crate::sock::stack().tcp_sync_mss(&entry); }
}
