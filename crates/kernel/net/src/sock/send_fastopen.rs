// The write that opens a fast-open connection: `MSG_FASTOPEN`, and the first
// write after a `connect` that `TCP_FASTOPEN_CONNECT` deferred.
//
// One call does what `connect` and `send` do separately, and reports one
// result for both. The blocking form is transparent — the caller gets its
// byte count and never learns whether the bytes rode the SYN or waited for
// the handshake. The non-blocking form cannot hide the difference, so it
// reports the two apart: bytes carried when the SYN took some, `EINPROGRESS`
// when it took none and the handshake is still in flight, which is exactly
// what a non-blocking `connect` would have reported on its own.
//
// Every failure of fast open itself lands on the ordinary path rather than on
// an error return: no cookie cached, a blackholed path, a cleared enable bit
// on the route — each opens the connection the three-way way. Only two
// answers are errors, and neither is a failure to fast open: a host whose
// client half is off told a program that asked for the feature by name, and a
// socket that already has a connection.

use alloc::sync::Arc;

use super::{InetSocket, NetError, RemoteAddr, SockKind};
use crate::tcp_fastopen::{self, SendAdmit};

/// Whether this socket's handshake is waiting for a write to supply its
/// payload. # C: O(1)
pub fn deferred(sock: &InetSocket) -> bool { sock.fastopen_deferred.lock().is_some() }

/// Whether a write on this socket is one of the two that open a connection.
/// # C: O(1)
pub fn opens_connection(sock: &InetSocket, msg_fastopen: bool) -> bool {
    matches!(*sock.kind.lock(), SockKind::TcpInit | SockKind::TcpConn(_))
        && (msg_fastopen || deferred(sock))
}

/// The destination a fast-open write opens to: the one it named, or the one
/// the deferred `connect` already committed. # C: O(1)
fn destination(sock: &InetSocket, dest: Option<RemoteAddr>) -> Result<RemoteAddr, NetError> {
    if let Some(addr @ (RemoteAddr::Inet { .. } | RemoteAddr::Inet6 { .. })) = dest {
        return Ok(addr);
    }
    let held = sock.fastopen_deferred.lock().ok_or(NetError::Edestaddrreq)?;
    Ok(match held.remote_ip {
        crate::IpAddr::V4(ip) => RemoteAddr::Inet { ip, port: held.remote_port },
        crate::IpAddr::V6(ip) => RemoteAddr::Inet6 {
            ip, port: held.remote_port,
            scope_id: sock.peer6_scope.load(::core::sync::atomic::Ordering::Acquire) },
    })
}

/// A socket that already has a connection has nothing left for this call to
/// open. # C: O(1)
fn already_open(sock: &InetSocket) -> Option<NetError> {
    match &*sock.kind.lock() {
        SockKind::TcpConn(entry) =>
            Some(if entry.conn.lock().state == crate::tcp_state::TcpState::Established {
                NetError::Eisconn
            } else { NetError::Ealready }),
        _ => None,
    }
}

/// Open the connection and send. # C: O(payload + RTT)
pub fn send(sock: &Arc<InetSocket>, payload: &[u8], dest: Option<RemoteAddr>, nonblock: bool)
    -> Result<usize, NetError>
{
    let bits = tcp_fastopen::enable_bits(&sock.owner.net_namespace);
    let addr_unspec = matches!(dest, Some(RemoteAddr::Unspec));
    match tcp_fastopen::admit_send(bits, addr_unspec, false) {
        SendAdmit::Open => {}
        SendAdmit::Eopnotsupp => return Err(NetError::Eopnotsupp),
        SendAdmit::Ealready => return Err(NetError::Ealready),
    }
    if let Some(error) = already_open(sock) { return Err(error); }
    let addr = destination(sock, dest)?;
    let admission = super::admit_connect(sock)?;
    let transaction = super::preflight_connect_admitted(sock, admission)?;
    let (entry, carried) = transaction.commit_write(addr, payload)?;
    if nonblock { return super::fastopen_result::nonblock_write_result(carried); }
    crate::sock_io::connect_wait_established(sock, &entry)?;
    let rest = &payload[carried..];
    if rest.is_empty() { return Ok(carried); }
    let cap = sock.opts.sndbuf.load(::core::sync::atomic::Ordering::Acquire).max(0) as usize;
    let nodelay = sock.opts.tcp_nodelay.load(::core::sync::atomic::Ordering::Acquire) != 0;
    let cork = sock.opts.tcp_cork.load(::core::sync::atomic::Ordering::Acquire) != 0;
    let sent = super::stack().tcp_send(&entry, rest, cap, nodelay, cork)?;
    super::drain_loopback();
    Ok(carried + sent)
}
