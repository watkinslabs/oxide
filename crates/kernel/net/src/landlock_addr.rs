// Address-driven Landlock checks the socket layer performs.
//
// `landlock_glue` owns the running task's domain and the abstract-namespace
// scope. This file owns the two checks that need an address in hand: the port
// right a datagram send to an explicit recipient asks for, and the resolve
// right a pathname AF_UNIX address asks for. Every verdict is one call into the
// `landlock` crate; what lives here is only the socket-layer knowledge that
// call needs — which transport a socket carries, and which domain published the
// address being resolved.

extern crate alloc;

use alloc::sync::Arc;

use landlock::netcheck::{self, Op, Proto, Verdict};
use landlock::Domain;
use syscall::errno::Errno;

use crate::landlock_glue::current_domain;
use crate::NetError;

/// Socket-layer error for a sandbox verdict. A denial is `EACCES`; the address
/// classifier's own argument errors keep their identity.
/// # C: O(1)
fn net_error(e: Errno) -> NetError {
    match e {
        Errno::Einval => NetError::Einval,
        Errno::Eafnosupport => NetError::Eafnosupport,
        _ => NetError::Eacces,
    }
}

/// Transport of an internet socket, for port-rule purposes.
/// # C: O(1)
pub fn sock_proto(sock: &crate::sock::InetSocket) -> Proto {
    match *sock.kind.lock() {
        crate::sock::SockKind::TcpInit
        | crate::sock::SockKind::TcpListener(_)
        | crate::sock::SockKind::TcpConn(_) => Proto::Tcp,
        crate::sock::SockKind::Udp => Proto::Udp,
        _ => Proto::Other,
    }
}

/// Whether `client` may name `bytes` for `op` on a `proto` socket.
///
/// A domain that filters none of the right this operation asks for is left
/// entirely alone — the address is not even parsed, so an unrelated sandbox
/// cannot turn a send into an argument error it would not otherwise have
/// produced.
/// # C: O(N_layers × N_rules)
pub fn addr_verdict(client: Option<&Arc<Domain>>, proto: Proto, op: Op, bytes: &[u8],
                    sock_family: u16) -> Result<(), NetError>
{
    let d = match client { Some(d) => d, None => return Ok(()) };
    let req = match if op == Op::Bind { netcheck::bind_request(proto) }
                    else { netcheck::connect_request(proto) } {
        Some(r) => r, None => return Ok(()),
    };
    if !d.handles_net(req) { return Ok(()); }
    match netcheck::classify(req, op, netcheck::Addr::parse(bytes), sock_family) {
        Verdict::Allow => Ok(()),
        Verdict::Fail(e) => Err(net_error(e)),
        Verdict::CheckPort(p) => d.check_net(p, req).map_err(net_error),
    }
}

/// Gate a datagram send that names an explicit recipient: settling a remote
/// port through `sendto`/`sendmsg` reaches the same endpoint a connect would,
/// so it asks for the same right. A send that names no address settles no port
/// and has nothing to check.
/// # C: O(N_layers × N_rules)
pub fn check_send_addr(sock: &crate::sock::InetSocket, name: &[u8]) -> Result<(), NetError> {
    addr_verdict(current_domain().as_ref(), sock_proto(sock), Op::Send, name,
                 sock.family.load(core::sync::atomic::Ordering::Acquire))
}

/// Domain that published the pathname socket bound at `addr`. The outer `None`
/// means nothing is bound there at all; an inner `None` is a server published
/// outside every domain. Pathname bindings are filesystem-global, so the lookup
/// needs no namespace.
/// # C: O(log N_bindings)
pub fn pathname_unix_owner(addr: &crate::UnixAddr) -> Option<Option<Arc<Domain>>> {
    if !addr.is_pathname() { return None; }
    let reg = &crate::sock::UNIX_REGISTRY;
    match reg.lookup_listener_addr(addr) {
        Some(l) => Some(l.owner_domain()),
        None => reg.dgram_lookup_addr(addr).map(|q| q.owner_domain()),
    }
}

/// Whether `client` may resolve the pathname AF_UNIX socket found at `path`,
/// for `connect(2)` and for a send that names an explicit recipient.
///
/// A server published inside the client's own domain stays reachable, exactly
/// as the scope flags treat abstract names; every other layer must be satisfied
/// by a hierarchy rule on the socket's own path.
///
/// An address nobody has bound is not a denial — the operation fails on its own
/// terms, and reporting a sandbox denial for a name with no server would leak
/// which names are in use. Abstract addresses never reach here: they carry no
/// filesystem object to anchor a rule on and are governed by the scope check in
/// `landlock_glue` instead.
/// # C: O(depth × N_layers × N_rules)
pub fn unix_resolve_verdict(client: Option<&Arc<Domain>>, path: &vfs::VfsPath,
                            addr: &crate::UnixAddr) -> Result<(), NetError>
{
    let d = match client { Some(d) => d, None => return Ok(()) };
    let owner = match pathname_unix_owner(addr) { Some(o) => o, None => return Ok(()) };
    d.check_unix_resolve(path, owner.as_ref()).map_err(net_error)
}

/// Same check for the running task. # C: O(depth × N_layers × N_rules)
pub fn check_unix_resolve(path: &vfs::VfsPath, addr: &crate::UnixAddr) -> Result<(), NetError> {
    unix_resolve_verdict(current_domain().as_ref(), path, addr)
}

#[cfg(test)]
#[path = "landlock_addr/tests.rs"]
mod tests;
