// Canonical security boundary for one socket message transaction.
//
// Every send and every receive asks exactly one question, in exactly one place:
// this file. It composes the two modules that answer it — the sandbox, which
// owns the destination-port rights a send may settle, and the namespace-scoped
// module registry, which owns the generic per-operation verdict — so that a
// call site never re-implements either and the two can never disagree.
//
// The composition order is the module order: the sandbox is consulted first, so
// its denial is the one reported when both would refuse. Callers supply the
// sandbox domain rather than the boundary reading it, which keeps the whole
// decision a pure function of its inputs and lets one syscall pin one domain
// snapshot across a batch.

extern crate alloc;

use alloc::sync::Arc;

use landlock::netcheck::{Op, Proto};
use landlock::Domain;

use crate::NetError;

/// Socket identity one message hook needs: the namespace and family the generic
/// module registry is keyed by, and the transport the port rules are keyed by.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MsgSock {
    pub namespace: u64,
    pub family: u16,
    pub proto: Proto,
}

/// Describe one internet-family socket to the message hooks. # C: O(1)
pub fn inet(sock: &crate::sock::InetSocket) -> MsgSock {
    MsgSock {
        namespace: sock.net_ns(),
        family: sock.family.load(core::sync::atomic::Ordering::Acquire),
        proto: crate::landlock_addr::sock_proto(sock),
    }
}

/// Describe one socket that carries no port rules — every family outside the
/// internet transports the sandbox writes rules for. # C: O(1)
pub fn other(namespace: u64, family: u16) -> MsgSock {
    MsgSock { namespace, family, proto: Proto::Other }
}

/// The sandbox module's send hook.
///
/// A Fast Open send that names an address opens the connection its payload
/// rides, so it asks for the connect right on that address before anything
/// else. Past that, only a datagram transport carries send rights: a stream
/// send settles no new port, and a family with no port rules is left alone. A
/// send that names no address settles nothing and is not checked.
/// # C: O(N_layers × N_rules)
#[inline(never)]
fn sandbox_send(domain: Option<&Arc<Domain>>, sock: MsgSock, name: Option<&[u8]>, flags: u64)
    -> Result<(), NetError>
{
    if domain.is_none() { return Ok(()); }
    if flags & crate::uapi::MSG_FASTOPEN != 0 && sock.proto == Proto::Tcp {
        if let Some(name) = name {
            crate::landlock_addr::addr_verdict(domain, Proto::Tcp, Op::Connect, name,
                                               sock.family)?;
        }
    }
    if sock.proto != Proto::Udp { return Ok(()); }
    let Some(name) = name else { return Ok(()); };
    crate::landlock_addr::addr_verdict(domain, Proto::Udp, Op::Send, name, sock.family)
}

/// Whether this task may transmit one message on this socket.
///
/// The one send-side security decision. `name` is the kernel-owned destination
/// this message names, or `None` for a send that rides the socket's existing
/// association.
/// `#[inline(never)]`: the sandbox verdict and the registry lookup each
/// materialise their own working set, and every send entry point calls this
/// ahead of the family work whose frame it would otherwise sum with.
/// # C: O(N_layers × N_rules)
#[inline(never)]
pub fn sendmsg(domain: Option<&Arc<Domain>>, sock: MsgSock, name: Option<&[u8]>, flags: u64)
    -> Result<(), NetError>
{
    sandbox_send(domain, sock, name, flags)?;
    crate::security_admission::check(sock.namespace, sock.family,
                                     security::network::Operation::Send)
}

/// Whether this task may consume one message from this socket.
///
/// The one receive-side security decision. The sandbox writes no receive rules —
/// a queued message named its destination when it was sent — so this is the
/// generic module verdict alone, asked once per receive transaction rather than
/// once per queue poll.
/// # C: O(1)
pub fn recvmsg(sock: MsgSock, _flags: u64) -> Result<(), NetError> {
    crate::security_admission::check(sock.namespace, sock.family,
                                     security::network::Operation::Receive)
}

#[cfg(test)]
#[path = "socket_security/tests.rs"]
mod tests;
