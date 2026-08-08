// AF_VSOCK send-destination admission.
//
// The two vsock personalities answer a supplied destination in opposite ways
// and neither answer is the other's: a connection-oriented socket REFUSES one,
// and the refusal names the connection state; a datagram socket REQUIRES one
// (or a connected peer) and screens its shape. One site had the connectible
// rule applied to both, keyed on the socket's outer variant rather than its
// state, so a socket mid-connect or one whose peer had already reset it
// reported "already connected".

use alloc::sync::Arc;

use crate::{Error, KResult};

/// `struct sockaddr_vm`: family, one reserved half-word, port, cid, flags,
/// then padding to the size every cast requires.
const SOCKADDR_VM_LEN: usize = 16;
const AF_VSOCK: u16 = 40;
/// `VMADDR_CID_ANY` / `VMADDR_PORT_ANY` — an address carrying either is not
/// bound, and no message may be addressed to it.
const VMADDR_ANY: u32 = u32::MAX;
/// `VMADDR_FLAG_TO_HOST` is the one flag bit a caller may set.
const VMADDR_FLAG_TO_HOST: u8 = 0x01;

fn u16_at(bytes: &[u8], at: usize) -> u16 { u16::from_ne_bytes(bytes[at..at + 2].try_into().unwrap()) }
fn u32_at(bytes: &[u8], at: usize) -> u32 { u32::from_ne_bytes(bytes[at..at + 4].try_into().unwrap()) }

/// One decoded `sockaddr_vm`. A cast that does not produce one is not an error
/// by itself: the datagram path falls back to its connected peer instead.
struct VsockAddr { port: u32, cid: u32 }

impl VsockAddr {
    /// `vsock_addr_bound`. # C: O(1)
    fn bound(&self) -> bool { self.cid != VMADDR_ANY && self.port != VMADDR_ANY }
}

/// `vsock_addr_cast` + `vsock_addr_validate`. # C: O(1)
fn cast(name: &[u8]) -> Option<VsockAddr> {
    if name.len() < SOCKADDR_VM_LEN { return None; }
    if u16_at(name, 0) != AF_VSOCK { return None; }
    if name[12] & !VMADDR_FLAG_TO_HOST != 0 { return None; }
    Some(VsockAddr { port: u32_at(name, 4), cid: u32_at(name, 8) })
}

/// Whether this endpoint has completed its handshake. Only an ESTABLISHED
/// connectible socket answers a supplied destination with EISCONN; every other
/// state — including a connect still in flight and one the peer has already
/// reset — answers EOPNOTSUPP. # C: O(1)
fn established(socket: &Arc<net::vsock_socket::VsockSocket>) -> bool {
    let Some(conn) = socket.conn() else { return false };
    let state = *conn.st.lock();
    matches!(state, net::vsock::VsockState::Connected | net::vsock::VsockState::RcvShutdown)
}

/// Admit one AF_VSOCK send destination. # C: O(1)
pub(crate) fn admit_destination(socket: &Arc<net::vsock_socket::VsockSocket>,
    name: Option<&[u8]>) -> KResult<()>
{
    if socket.is_datagram() { return admit_datagram(socket, name); }
    if name.is_none() { return Ok(()); }
    Err(if established(socket) { Error::Eisconn } else { Error::Eopnotsupp })
}

/// A datagram send resolves its destination from the supplied name when that
/// name casts, and from the connected peer otherwise. An unbound destination —
/// including the "no name and no peer" case — is EINVAL, which is the answer
/// before the transport is ever asked whether it carries datagrams.
/// # C: O(1)
fn admit_datagram(socket: &Arc<net::vsock_socket::VsockSocket>, name: Option<&[u8]>)
    -> KResult<()>
{
    if let Some(addr) = name.and_then(cast) {
        // `VMADDR_CID_ANY` names this host's own context, which is bound.
        if addr.cid == VMADDR_ANY && addr.port != VMADDR_ANY { return Ok(()); }
        return if addr.bound() { Ok(()) } else { Err(Error::Einval) };
    }
    // A connected datagram socket falls back to the peer `connect` bound;
    // an unconnected one with no usable name has no destination at all.
    if socket.conn().is_some() { Ok(()) } else { Err(Error::Einval) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn sockaddr(family: u16, port: u32, cid: u32, flags: u8) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&family.to_ne_bytes());
        out.extend_from_slice(&0u16.to_ne_bytes());
        out.extend_from_slice(&port.to_ne_bytes());
        out.extend_from_slice(&cid.to_ne_bytes());
        out.push(flags);
        while out.len() < SOCKADDR_VM_LEN { out.push(0); }
        out
    }

    #[test]
    fn a_bound_destination_casts_and_an_unbound_one_does_not() {
        assert!(cast(&sockaddr(AF_VSOCK, 1234, 3, 0)).unwrap().bound());
        assert!(!cast(&sockaddr(AF_VSOCK, VMADDR_ANY, 3, 0)).unwrap().bound());
        assert!(!cast(&sockaddr(AF_VSOCK, 1234, VMADDR_ANY, 0)).unwrap().bound());
    }

    #[test]
    fn a_short_foreign_or_flagged_address_does_not_cast() {
        assert!(cast(&sockaddr(AF_VSOCK, 1, 3, 0)[..15]).is_none());
        assert!(cast(&sockaddr(2, 1, 3, 0)).is_none());
        assert!(cast(&sockaddr(AF_VSOCK, 1, 3, 0x80)).is_none());
        assert!(cast(&sockaddr(AF_VSOCK, 1, 3, VMADDR_FLAG_TO_HOST)).is_some());
    }
}
