// What a socket-holding bpf map stores, and what the stored socket is now.
//
// The map itself holds a type-erased weak handle and knows nothing about
// sockets; everything socket-shaped is decided here, so there is exactly one
// place that answers "which object is hashed for this socket", "may it be
// stored at all", and "which group is it in right now".
//
// The stored object is the HASHED one — the listen entry or the bound receive
// queue that lives in the bind table — not the descriptor's socket. That is
// the object an arriving packet is steered to, so it is the only thing a
// selection can usefully name, and holding it weakly means an unbound or
// closed socket simply has no live handle rather than a second liveness flag
// that could disagree with the bind table.

extern crate alloc;
use alloc::sync::Arc;
use core::any::Any;

use security::bpf::map::sockarray::{SockHandle, SockState, StoredShape};

use crate::sock::{InetSocket, SockKind};
use crate::stack::TcpListenEntry;
use crate::stack::UdpRxQueue;
use crate::stack_ipv6::Udp6RxQueue;

/// The bind-table object a packet for this socket is steered to, if the socket
/// occupies a transport hash at all. # C: O(1)
pub fn hashed_object(sock: &InetSocket) -> Option<Arc<dyn Any + Send + Sync>> {
    if let Some(queue) = sock.udp4.lock().clone() { return Some(queue); }
    if let Some(queue) = sock.udp6.lock().clone() { return Some(queue); }
    match &*sock.kind.lock() {
        SockKind::TcpListener(listener) => Some(listener.clone()),
        _ => None,
    }
}

/// The five terms a store decision is made in. # C: O(1)
pub fn stored_shape(sock: &InetSocket) -> StoredShape {
    let shape = crate::reuseport::SockShape::of(&crate::sock_opts::describe(sock));
    StoredShape {
        tcp_or_udp: shape.tcp_or_udp,
        inet: shape.inet,
        stream_or_dgram: shape.stream_or_dgram,
        hashed: crate::reuseport::is_hashed(sock),
        in_group: crate::reuseport::group_of(sock).is_some(),
    }
}

/// Group, protocol and family of a stored socket, read now rather than
/// remembered: a socket may leave or join a group after being stored.
/// # C: O(1)
pub fn state_of(handle: &SockHandle) -> Option<SockState> {
    let object = handle.upgrade()?;
    let udp = crate::addr::IpProto::Udp as u8;
    let tcp = crate::addr::IpProto::Tcp as u8;
    let v4 = crate::socket_args::AF_INET as u16;
    let v6 = crate::socket_args::AF_INET6 as u16;
    let (slot, protocol, family) =
        match object.clone().downcast::<TcpListenEntry>() {
            Ok(listener) => {
                let family = match listener.local.ip {
                    crate::addr::IpAddr::V6(_) => v6, crate::addr::IpAddr::V4(_) => v4,
                };
                (listener.reuseport_group.clone(), tcp, family)
            }
            Err(_) => match object.clone().downcast::<UdpRxQueue>() {
                Ok(queue) => (queue.reuseport_group.clone(), udp, v4),
                Err(_) => match object.downcast::<Udp6RxQueue>() {
                    Ok(queue) => (queue.reuseport_group.clone(), udp, v6),
                    Err(_) => return None,
                },
            },
        };
    let group = crate::reuseport::slot::group(&slot)?;
    Some(SockState { group_id: group.id(), protocol, family })
}

/// Build the handle a map slot holds for this socket, once the socket has
/// been admitted. # C: O(1)
pub fn handle_of(sock: &InetSocket) -> Option<SockHandle> {
    let hashed = hashed_object(sock)?;
    Some(SockHandle {
        hashed: Arc::downgrade(&hashed),
        cookie: sock.opts.base.generic
            .cookie(crate::sock_opts::sol_socket::next_cookie) as u64,
    })
}

#[cfg(target_os = "oxide-kernel")]
#[path = "sockarray_fd.rs"]
mod fd;
#[cfg(target_os = "oxide-kernel")]
pub use fd::install;
