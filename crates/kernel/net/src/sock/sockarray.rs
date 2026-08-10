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

/// Which group a stored socket is in right now, with the two facts that
/// cannot change riding the handle.
///
/// This deliberately does NOT take a reference to the socket. A selection runs
/// in softirq at the tail of a receive path, and being the last owner of a
/// closing socket there would run the socket's entire teardown — file, mount,
/// superblock writeback — from inside a program run. Reaching the group
/// through the socket's own reuseport cell keeps the only teardown reachable
/// from here a group and its member list. # C: O(1)
pub fn state_of(handle: &SockHandle) -> Option<SockState> {
    let cell = handle.cell.upgrade()?
        .downcast::<crate::reuseport::slot::SlotCell>().ok()?;
    let group = crate::reuseport::slot::group(&cell)?;
    Some(SockState { group_id: group.id(), protocol: handle.protocol, family: handle.family })
}

/// The transport protocol and address family a stored socket keeps for life.
/// # C: O(1)
fn fixed_shape(sock: &InetSocket) -> (u8, u16) {
    let personality = crate::sock_opts::describe(sock);
    let protocol = if personality.udp { crate::addr::IpProto::Udp as u8 }
                   else { crate::addr::IpProto::Tcp as u8 };
    let family = if personality.family == crate::sock::AF_INET6 {
        crate::socket_args::AF_INET6 as u16
    } else {
        crate::socket_args::AF_INET as u16
    };
    (protocol, family)
}

/// Build the handle a map slot holds for this socket, once the socket has
/// been admitted. # C: O(1)
pub fn handle_of(sock: &InetSocket) -> Option<SockHandle> {
    let hashed = hashed_object(sock)?;
    let cell: Arc<dyn Any + Send + Sync> = sock.reuseport_group.clone();
    let (protocol, family) = fixed_shape(sock);
    Some(SockHandle {
        hashed: Arc::downgrade(&hashed),
        cell: Arc::downgrade(&cell),
        cookie: sock.opts.base.generic
            .cookie(crate::sock_opts::sol_socket::next_cookie) as u64,
        protocol, family,
    })
}

#[cfg(target_os = "oxide-kernel")]
#[path = "sockarray_fd.rs"]
mod fd;
#[cfg(target_os = "oxide-kernel")]
pub use fd::install;
