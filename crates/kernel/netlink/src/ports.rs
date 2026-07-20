//! Live AF_NETLINK port-ID ownership.

extern crate alloc;

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use sync::{Socket as SockLockClass, Spinlock};

use crate::NetlinkSocket;

struct PortOwner {
    namespace: u64,
    protocol: u16,
    port_id: u32,
    socket: Weak<NetlinkSocket>,
}

static PORT_OWNERS: Spinlock<Vec<PortOwner>, SockLockClass> = Spinlock::new(Vec::new());

fn key(socket: &NetlinkSocket, port_id: u32) -> (u64, u16, u32) {
    (socket.net_ns.id().as_u64(), socket.protocol, port_id)
}

fn retain_live(owners: &mut Vec<PortOwner>) {
    owners.retain(|owner| owner.socket.strong_count() != 0);
}

/// Publish a newly reachable Netlink socket's already-allocated port ID.
/// # C: O(N live Netlink ports)
pub(crate) fn register_port_id(socket: &Arc<NetlinkSocket>) {
    let port_id = socket.port_id.load(Ordering::Acquire);
    let wanted = key(socket, port_id);
    let mut owners = PORT_OWNERS.lock();
    retain_live(&mut owners);
    if owners.iter().any(|owner| {
        (owner.namespace, owner.protocol, owner.port_id) == wanted
            && owner.socket.upgrade().is_some_and(|live| !Arc::ptr_eq(&live, socket))
    }) { return; }
    if owners.iter().any(|owner| owner.socket.upgrade().is_some_and(|live| Arc::ptr_eq(&live, socket))) {
        return;
    }
    owners.push(PortOwner { namespace: wanted.0, protocol: wanted.1, port_id, socket: Arc::downgrade(socket) });
}

/// Atomically claim an explicit `sockaddr_nl.nl_pid`, or retain the current
/// autobound ID when the request is zero. # C: O(N live Netlink ports)
pub(crate) fn bind_port_id(socket: &Arc<NetlinkSocket>, requested: u32) -> Result<(), net::NetError> {
    let current = socket.port_id.load(Ordering::Acquire);
    let port_id = if requested == 0 { current } else { requested };
    let wanted = key(socket, port_id);
    let mut owners = PORT_OWNERS.lock();
    retain_live(&mut owners);
    if owners.iter().any(|owner| {
        (owner.namespace, owner.protocol, owner.port_id) == wanted
            && owner.socket.upgrade().is_some_and(|live| !Arc::ptr_eq(&live, socket))
    }) { return Err(net::NetError::Eaddrinuse); }
    owners.retain(|owner| !owner.socket.upgrade().is_some_and(|live| Arc::ptr_eq(&live, socket)));
    socket.port_id.store(port_id, Ordering::Release);
    owners.push(PortOwner { namespace: wanted.0, protocol: wanted.1, port_id, socket: Arc::downgrade(socket) });
    Ok(())
}

/// Deliver one userspace unicast to the live socket identified by the Linux
/// Netlink namespace/protocol/port-ID key. # C: O(N live Netlink ports + len)
pub(crate) fn unicast_port(sender: &NetlinkSocket, destination_port_id: u32, bytes: &[u8]) -> bool {
    let wanted = (sender.net_ns.id().as_u64(), sender.protocol, destination_port_id);
    let target = {
        let mut owners = PORT_OWNERS.lock();
        retain_live(&mut owners);
        owners.iter().find(|owner| (owner.namespace, owner.protocol, owner.port_id) == wanted)
            .and_then(|owner| owner.socket.upgrade())
    };
    let Some(target) = target else { return false; };
    let source_port_id = sender.port_id.load(Ordering::Acquire);
    if !target.accepts_unicast_from(source_port_id) { return false; }
    target.enqueue_from(bytes.to_vec(), source_port_id);
    true
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use super::*;

    #[test]
    fn bind_rejects_a_live_namespace_protocol_port_collision() {
        let namespace = network_namespace::initial();
        let first = Arc::new(NetlinkSocket::new(crate::proto::NETLINK_ROUTE, &namespace));
        let second = Arc::new(NetlinkSocket::new(crate::proto::NETLINK_ROUTE, &namespace));
        register_port_id(&first);
        let first_port = first.port_id.load(Ordering::Acquire);
        assert_eq!(bind_port_id(&second, first_port), Err(net::NetError::Eaddrinuse));
        drop(first);
        assert_eq!(bind_port_id(&second, first_port), Ok(()));
    }

    #[test]
    fn unicast_uses_the_bound_port_owner_and_connected_peer_rule() {
        let namespace = network_namespace::initial();
        let sender = Arc::new(NetlinkSocket::new(crate::proto::NETLINK_ROUTE, &namespace));
        let target = Arc::new(NetlinkSocket::new(crate::proto::NETLINK_ROUTE, &namespace));
        register_port_id(&sender);
        register_port_id(&target);
        let target_port = target.port_id.load(Ordering::Acquire);
        assert!(unicast_port(&sender, target_port, b"netlink"));
        assert_eq!(target.dequeue().map(|(bytes, _)| bytes), Some(b"netlink".to_vec()));
        let sender_port = sender.port_id.load(Ordering::Acquire);
        assert_eq!(target.connect_destination(sender_port.wrapping_add(1), 0), Ok(()));
        assert!(!unicast_port(&sender, target_port, b"blocked"));
    }
}
