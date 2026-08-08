//! Live AF_NETLINK port-ID ownership.

extern crate alloc;

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use sync::{Socket as SockLockClass, Spinlock};

use crate::NetlinkSocket;
use crate::admission::Unicast;

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

/// NETLINK request handling has no asynchronously queued transmit allocation:
/// it completes synchronously and dump output is charged to RX when produced.
/// # C: O(1)
fn queued_write_bytes(_socket: &NetlinkSocket) -> usize { 0 }

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
pub fn bind_port_id(socket: &Arc<NetlinkSocket>, requested: u32) -> Result<(), net::NetError> {
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
/// Netlink namespace/protocol/port-ID key, under the destination's receive
/// budget. A refused message fails a non-blocking send and otherwise blocks
/// this sender, bounded by ITS OWN send timeout, until the destination drains.
/// # C: O(N live Netlink ports + len) per attempt
pub(crate) fn unicast_port(sender: &NetlinkSocket, destination_port_id: u32, bytes: &[u8],
    nonblock: bool) -> Unicast
{
    let deadline = if nonblock { 0 } else { sender.send_deadline_ns() };
    loop {
        // The destination is resolved on every attempt: a blocked sender must
        // not hold the port it is waiting on alive by itself.
        let wanted = (sender.net_ns.id().as_u64(), sender.protocol, destination_port_id);
        let target = {
            let mut owners = PORT_OWNERS.lock();
            retain_live(&mut owners);
            owners.iter().find(|owner| (owner.namespace, owner.protocol, owner.port_id) == wanted)
                .and_then(|owner| owner.socket.upgrade())
        };
        let Some(target) = target else { return Unicast::NoPort; };
        let source_port_id = sender.port_id.load(Ordering::Acquire);
        if !target.accepts_unicast_from(source_port_id) { return Unicast::NoPort; }
        match target.try_enqueue_from_creds(bytes.to_vec(), source_port_id,
            net::sock_opts::SenderCreds::current())
        {
            Unicast::Again => {}
            settled => return settled,
        }
        if nonblock { return Unicast::Again; }
        match wait_for_space(&target, deadline) {
            Some(verdict) => return verdict,
            None => continue,
        }
    }
}

/// Block until the destination drains, its send timeout expires, or a signal
/// arrives. `None` means "try again". # C: O(1)
#[cfg(target_os = "oxide-kernel")]
fn wait_for_space(target: &NetlinkSocket, deadline: u64) -> Option<Unicast> {
    if sched::live::deliverable_signals_self() != 0 { return Some(Unicast::Interrupted); }
    // SAFETY: this syscall process parks itself on the destination socket's
    // sender wait list and is removed from it before returning.
    unsafe { target.space_waiters.park_interruptible_with_deadline(deadline); }
    // SAFETY: the running task is parked on that wait list.
    unsafe { sched::live::schedule::schedule(); }
    target.space_waiters.remove_current();
    if sched::live::deliverable_signals_self() != 0 { return Some(Unicast::Interrupted); }
    if net::sock_intr::deadline_expired(deadline) { return Some(Unicast::Again); }
    None
}

/// A hosted build has no task to park, so a refused message reports the
/// non-blocking answer. # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
fn wait_for_space(_target: &NetlinkSocket, _deadline: u64) -> Option<Unicast> {
    Some(Unicast::Again)
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
        assert_eq!(unicast_port(&sender, target_port, b"netlink", true), Unicast::Queued);
        assert_eq!(target.dequeue().map(|(bytes, _)| bytes), Some(b"netlink".to_vec()));
        let sender_port = sender.port_id.load(Ordering::Acquire);
        assert_eq!(target.connect_destination(sender_port.wrapping_add(1), 0), Ok(()));
        assert_eq!(unicast_port(&sender, target_port, b"blocked", true), Unicast::NoPort);
    }

    /// The destination's receive budget bounds a unicast: the first message is
    /// always admitted, one that no longer fits is refused, and a refusal a
    /// non-blocking sender meets is EAGAIN rather than a silent enqueue.
    /// Draining the destination admits the next one.
    #[test]
    fn a_unicast_is_admitted_by_the_destination_receive_budget() {
        let namespace = network_namespace::initial();
        let sender = Arc::new(NetlinkSocket::new(crate::proto::NETLINK_ROUTE, &namespace));
        let target = Arc::new(NetlinkSocket::new(crate::proto::NETLINK_ROUTE, &namespace));
        register_port_id(&sender);
        register_port_id(&target);
        let target_port = target.port_id.load(Ordering::Acquire);
        target.set_receive_buffer(8);
        // An empty destination takes a message far larger than its budget.
        assert_eq!(unicast_port(&sender, target_port, &[0u8; 64], true), Unicast::Queued);
        // With that queued, the budget refuses the next one.
        assert_eq!(unicast_port(&sender, target_port, b"x", true), Unicast::Again);
        assert!(target.dequeue().is_some());
        // A drained destination admits again.
        assert_eq!(unicast_port(&sender, target_port, b"x", true), Unicast::Queued);
    }
}

/// Live netlink sockets in `net_ns`, as `/proc/net/netlink` reports them.
///
/// The reference lists only the reading namespace's sockets, so a container
/// cannot enumerate the host's. # C: O(N live Netlink ports)
pub fn proc_rows(net_ns: u64) -> Vec<crate::ProcRow> {
    let mut owners = PORT_OWNERS.lock();
    retain_live(&mut owners);
    let mut rows = Vec::new();
    for owner in owners.iter() {
        if owner.namespace != net_ns { continue; }
        let Some(sock) = owner.socket.upgrade() else { continue };
        rows.push(crate::ProcRow {
            // Arc address stands in for the reference's `%pK` socket pointer:
            // a stable identity for the life of the socket, nothing more.
            sk: Arc::as_ptr(&sock) as *const () as u64,
            protocol: sock.protocol,
            port_id: sock.port_id.load(Ordering::Acquire),
            groups: sock.groups.low_mask(),
            rmem: sock.queued_bytes(),
            wmem: queued_write_bytes(&sock),
            dump: u32::from(sock.dump.lock().active()),
            locks: Arc::strong_count(&sock) as u32,
            drops: sock.rx_drops.load(Ordering::Relaxed),
            ino: sock.ino.load(Ordering::Acquire),
        });
    }
    rows
}
