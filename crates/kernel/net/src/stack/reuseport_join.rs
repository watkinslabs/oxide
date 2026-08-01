// Linux `reuseport_add_sock` / `reuseport_detach_sock` against the canonical
// bind tables: a socket joining a key finds its group by asking the members
// already published there, so the group set can never disagree with the bind
// state that produced it.

use super::*;
use crate::reuseport::{slot, ReuseportGroup, ReuseportSlot};

fn udp4_same_key(old: &Arc<UdpRxQueue>, new: &Arc<UdpRxQueue>) -> bool {
    old.reuseport_member() && old.owner_uid == new.owner_uid && old.bound_ip == new.bound_ip
        && old.bound_ifindex.load(::core::sync::atomic::Ordering::Acquire)
            == new.bound_ifindex.load(::core::sync::atomic::Ordering::Acquire)
}

fn udp6_same_key(old: &Arc<crate::stack_ipv6::Udp6RxQueue>,
                 new: &Arc<crate::stack_ipv6::Udp6RxQueue>) -> bool {
    old.reuseport_member() && old.owner_uid == new.owner_uid && old.bound_ip == new.bound_ip
        && old.v6only_at_bind() == new.v6only_at_bind()
        && old.bound_ifindex.load(::core::sync::atomic::Ordering::Acquire)
            == new.bound_ifindex.load(::core::sync::atomic::Ordering::Acquire)
}

fn tcp_same_key(old: &Arc<TcpListenEntry>, new: &Arc<TcpListenEntry>) -> bool {
    old.bind.reuseport && old.bind.owner.owner_uid == new.bind.owner.owner_uid
        && old.bind.v6only == new.bind.v6only
        && old.bind.bound_iface() == new.bind.bound_iface()
}

/// Adopt an existing key-mate's group, else the socket's own pre-bind group,
/// else a fresh one — Linux's `reuseport_alloc` / `reuseport_add_sock` split.
fn resolve(existing: Option<Arc<ReuseportGroup>>, sock_slot: &ReuseportSlot)
    -> Arc<ReuseportGroup>
{
    existing
        .or_else(|| slot::group(sock_slot))
        .unwrap_or_else(ReuseportGroup::new)
}

fn publish(sock_slot: &ReuseportSlot, endpoint_slot: &ReuseportSlot,
           group: Arc<ReuseportGroup>) {
    slot::join(sock_slot, &group);
    slot::set_endpoint_group(endpoint_slot, Some(group));
}

impl NetStack {
    /// Join one published IPv4 UDP endpoint's owning socket to the SO_REUSEPORT
    /// group of its bind key. # C: O(N_port)
    pub fn join_udp4_reuseport(&self, endpoint: &Arc<UdpRxQueue>, sock_slot: &ReuseportSlot) {
        if !endpoint.reuseport_member() { return; }
        let Some(tables) = self.try_inet_tables(endpoint.net_ns()) else { return; };
        let map = tables.udp.lock();
        let existing = map.get(&endpoint.bound_port).and_then(|group| {
            group.iter()
                .find(|old| !Arc::ptr_eq(old, endpoint) && udp4_same_key(old, endpoint))
                .and_then(|old| slot::group(&old.reuseport_group))
        });
        publish(sock_slot, &endpoint.reuseport_group, resolve(existing, sock_slot));
    }

    /// Join one published IPv6 UDP endpoint's owning socket to the SO_REUSEPORT
    /// group of its bind key. # C: O(N_port)
    pub fn join_udp6_reuseport(&self, endpoint: &Arc<crate::stack_ipv6::Udp6RxQueue>,
                               sock_slot: &ReuseportSlot) {
        if !endpoint.reuseport_member() { return; }
        let Some(tables) = self.try_inet_tables(endpoint.net_ns()) else { return; };
        let map = tables.udp6.lock();
        let existing = map.get(&endpoint.bound_port).and_then(|group| {
            group.iter()
                .find(|old| !Arc::ptr_eq(old, endpoint) && udp6_same_key(old, endpoint))
                .and_then(|old| slot::group(&old.reuseport_group))
        });
        publish(sock_slot, &endpoint.reuseport_group, resolve(existing, sock_slot));
    }

    /// Join one published TCP listener's owning socket to the SO_REUSEPORT group
    /// of its listen key. # C: O(N_bucket)
    pub fn join_tcp_reuseport(&self, listener: &Arc<TcpListenEntry>,
                              sock_slot: &ReuseportSlot) {
        if !listener.bind.reuseport { return; }
        let Some(tables) = self.try_inet_tables(listener.bind.net_ns()) else { return; };
        let key = TcpListenKey { local_ip: listener.local.ip, local_port: listener.local.port };
        let map = tables.tcp_listens.lock();
        let existing = map.get(&key).and_then(|bucket| {
            bucket.iter()
                .find(|old| !Arc::ptr_eq(old, listener) && tcp_same_key(old, listener))
                .and_then(|old| slot::group(&old.reuseport_group))
        });
        publish(sock_slot, &listener.reuseport_group, resolve(existing, sock_slot));
    }
}
