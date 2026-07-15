use alloc::sync::Arc;
use core::sync::atomic::AtomicI32;

use sync::{Socket as StackLockClass, Spinlock};

use super::*;
use network_namespace::NetworkNamespaceRef;

fn namespace() -> NetworkNamespaceRef {
    install_final_drop_pending_notifier().expect("install final-drop pending notifier");
    network_namespace::allocate(0).expect("allocate test network namespace")
}

#[test]
fn final_drop_notifier_only_sets_pending_signal() {
    while take_final_drop_pending() {}
    let owner = namespace();
    let id = owner.id();
    drop(owner);
    assert!(take_final_drop_pending());
    assert!(network_namespace::lookup(id).is_none(), "notifier does not retain or reconstruct owner");
}

#[test]
fn hosted_current_namespace_is_the_concrete_initial_owner() {
    let current = current_namespace();
    assert!(Arc::ptr_eq(&current, &network_namespace::initial()));
}

#[test]
fn retained_state_pins_owner_and_dead_id_never_rematerializes() {
    let owner = namespace();
    let id = owner.id();
    let state = materialize_state(&owner);
    drop(owner);
    assert!(network_namespace::lookup(id).is_some(), "state reference retains owner");
    drop(state);

    let claimed = network_namespace::take_dead_namespace_ids();
    assert!(claimed.contains(&id));
    assert!(try_ns_net(id.as_u64()).is_none(), "claimed ID cannot rematerialize state");
    NET_NS.lock().remove(&id.as_u64());
    assert!(network_namespace::finish_teardown(id));
    assert!(try_ns_net(id.as_u64()).is_none(), "finished ID cannot rematerialize state");
}

#[test]
fn private_loopback_snapshot_pins_owner_through_packet_dispatch() {
    use crate::netdev::NetDev;

    let stack = crate::NetStack::new();
    let owner = namespace();
    let id = owner.id();
    let ns = id.as_u64();
    materialize_loopback_into(&stack, &owner);
    let state = state_for(&owner).expect("materialized namespace state");
    let (_, loopback) = state.loopback.lock().clone().expect("private loopback");
    let endpoint = stack.bind_udp_socket_in(
        ns, crate::Ipv4Addr::LOOPBACK, 42_848, None,
        Arc::new(crate::SocketError::new()), Arc::new(AtomicI32::new(0)),
        Arc::new(AtomicI32::new(0)),
        Arc::new(AtomicI32::new(crate::uapi::IP_PMTUDISC_WANT)), 1_000,
        Arc::new(Spinlock::<Option<(crate::Ipv4Addr, u16)>, StackLockClass>::new(None)),
        Arc::new(crate::bpf_filter::SocketFilter::new()),
        Arc::new(crate::mcast_filter::SocketMcast::new()),
    ).expect("bind private UDP endpoint");
    let udp_len = crate::udp::UDP_HDR_LEN + 1;
    let mut bytes = alloc::vec![0u8; crate::ipv4::IPV4_HDR_LEN + udp_len];
    crate::udp::UdpHdr::build_into(
        42_849, 42_848, crate::Ipv4Addr::LOOPBACK, crate::Ipv4Addr::LOOPBACK,
        &[7], &mut bytes[crate::ipv4::IPV4_HDR_LEN..],
    );
    crate::ipv4::Ipv4Hdr::build(
        crate::Ipv4Addr::LOOPBACK, crate::Ipv4Addr::LOOPBACK,
        crate::IpProto::Udp, udp_len as u16, 1,
    ).write_to(&mut bytes[..crate::ipv4::IPV4_HDR_LEN]);
    let mut packet = crate::Pkt::with_capacity(0, bytes.len());
    packet.put(bytes.len()).expect("packet capacity").copy_from_slice(&bytes);
    packet.proto = crate::addr::eth_p::IPV4;
    loopback.xmit(packet).expect("queue private loopback packet");

    let snapshots = private_loopbacks();
    let snapshot = snapshots.into_iter().find(|snapshot| snapshot.namespace().id() == id)
        .expect("owner-retained private loopback snapshot");
    drop(state);
    drop(owner);
    assert!(network_namespace::lookup(id).is_some(), "snapshot retains concrete owner");

    snapshot.drain_into(&stack);
    assert_eq!(endpoint.recv(false).expect("UDP delivered").5, alloc::vec![7]);
    assert!(network_namespace::lookup(id).is_none(), "owner releases after dispatch returns");
}
