use alloc::sync::Arc;
use core::sync::atomic::AtomicI32;

use sync::{Socket as StackLockClass, Spinlock};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use super::*;
use network_namespace::NetworkNamespaceRef;

fn namespace() -> NetworkNamespaceRef {
    test_support::allocate_namespace()
}

#[test]
fn final_drop_notifier_only_sets_pending_signal() {
    let _guard = test_support::LIFETIME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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
fn lookup_first_pins_owner_until_materialization_publishes_retained_state() {
    let _guard = test_support::LIFETIME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let stack = crate::NetStack::new();
    let owner = namespace();
    let id = owner.id();
    let (pinned_tx, pinned_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let resolved = network_namespace::lookup_u64(id.as_u64())
            .expect("lookup pins live namespace owner");
        pinned_tx.send(()).expect("publish successful lookup phase");
        if release_rx.recv().is_err() { return None; }
        Some(materialize_state(&resolved))
    });

    pinned_rx.recv_timeout(Duration::from_secs(5)).expect("lookup phase completes");
    drop(owner);
    let claimed = network_namespace::take_dead_namespace_ids();
    assert!(!claimed.contains(&id),
        "retained lookup prevents final-drop claim before materialization");
    test_support::finish_claimed(&stack, &claimed);
    release_tx.send(()).expect("release materialization phase");
    let state = worker.join().unwrap().expect("materialization completes");
    assert!(network_namespace::lookup(id).is_some(),
        "materialized state takes over retained namespace ownership");
    drop(state);

    let claimed = network_namespace::take_dead_namespace_ids();
    assert!(claimed.contains(&id));
    test_support::finish_claimed(&stack, &claimed);
}

#[test]
fn final_drop_claim_first_prevents_state_publication() {
    let _guard = test_support::LIFETIME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let stack = crate::NetStack::new();
    let owner = namespace();
    let id = owner.id();
    let (release_tx, release_rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        if release_rx.recv().is_err() { return None; }
        try_ns_net(id.as_u64())
    });
    drop(owner);

    let mut claimed = network_namespace::take_dead_namespace_ids();
    assert!(claimed.contains(&id));
    let target = claimed.iter().position(|claimed_id| *claimed_id == id).unwrap();
    claimed.swap_remove(target);
    test_support::finish_claimed(&stack, &claimed);
    release_tx.send(()).expect("release post-claim lookup phase");
    assert!(worker.join().unwrap().is_none(), "claimed ID cannot materialize state");
    assert!(!NET_NS.lock().contains_key(&id.as_u64()),
        "failed resolution publishes no namespace state");
    test_support::finish_claimed(&stack, &[id]);
    assert!(try_ns_net(id.as_u64()).is_none(), "finished ID cannot materialize state");
}

#[test]
fn private_loopback_snapshot_pins_owner_through_packet_dispatch() {
    use crate::netdev::NetDev;

    let _guard = test_support::LIFETIME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let stack = Arc::new(crate::NetStack::new());
    let owner = namespace();
    let id = owner.id();
    let ns = id.as_u64();
    materialize_loopback_into(&stack, &owner);
    let state = state_for(&owner).expect("materialized namespace state");
    let (iface, loopback) = state.loopback.lock().clone().expect("private loopback");
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

    let generation = stack.ifaces.acquire_ingress(iface)
        .expect("live loopback generation").generation();
    let snapshots = private_loopbacks(&stack);
    let snapshot = snapshots.into_iter().find(|snapshot| snapshot.namespace().id() == id)
        .expect("owner-retained private loopback snapshot");
    assert_eq!(snapshot.generation(), generation);
    drop(state);
    drop(owner);
    assert!(network_namespace::lookup(id).is_some(), "snapshot retains concrete owner");

    let teardown_stack = stack.clone();
    let (done_tx, done_rx) = mpsc::channel();
    let teardown = std::thread::spawn(move || {
        done_tx.send(destroy_namespace_into(&teardown_stack, ns)).unwrap();
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    while stack.ifaces.acquire_ingress(iface).is_some() {
        assert!(Instant::now() < deadline, "namespace teardown closes ingress");
        std::thread::yield_now();
    }
    assert_eq!(loopback.rx_len(), 1, "closed ingress cannot dequeue before retained lease");
    assert!(matches!(done_rx.try_recv(), Err(mpsc::TryRecvError::Empty)),
        "teardown waits for retained loopback ingress");

    snapshot.drain_into(&stack);
    assert_eq!(endpoint.recv(false).expect("UDP delivered").5, alloc::vec![7]);
    assert!(done_rx.recv_timeout(Duration::from_secs(5)).expect("teardown completes"));
    teardown.join().unwrap();
    let mut rejected = crate::Pkt::with_capacity(0, 1);
    rejected.put(1).unwrap()[0] = 1;
    assert_eq!(loopback.xmit(rejected), Err(crate::NetError::Enodev));
    assert_eq!(loopback.rx_len(), 0);
    assert!(network_namespace::lookup(id).is_none(), "owner releases after dispatch returns");
    let claimed = network_namespace::take_dead_namespace_ids();
    assert!(claimed.contains(&id));
    test_support::finish_claimed(&stack, &claimed);
}

#[test]
fn final_drop_first_purges_loopback_and_accounts_packets() {
    use crate::netdev::NetDev;

    let _guard = test_support::LIFETIME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let stack = crate::NetStack::new();
    let owner = namespace();
    let ns = owner.id().as_u64();
    materialize_loopback_into(&stack, &owner);
    let state = state_for(&owner).expect("materialized namespace state");
    let (iface, loopback) = state.loopback.lock().clone().expect("private loopback");
    for byte in [1, 2] {
        let mut packet = crate::Pkt::with_capacity(0, 1);
        packet.put(1).unwrap()[0] = byte;
        loopback.xmit(packet).unwrap();
    }

    assert!(destroy_namespace_into(&stack, ns));
    assert_eq!(loopback.rx_len(), 0);
    assert_eq!(loopback.stats().rx_dropped, 2);
    stack.drain_loopback(iface, &loopback);
    assert_eq!(loopback.rx_len(), 0);

    let mut rejected = crate::Pkt::with_capacity(0, 1);
    rejected.put(1).unwrap()[0] = 3;
    assert_eq!(loopback.xmit(rejected), Err(crate::NetError::Enodev));
    assert_eq!(loopback.stats().tx_dropped, 1);
    let id = owner.id();
    drop(state);
    drop(owner);
    let claimed = network_namespace::take_dead_namespace_ids();
    assert!(claimed.contains(&id));
    test_support::finish_claimed(&stack, &claimed);
}

#[test]
fn final_drop_purges_ndp_state_without_touching_other_namespace() {
    use crate::addr::{Ipv6Addr, MacAddr};

    let _guard = test_support::LIFETIME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let stack = crate::NetStack::new();
    let removed = namespace();
    let retained = namespace();
    materialize_loopback_into(&stack, &removed);
    materialize_loopback_into(&stack, &retained);
    let removed_id = removed.id().as_u64();
    let retained_id = retained.id().as_u64();
    let removed_state = state_for(&removed).expect("removed namespace state");
    let retained_state = state_for(&retained).expect("retained namespace state");
    let removed_iface = removed_state.loopback.lock().as_ref().expect("removed loopback").0;
    let retained_iface = retained_state.loopback.lock().as_ref().expect("retained loopback").0;
    let peer = Ipv6Addr::from_segments([0xfe80, 0, 0, 0, 0, 0, 0, 2]);
    let removed_mac = MacAddr([2, 0, 0, 0, 0, 1]);
    let retained_mac = MacAddr([2, 0, 0, 0, 0, 2]);
    stack.ndp_insert(removed_iface, peer, removed_mac);
    stack.ndp_insert(retained_iface, peer, retained_mac);
    assert_eq!(stack.ndp_lookup(removed_iface, peer), Some(removed_mac));
    assert_eq!(stack.ndp_lookup(retained_iface, peer), Some(retained_mac));

    assert!(destroy_namespace_into(&stack, removed_id));
    assert_eq!(stack.ndp_lookup(removed_iface, peer), None,
        "final namespace teardown must purge NDP entries for removed interfaces");
    assert_eq!(stack.ndp_lookup(retained_iface, peer), Some(retained_mac),
        "NDP entries belonging to another namespace must survive teardown");

    assert!(destroy_namespace_into(&stack, retained_id));
    drop(removed_state);
    drop(retained_state);
    let removed_id_ref = removed.id();
    let retained_id_ref = retained.id();
    drop(removed);
    drop(retained);
    let claimed = network_namespace::take_dead_namespace_ids();
    assert!(claimed.contains(&removed_id_ref));
    assert!(claimed.contains(&retained_id_ref));
    test_support::finish_claimed(&stack, &claimed);
}
