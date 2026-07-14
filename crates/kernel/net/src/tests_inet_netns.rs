use alloc::sync::Arc;
use core::sync::atomic::AtomicI32;

use sync::{Socket as StackLockClass, Spinlock};

use crate::addr::{IpAddr, Ipv4Addr, Ipv6Addr};
use crate::netdev::{NetDev, NetResult};
use crate::stack::{NetStack, UdpRxQueue};
use crate::{LoopbackDev, NetIfaceId, SocketError};

const PORT: u16 = 42_824;

fn owners() -> (network_namespace::NetworkNamespaceRef,
    network_namespace::NetworkNamespaceRef)
{
    crate::net_ns::install_final_drop_pending_notifier().unwrap();
    (network_namespace::allocate(0).unwrap(), network_namespace::allocate(0).unwrap())
}

fn flag(value: i32) -> Arc<AtomicI32> { Arc::new(AtomicI32::new(value)) }

fn bind_udp(stack: &NetStack, ns: u64, ip: Ipv4Addr, port: u16) -> NetResult<Arc<UdpRxQueue>> {
    stack.bind_udp_socket_in(
        ns, ip, port, None, Arc::new(SocketError::new()), flag(0), flag(0),
        flag(crate::uapi::IP_PMTUDISC_WANT), 1_000,
        Arc::new(Spinlock::<Option<(Ipv4Addr, u16)>, StackLockClass>::new(None)),
        Arc::new(crate::bpf_filter::SocketFilter::new()),
        Arc::new(crate::mcast_filter::SocketMcast::new()),
    )
}

fn iface_in(stack: &NetStack, ns: u64) -> NetIfaceId {
    stack.ifaces.register_in_ns(Arc::new(LoopbackDev::new()) as Arc<dyn NetDev>, ns)
}

#[test]
fn duplicate_udp_and_tcp_local_names_are_isolated() {
    let stack = NetStack::new();
    let (owner_a, owner_b) = owners();
    let (ns_a, ns_b) = (owner_a.id().as_u64(), owner_b.id().as_u64());
    let udp_a = bind_udp(&stack, ns_a, Ipv4Addr::ANY, PORT).unwrap();
    let udp_b = bind_udp(&stack, ns_b, Ipv4Addr::ANY, PORT).unwrap();
    assert!(!Arc::ptr_eq(&udp_a, &udp_b));

    let tcp_a = stack.tcp_reserve_in(ns_a, IpAddr::V4(Ipv4Addr::ANY), PORT,
        None, false, false, 1_000, false).unwrap();
    let tcp_b = stack.tcp_reserve_in(ns_b, IpAddr::V4(Ipv4Addr::ANY), PORT,
        None, false, false, 1_000, false).unwrap();
    stack.tcp_listen_reserved(&tcp_a).unwrap();
    stack.tcp_listen_reserved(&tcp_b).unwrap();

    assert_eq!(stack.inet_diag_snapshot_in(ns_a, 17).len(), 1);
    assert_eq!(stack.inet_diag_snapshot_in(ns_b, 17).len(), 1);
    assert_eq!(stack.inet_diag_snapshot_in(ns_a, 6).len(), 1);
    assert_eq!(stack.inet_diag_snapshot_in(ns_b, 6).len(), 1);
    assert!(stack.inet_diag_snapshot_in(0, 17).is_empty());
    assert!(stack.inet_diag_snapshot_in(0, 6).is_empty());
}

#[test]
fn ingress_interface_selects_only_its_namespace_udp_endpoint() {
    let stack = NetStack::new();
    let (owner_a, owner_b) = owners();
    let (ns_a, ns_b) = (owner_a.id().as_u64(), owner_b.id().as_u64());
    let iface_a = iface_in(&stack, ns_a);
    let iface_b = iface_in(&stack, ns_b);
    let a = bind_udp(&stack, ns_a, Ipv4Addr::ANY, PORT).unwrap();
    let b = bind_udp(&stack, ns_b, Ipv4Addr::ANY, PORT).unwrap();
    let src = Ipv4Addr::new(192, 0, 2, 1);

    let selected_a = stack.udp_demux_in(ns_a, src, 50_000, Ipv4Addr::LOOPBACK, PORT, iface_a);
    let selected_b = stack.udp_demux_in(ns_b, src, 50_000, Ipv4Addr::LOOPBACK, PORT, iface_b);
    assert_eq!(selected_a.len(), 1);
    assert_eq!(selected_b.len(), 1);
    assert!(Arc::ptr_eq(&selected_a[0], &a));
    assert!(Arc::ptr_eq(&selected_b[0], &b));
}

#[test]
fn pmtu_and_ephemeral_sequences_are_namespace_owned() {
    let stack = NetStack::new();
    let (owner_a, owner_b) = owners();
    crate::net_ns::materialize_state(&owner_a);
    crate::net_ns::materialize_state(&owner_b);
    let (ns_a, ns_b) = (owner_a.id().as_u64(), owner_b.id().as_u64());
    let iface_a = iface_in(&stack, ns_a);
    let iface_b = iface_in(&stack, ns_b);
    let dst = Ipv6Addr::from_segments([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]);
    stack.update_pmtu_v6_in(ns_a, iface_a, dst, 1_280);
    assert_eq!(stack.path_mtu_in(ns_a, IpAddr::V6(dst), Some(iface_a), false), Ok(1_280));
    assert_eq!(stack.path_mtu_in(ns_b, IpAddr::V6(dst), Some(iface_b), false), Ok(65_535));

    crate::ephemeral::set_range_in(ns_a, 45_000, 45_001).unwrap();
    crate::ephemeral::set_range_in(ns_b, 45_000, 45_001).unwrap();
    let a = stack.tcp_reserve_in(ns_a, IpAddr::V4(Ipv4Addr::ANY), 0,
        None, false, false, 1_000, false).unwrap();
    let b = stack.tcp_reserve_in(ns_b, IpAddr::V4(Ipv4Addr::ANY), 0,
        None, false, false, 1_000, false).unwrap();
    assert_eq!(a.local.port, b.local.port);
}

#[test]
fn namespace_teardown_removes_all_transport_visibility() {
    let stack = NetStack::new();
    let (owner, _) = owners();
    let id = owner.id();
    let ns = id.as_u64();
    let endpoint = bind_udp(&stack, ns, Ipv4Addr::ANY, PORT).unwrap();
    stack.unbind_udp_endpoint(&endpoint);
    drop(endpoint);
    assert!(stack.remove_inet_namespace(ns));
    assert!(stack.inet_diag_snapshot_in(ns, 17).is_empty());
    drop(owner);
    let claimed = network_namespace::take_dead_namespace_ids();
    assert!(claimed.contains(&id));
    assert!(stack.try_inet_tables(ns).is_none(), "claimed ID cannot recreate transport state");
    assert!(network_namespace::finish_teardown(id));
    assert!(stack.try_inet_tables(ns).is_none(), "finished ID cannot recreate transport state");
}
