use core::sync::atomic::Ordering;

use crate::*;

// Module manifest: `uevent` owns raw, cooked, and unicast uevent delivery tests.
mod uevent;

fn namespace_dropped() {}

/// Allocate one isolated hosted namespace fixture. # C: O(1)
pub(crate) fn test_namespace() -> network_namespace::NetworkNamespaceRef {
    network_namespace::install_final_drop_callback(namespace_dropped).unwrap();
    network_namespace::allocate(namespace_identity::initial(
        namespace_identity::NamespaceKind::User)).unwrap()
}

#[test]
fn nlmsghdr_roundtrip() {
    let h = Nlmsghdr {
        nlmsg_len: 24,
        nlmsg_type: 0x12,
        nlmsg_flags: flags::NLM_F_REQUEST | flags::NLM_F_DUMP,
        nlmsg_seq: 0xDEAD_BEEF,
        nlmsg_pid: 42,
    };
    let mut buf = [0u8; Nlmsghdr::SIZE];
    h.write_to(&mut buf);
    let p = Nlmsghdr::parse(&buf).unwrap();
    assert_eq!(p.nlmsg_len, 24);
    assert_eq!(p.nlmsg_type, 0x12);
    assert_eq!(p.nlmsg_flags, flags::NLM_F_REQUEST | flags::NLM_F_DUMP);
    assert_eq!(p.nlmsg_seq, 0xDEAD_BEEF);
    assert_eq!(p.nlmsg_pid, 42);
}

#[test]
fn nlmsg_align_rounds_up_to_4() {
    assert_eq!(nlmsg_align(0), 0);
    assert_eq!(nlmsg_align(1), 4);
    assert_eq!(nlmsg_align(3), 4);
    assert_eq!(nlmsg_align(4), 4);
    assert_eq!(nlmsg_align(5), 8);
    assert_eq!(nlmsg_align(13), 16);
}

#[test]
fn vfs_write_dispatches_netlink_request_and_queues_reply() {
    use alloc::sync::Arc;
    let sock = Arc::new(NetlinkSocket::new(proto::NETLINK_ROUTE, &network_namespace::initial()));
    let inode = make_netlink_socket_inode(Arc::clone(&sock));
    let dentry = vfs::Dentry::new(None, "nl".into(), Arc::clone(&inode));
    let file = vfs::File::new(inode, dentry, vfs::OpenFlags::O_RDWR);

    let req = Nlmsghdr {
        nlmsg_len:   Nlmsghdr::SIZE as u32,
        nlmsg_type:  rtnetlink::RTM_GETLINK,
        nlmsg_flags: flags::NLM_F_REQUEST | flags::NLM_F_DUMP,
        nlmsg_seq:   77,
        nlmsg_pid:   1234,
    };
    let mut msg = [0u8; Nlmsghdr::SIZE];
    req.write_to(&mut msg);

    assert_eq!(file.write(&msg), Ok(msg.len()));
    let (reply, src) = sock.dequeue().expect("RTM_GETLINK reply queued");
    assert_eq!(src, 0);
    assert!(reply.len() >= Nlmsghdr::SIZE + 4, "multipart dump has NLMSG_DONE");
    let done_at = reply.len() - (Nlmsghdr::SIZE + 4);
    let done = Nlmsghdr::parse(&reply[done_at..]).expect("done header");
    assert_eq!(done.nlmsg_type, msg::NLMSG_DONE);
    assert_eq!(done.nlmsg_flags, flags::NLM_F_MULTI);
    assert_eq!(done.nlmsg_seq, 77);
    assert_eq!(done.nlmsg_pid, sock.port_id.load(Ordering::Acquire));
}

#[test]
fn vfs_write_iter_keeps_one_datagram_on_pinned_file_after_close_reuse() {
    use alloc::sync::Arc;

    let (old_weak, old_file) = socket_file(vfs::OpenFlags::O_RDWR);
    let fdt = vfs::FdTable::new();
    let fd = fdt.alloc(old_file).unwrap();
    let pinned = fdt.get(fd).unwrap();
    fdt.close(fd).unwrap();

    let (replacement_weak, replacement_file) = socket_file(
        vfs::OpenFlags::O_RDWR | vfs::OpenFlags::O_NONBLOCK);
    assert_eq!(fdt.alloc(replacement_file).unwrap(), fd);

    let request = Nlmsghdr {
        nlmsg_len: Nlmsghdr::SIZE as u32,
        nlmsg_type: rtnetlink::RTM_GETLINK,
        nlmsg_flags: flags::NLM_F_REQUEST | flags::NLM_F_DUMP,
        nlmsg_seq: 91,
        nlmsg_pid: 4321,
    };
    let mut message = [0u8; Nlmsghdr::SIZE];
    request.write_to(&mut message);
    let iov = [&message[..7], &message[7..]];

    assert_eq!(pinned.write_iter(&iov), Ok(message.len()));
    let old = old_weak.upgrade().expect("active writev File pins original socket");
    let (reply, _) = old.dequeue().expect("coalesced request emits one reply datagram");
    assert!(Nlmsghdr::parse(&reply).is_some());
    assert!(old.dequeue().is_none(), "one writev emits one reply datagram");
    assert!(replacement_weak.upgrade().unwrap().dequeue().is_none(),
        "exact descriptor reuse cannot retarget pinned writev");
    assert!(Arc::ptr_eq(&old, &netlink_arc_from_inode(pinned.inode()).unwrap()));
}

#[test]
fn vfs_write_iter_parses_headers_across_arbitrary_iovec_boundaries() {
    let (weak, file) = socket_file(vfs::OpenFlags::O_RDWR);
    let request = Nlmsghdr {
        nlmsg_len: Nlmsghdr::SIZE as u32,
        nlmsg_type: 0x1234,
        nlmsg_flags: flags::NLM_F_REQUEST,
        nlmsg_seq: 92,
        nlmsg_pid: 4322,
    };
    let mut message = [0u8; Nlmsghdr::SIZE];
    request.write_to(&mut message);
    let iov: alloc::vec::Vec<&[u8]> = message.iter().map(core::slice::from_ref).collect();

    assert_eq!(file.write_iter(&iov), Ok(message.len()));
    let socket = weak.upgrade().unwrap();
    let (reply, _) = socket.dequeue().expect("split header dispatched");
    assert_eq!(Nlmsghdr::parse(&reply).unwrap().nlmsg_seq, 92);
}

#[test]
fn vfs_write_iter_dispatches_multiple_aligned_messages() {
    let (weak, file) = socket_file(vfs::OpenFlags::O_RDWR);
    let mut datagram = [0u8; 2 * Nlmsghdr::SIZE];
    for (index, seq) in [101u32, 102].into_iter().enumerate() {
        Nlmsghdr {
            nlmsg_len: Nlmsghdr::SIZE as u32,
            nlmsg_type: 0x1234,
            nlmsg_flags: flags::NLM_F_REQUEST,
            nlmsg_seq: seq,
            nlmsg_pid: 5000,
        }.write_to(&mut datagram[index * Nlmsghdr::SIZE..]);
    }
    let iov = [&datagram[..3], &datagram[3..19], &datagram[19..25], &datagram[25..]];

    assert_eq!(file.write_iter(&iov), Ok(datagram.len()));
    let socket = weak.upgrade().unwrap();
    for seq in [101u32, 102] {
        let (reply, _) = socket.dequeue().expect("each request dispatched");
        assert_eq!(Nlmsghdr::parse(&reply).unwrap().nlmsg_seq, seq);
    }
    assert!(socket.dequeue().is_none());
}

#[test]
fn vfs_write_iter_rejects_malformed_split_header_without_dispatch() {
    let (weak, file) = socket_file(vfs::OpenFlags::O_RDWR);
    let mut message = [0u8; Nlmsghdr::SIZE];
    Nlmsghdr {
        nlmsg_len: (Nlmsghdr::SIZE - 1) as u32,
        nlmsg_type: 0x1234,
        nlmsg_flags: flags::NLM_F_REQUEST,
        nlmsg_seq: 103,
        nlmsg_pid: 5001,
    }.write_to(&mut message);
    let iov = [&message[..1], &message[1..4], &message[4..15], &message[15..]];

    assert_eq!(file.write_iter(&iov), Err(vfs::VfsError::Einval));
    assert!(weak.upgrade().unwrap().dequeue().is_none());
}

#[test]
fn scatter_snapshot_is_atomic_against_header_length_mutation() {
    let socket = NetlinkSocket::new(proto::NETLINK_ROUTE, &network_namespace::initial());
    let mut scatter = [alloc::vec![0u8; 7], alloc::vec![0u8; Nlmsghdr::SIZE - 7]];
    let mut message = [0u8; Nlmsghdr::SIZE];
    Nlmsghdr {
        nlmsg_len: Nlmsghdr::SIZE as u32,
        nlmsg_type: 0x1234,
        nlmsg_flags: flags::NLM_F_REQUEST,
        nlmsg_seq: 104,
        nlmsg_pid: 5002,
    }.write_to(&mut message);
    scatter[0].copy_from_slice(&message[..7]);
    scatter[1].copy_from_slice(&message[7..]);
    assert_eq!(socket.write_mutating_scatter_for_test(scatter.into(), |bufs|
        bufs[0][..4].copy_from_slice(&u32::MAX.to_ne_bytes())), Ok(Nlmsghdr::SIZE));
    let (reply, _) = socket.dequeue().expect("pre-mutation datagram dispatched atomically");
    assert_eq!(Nlmsghdr::parse(&reply).unwrap().nlmsg_seq, 104);
    assert!(socket.dequeue().is_none());
}

#[test]
fn vectored_datagram_length_overflow_is_einval() {
    assert_eq!(crate::netlink_socket::checked_iov_len([usize::MAX, 1].into_iter()),
        Err(vfs::VfsError::Einval));
}

#[test]
fn port_ids_are_unique() {
    let a = alloc_port_id();
    let b = alloc_port_id();
    assert_ne!(a, b);
}

#[test]
fn membership_bits_map_group_minus_one() {
    let s = NetlinkSocket::new(proto::NETLINK_ROUTE, &network_namespace::initial());
    s.add_membership(1);
    s.add_membership(5);
    assert_eq!(s.groups.load(Ordering::Acquire), (1 << 0) | (1 << 4));
    s.drop_membership(1);
    assert_eq!(s.groups.load(Ordering::Acquire), 1 << 4);
    s.set_group_mask(0xF);
    assert_eq!(s.groups.load(Ordering::Acquire), 0xF);
    s.add_membership(0);
    assert_eq!(s.groups.load(Ordering::Acquire), 0xF);
}

#[test]
fn connect_destination_owns_default_send_and_peer_state() {
    const DESTINATION_PORT_ID: u32 = 42;
    const REQUESTED_GROUPS: u32 = 0b1100;
    const FIRST_REQUESTED_GROUP: u32 = 0b0100;
    let socket = NetlinkSocket::new(proto::NETLINK_ROUTE, &network_namespace::initial());
    assert_eq!(socket.destination(), (NETLINK_UNCONNECTED_PORT_ID, NETLINK_UNCONNECTED_GROUPS));
    assert_eq!(socket.connect_destination(DESTINATION_PORT_ID, REQUESTED_GROUPS), Ok(()));
    assert_eq!(socket.destination(), (DESTINATION_PORT_ID, FIRST_REQUESTED_GROUP));
    assert_eq!(socket.disconnect_destination(), Ok(()));
    assert_eq!(socket.destination(), (NETLINK_UNCONNECTED_PORT_ID, NETLINK_UNCONNECTED_GROUPS));
}

fn deny_connect(_context: security::network::Context) -> security::network::Verdict {
    security::network::Verdict::Deny
}

#[test]
fn connect_destination_does_not_repeat_syscall_connect_admission() {
    const DESTINATION_PORT_ID: u32 = 42;
    const REQUESTED_GROUPS: u32 = 0b1100;
    const FIRST_REQUESTED_GROUP: u32 = 0b0100;
    let namespace = test_namespace();
    let namespace_id = namespace.id().as_u64();
    let _ = security::network::remove(namespace_id, security::network::Operation::Connect);
    assert_eq!(security::network::install(namespace_id, security::network::Operation::Connect,
        deny_connect), None);
    let socket = NetlinkSocket::new(proto::NETLINK_ROUTE, &namespace);
    assert_eq!(socket.connect_destination(DESTINATION_PORT_ID, REQUESTED_GROUPS), Ok(()));
    assert_eq!(socket.destination(), (DESTINATION_PORT_ID, FIRST_REQUESTED_GROUP));
    assert_eq!(security::network::counters(namespace_id, security::network::Operation::Connect),
        Some((0, 0)));
    assert_eq!(security::network::remove(namespace_id, security::network::Operation::Connect),
        Some(deny_connect as security::network::Hook));
}

#[test]
fn socket_retains_concrete_namespace_owner_until_close() {
    use alloc::sync::{Arc, Weak};

    let domain = net::hosted_fixture::init_net_domain();
    domain.set_notifier(crate::mcast::notify_control_event);
    let namespace = test_namespace();
    let id = namespace.id();
    let weak: Weak<network_namespace::NetworkNamespace> = Arc::downgrade(&namespace);
    let socket = NetlinkSocket::new(proto::NETLINK_ROUTE, &namespace);
    assert!(Arc::ptr_eq(&socket.net_ns, &namespace));
    assert_eq!(Arc::strong_count(&namespace), 2);

    drop(namespace);
    assert!(network_namespace::lookup(id).is_some(), "socket must pin namespace after task owner drops");
    drop(socket);
    assert!(weak.upgrade().is_none(), "socket close releases final namespace owner");
    assert!(network_namespace::lookup(id).is_none());
}

fn socket_file(flags: vfs::OpenFlags) -> (alloc::sync::Weak<NetlinkSocket>, alloc::sync::Arc<vfs::File>) {
    use alloc::sync::Arc;
    let socket = Arc::new(NetlinkSocket::new(proto::NETLINK_ROUTE, &network_namespace::initial()));
    let weak = Arc::downgrade(&socket);
    let inode = make_netlink_socket_inode(socket);
    let dentry = vfs::Dentry::new(None, "netlink".into(), inode.clone());
    (weak, vfs::File::new(inode, dentry, flags))
}

#[test]
fn socket_file_is_nonseekable() {
    let (_weak, file) = socket_file(vfs::OpenFlags::O_RDWR);
    assert_eq!(file.inode().file_type(), vfs::FileType::Socket);
    assert!(!file.f_mode().contains(vfs::Fmode::LSEEK));
    assert!(!file.f_mode().contains(vfs::Fmode::PREAD));
    assert!(!file.f_mode().contains(vfs::Fmode::PWRITE));
}

#[test]
fn socket_file_duplicate_and_fork_release_after_final_close() {
    let (weak, file) = socket_file(vfs::OpenFlags::O_RDWR);
    let parent = vfs::FdTable::new();
    let fd = parent.alloc(file).unwrap();
    let dup = parent.dup(fd).unwrap();
    let child = parent.fork_clone();

    parent.close(fd).unwrap();
    parent.close(dup).unwrap();
    assert!(weak.upgrade().is_some());
    child.close(fd).unwrap();
    assert!(weak.upgrade().is_some());
    child.close(dup).unwrap();
    assert!(weak.upgrade().is_none());
}

#[test]
fn socket_file_active_pin_survives_close_and_exact_fd_reuse() {
    let (old, file) = socket_file(vfs::OpenFlags::O_RDWR);
    let fdt = vfs::FdTable::new();
    let fd = fdt.alloc(file).unwrap();
    let pin = fdt.get(fd).unwrap();

    fdt.close(fd).unwrap();
    let (replacement, replacement_file) = socket_file(
        vfs::OpenFlags::O_RDWR | vfs::OpenFlags::O_NONBLOCK);
    let reused = fdt.alloc(replacement_file).unwrap();
    assert_eq!(reused, fd);
    assert!(!pin.flags().contains(vfs::OpenFlags::O_NONBLOCK));
    assert!(fdt.get(reused).unwrap().flags().contains(vfs::OpenFlags::O_NONBLOCK));
    assert!(old.upgrade().is_some());

    drop(pin);
    assert!(old.upgrade().is_none());
    assert!(replacement.upgrade().is_some());
    fdt.close(reused).unwrap();
    assert!(replacement.upgrade().is_none());
}

#[test]
fn socket_file_failed_publication_and_table_drop_release_synchronously() {
    let (unpublished, file) = socket_file(vfs::OpenFlags::O_RDWR);
    let fdt = vfs::FdTable::new();
    assert_eq!(fdt.install_limit(file, vfs::OpenFlags::empty(), 0),
        Err(vfs::VfsError::Emfile));
    assert!(unpublished.upgrade().is_none());

    let (installed, file) = socket_file(vfs::OpenFlags::O_RDWR);
    let fdt = vfs::FdTable::new();
    fdt.alloc(file).unwrap();
    drop(fdt);
    assert!(installed.upgrade().is_none());
}

#[test]
fn rtnl_multicast_delivers_only_to_subscribers() {
    use alloc::sync::Arc;
    let namespace = network_namespace::initial();
    let a = Arc::new(NetlinkSocket::new(proto::NETLINK_ROUTE, &namespace));
    let b = Arc::new(NetlinkSocket::new(proto::NETLINK_ROUTE, &namespace));
    a.add_membership(1);
    b.add_membership(5);
    register_rtnl_listener(&a);
    register_rtnl_listener(&b);
    let msg = alloc::vec![0xABu8; 8];

    let n = rtnl_multicast(1, &msg);
    assert_eq!(n, 1);
    assert!(a.dequeue().is_some());
    assert!(b.dequeue().is_none());

    let n = rtnl_multicast(5, &msg);
    assert_eq!(n, 1);
    assert!(a.dequeue().is_none());
    assert!(b.dequeue().is_some());

    assert_eq!(rtnl_multicast(0, &msg), 0);
}

#[test]
fn rtnl_multicast_isolates_link_addr_and_route_by_socket_namespace() {
    use alloc::sync::Arc;
    let domain = net::hosted_fixture::init_net_domain();
    domain.set_notifier(crate::mcast::notify_control_event);
    let namespace_a = test_namespace();
    let namespace_b = test_namespace();
    let ns_a = namespace_a.id().as_u64();
    let iface = net::global_stack().ifaces
        .register_in_ns(Arc::new(net::LoopbackDev::new()), ns_a);
    let a = Arc::new(NetlinkSocket::new(proto::NETLINK_ROUTE, &namespace_a));
    let b = Arc::new(NetlinkSocket::new(proto::NETLINK_ROUTE, &namespace_b));
    for group in [
        mcast::grp::RTNLGRP_LINK,
        mcast::grp::RTNLGRP_IPV4_IFADDR,
        mcast::grp::RTNLGRP_IPV4_ROUTE,
    ] {
        a.add_membership(group);
        b.add_membership(group);
    }
    register_rtnl_listener(&a);
    register_rtnl_listener(&b);

    let stack = net::global_stack();
    let generation = stack.ifaces.acquire_ingress(iface).unwrap().generation();
    let rtnl = stack.rtnl_lock();
    let owner = net::control_event::IfaceOwner { iface, generation };
    let namespace_owner = || net::control_event::NamespaceOwner::Live(namespace_a.clone());
    let link_ticket = net::control_event::stage(&rtnl,
        net::control_event::ControlEvent::Link(net::control_event::LinkEvent {
            kind: net::control_event::EventKind::New, namespace: namespace_owner(), owner,
            name: alloc::string::String::from("lo"), mac: net::MacAddr::ZERO, mtu: 65_535,
            broadcast: net::PacketLinkAddress { len: net::MacAddr::ZERO.0.len() as u8,
                bytes: [0; net::PACKET_LINK_ADDRESS_MAX] },
            is_loopback: true, flags: net::netdev::iff::IFF_UP,
            stats: net::NetStats::default(),
        }));
    let addr_ticket = net::control_event::stage(&rtnl,
        net::control_event::ControlEvent::Addr(net::control_event::AddrEvent {
            kind: net::control_event::EventKind::New, namespace: namespace_owner(), owner,
            label: alloc::string::String::from("lo"),
            row: net::iface_addr::Ipv4IfaceAddr {
                ns: ns_a, iface, addr: net::Ipv4Addr::new(198, 18, 61, 1), peer: None,
                prefixlen: 24,
                mask: 0xffff_ff00, broadcast: None, scope: rtnetlink::RT_SCOPE_UNIVERSE,
                flags: net::iface_addr::IFA_F_PERMANENT,
                cacheinfo: net::iface_addr::Ipv4AddrCacheInfo::PERMANENT,
            },
        }));
    let row = rtnetlink::RouteRow {
            ns: ns_a, table: rtnetlink::RT_TABLE_MAIN as u32,
            protocol: rtnetlink::RTPROT_STATIC, scope: rtnetlink::RT_SCOPE_LINK,
            kind: rtnetlink::RTN_UNICAST, dst: Some(([198, 18, 61, 0], 24)),
            gateway: None, oif_ifindex: iface.raw(), prefsrc: None,
            metric: 0, mtu: None, flags: 0, weight: 1, nh_flags: 0,
        };
    let route_ticket = net::control_event::stage(&rtnl,
        net::control_event::ControlEvent::Route(net::control_event::RouteEvent {
            kind: net::control_event::EventKind::New, namespace: namespace_owner(),
            owners: alloc::vec![owner], leases: alloc::vec::Vec::new(),
            records: alloc::vec![rtnetlink::route_state::to_record(row)],
        }));
    drop(rtnl);
    net::control_event::publish(link_ticket);
    net::control_event::publish(addr_ticket);
    net::control_event::publish(route_ticket);

    for ty in [
        rtnetlink::RTM_NEWLINK,
        rtnetlink::RTM_NEWADDR,
        rtnetlink::RTM_NEWROUTE,
    ] {
        let (msg, src) = a.dequeue().expect("mutation namespace listener receives notification");
        assert_eq!(src, 0);
        assert_eq!(Nlmsghdr::parse(&msg).unwrap().nlmsg_type, ty);
    }
    assert!(b.dequeue().is_none(), "other network namespace must not receive rtnetlink multicast");
    let _ = net::global_stack().ifaces.unregister(iface);
}
