use core::sync::atomic::Ordering;

use crate::*;

fn namespace_dropped() {}

pub(crate) fn test_namespace() -> network_namespace::NetworkNamespaceRef {
    network_namespace::install_final_drop_callback(namespace_dropped).unwrap();
    net::control_event::set_notifier(crate::mcast::notify_control_event);
    network_namespace::allocate(0).unwrap()
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
fn socket_retains_concrete_namespace_owner_until_close() {
    use alloc::sync::{Arc, Weak};

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
                mask: 0xffff_ff00, scope: rtnetlink::RT_SCOPE_UNIVERSE,
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

#[test]
fn raw_uevent_delivers_only_to_kernel_group() {
    use alloc::sync::Arc;
    let namespace = network_namespace::initial();
    let udevd = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT, &namespace));
    let monitor = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT, &namespace));
    udevd.set_group_mask(1);
    monitor.set_group_mask(0);
    register_uevent_listener(&udevd);
    register_uevent_listener(&monitor);

    let n = emit_uevent("add", "/devices/virtual/drm/card0", "drm");
    assert_eq!(n, 1);
    assert!(udevd.dequeue().is_some());
    assert!(monitor.dequeue().is_none());
}

#[test]
fn raw_uevent_stays_level_ready_until_consumed() {
    use alloc::sync::Arc;
    let udevd = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT, &network_namespace::initial()));
    udevd.set_group_mask(1);
    register_uevent_listener(&udevd);

    let n = emit_uevent_with_env(
        "add",
        "/devices/pci0000:00/0000:00:04.0/virtio3/drm/card0",
        "drm",
        &["DEVNAME=dri/card0", "MAJOR=226", "MINOR=0", "DEVTYPE=drm_minor"]);
    assert_eq!(n, 1);
    assert_ne!(udevd.poll() & vfs::POLL_IN, 0, "queued coldplug uevent must poll readable");

    let (msg, src) = udevd.peek_front().expect("queued uevent");
    assert_eq!(src, 0);
    assert!(msg.split(|b| *b == 0).any(|e| e == b"ACTION=add"));
    assert!(msg.split(|b| *b == 0).any(|e| e == b"DEVPATH=/devices/pci0000:00/0000:00:04.0/virtio3/drm/card0"));
    assert!(msg.split(|b| *b == 0).any(|e| e == b"SUBSYSTEM=drm"));
    assert!(msg.split(|b| *b == 0).any(|e| e == b"DEVNAME=dri/card0"));
    assert!(msg.split(|b| *b == 0).any(|e| e == b"MAJOR=226"));
    assert!(msg.split(|b| *b == 0).any(|e| e == b"MINOR=0"));
    assert!(msg.split(|b| *b == 0).any(|e| e == b"DEVTYPE=drm_minor"));
}

#[test]
fn cooked_uevent_reaches_only_subscribed_udev_group_monitors() {
    use alloc::sync::Arc;
    let namespace = network_namespace::initial();
    let sender = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT, &namespace));
    let kernel_listener = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT, &namespace));
    let worker_none = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT, &namespace));
    let udev_monitor = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT, &namespace));
    sender.set_group_mask(2);
    kernel_listener.set_group_mask(1);
    worker_none.set_group_mask(0);
    udev_monitor.set_group_mask(2);
    register_uevent_listener(&sender);
    register_uevent_listener(&kernel_listener);
    register_uevent_listener(&worker_none);
    register_uevent_listener(&udev_monitor);

    let msg = b"libudev\0ACTION=add\0SUBSYSTEM=drm\0";
    let n = rebroadcast_cooked_uevent(msg, 2, &sender);
    assert_eq!(n, 1, "only the group-2 subscriber receives it");
    assert!(sender.dequeue().is_none());
    assert!(kernel_listener.dequeue().is_none());
    assert!(worker_none.dequeue().is_none(), "group-0 worker monitor is NOT flooded");
    assert_eq!(udev_monitor.dequeue().map(|(m, _)| m).as_deref(), Some(&msg[..]));
}

#[test]
fn unicast_reaches_only_target_port_with_sender_stamped() {
    use alloc::sync::Arc;
    let namespace = network_namespace::initial();
    let manager = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT, &namespace));
    let worker_a = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT, &namespace));
    let worker_b = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT, &namespace));
    worker_a.set_group_mask(0);
    worker_b.set_group_mask(0);
    register_uevent_listener(&manager);
    register_uevent_listener(&worker_a);
    register_uevent_listener(&worker_b);

    let mgr_port = manager.port_id.load(Ordering::Acquire);
    let a_port = worker_a.port_id.load(Ordering::Acquire);
    let msg = b"libudev\0ACTION=add\0SEQNUM=42\0";
    let delivered = unicast_uevent_to_port(a_port, msg, mgr_port);
    assert_eq!(delivered, 1, "unicast found the target port");
    assert!(worker_b.dequeue().is_none(), "non-target worker got nothing");
    let got = worker_a.dequeue().expect("target worker got the datagram");
    assert_eq!(got.0.as_slice(), &msg[..]);
    assert_eq!(got.1, mgr_port, "sender port stamped for the receiver");
}
