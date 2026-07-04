use core::sync::atomic::Ordering;

use crate::*;

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
fn port_ids_are_unique() {
    let a = alloc_port_id();
    let b = alloc_port_id();
    assert_ne!(a, b);
}

#[test]
fn membership_bits_map_group_minus_one() {
    let s = NetlinkSocket::new(proto::NETLINK_ROUTE);
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
fn rtnl_multicast_delivers_only_to_subscribers() {
    use alloc::sync::Arc;
    let a = Arc::new(NetlinkSocket::new(proto::NETLINK_ROUTE));
    let b = Arc::new(NetlinkSocket::new(proto::NETLINK_ROUTE));
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
fn raw_uevent_delivers_only_to_kernel_group() {
    use alloc::sync::Arc;
    let udevd = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT));
    let monitor = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT));
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
fn cooked_uevent_reaches_only_subscribed_udev_group_monitors() {
    use alloc::sync::Arc;
    let sender = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT));
    let kernel_listener = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT));
    let worker_none = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT));
    let udev_monitor = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT));
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
    let manager = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT));
    let worker_a = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT));
    let worker_b = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT));
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
