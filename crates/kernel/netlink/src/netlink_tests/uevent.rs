use core::sync::atomic::Ordering;

use crate::*;

#[test]
fn raw_uevent_delivers_only_to_kernel_group() {
    use alloc::sync::Arc;
    let namespace = crate::netlink_tests::test_namespace();
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
    let udevd = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT, &crate::netlink_tests::test_namespace()));
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
    let namespace = crate::netlink_tests::test_namespace();
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
    let namespace = crate::netlink_tests::test_namespace();
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
