use super::*;

#[test]
fn device_uevent_replay_uses_nested_canonical_devpath() {
    use netlink::{proto, NetlinkSocket};

    let listener = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT, &network_namespace::initial()));
    listener.set_group_mask(1);
    netlink::register_uevent_listener(&listener);

    let parent = Arc::new(drv::Device::new(
        "pci", String::from("0000:00:31.0"), 0x1af4, 0x1000, 0x010000));
    drv::try_device_add(Arc::clone(&parent)).expect("parent registered");
    let child = Arc::new(drv::Device::new(
        "virtio", String::from("sysfs-replay-child0"), 0, 2, 0)
        .with_parent("pci", String::from("0000:00:31.0")));
    drv::try_device_add(Arc::clone(&child)).expect("child registered");

    let pci_root = make_devices_root_inode("pci");
    let child_dir = pci_root
        .lookup("0000:00:31.0")
        .expect("pci device dir")
        .lookup("sysfs-replay-child0")
        .expect("nested virtio child dir");
    let uevent = child_dir.lookup("uevent").expect("uevent attr");
    assert_eq!(uevent.write(0, b"change\n"), Ok("change\n".len()));

    let msg = next_uevent_matching(&listener, &[
        b"ACTION=change",
        b"DEVPATH=/devices/pci0000:00/0000:00:31.0/sysfs-replay-child0",
        b"SUBSYSTEM=virtio",
    ]);
    assert!(uevent_has_entry(
        &msg,
        b"DEVPATH=/devices/pci0000:00/0000:00:31.0/sysfs-replay-child0"
    ));
    assert!(!uevent_has_entry(&msg, b"DEVPATH=/devices/virtio/sysfs-replay-child0"));

    drv::device_del(&child);
    drv::device_del(&parent);
}

#[test]
fn parented_drm_card_uevent_replay_matches_udev_seat_rules() {
    use netlink::{proto, NetlinkSocket};

    let listener = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT, &network_namespace::initial()));
    listener.set_group_mask(1);
    netlink::register_uevent_listener(&listener);

    let pci = Arc::new(
        drv::Device::new("pci", String::from("0000:00:04.0"), 0x1af4, 0x1050, 0x030000));
    let virtio = Arc::new(
        drv::Device::new("virtio", String::from("virtio3"), 0x1af4, 16, 0)
            .with_parent("pci", String::from("0000:00:04.0")));
    let card = Arc::new(
        drv::Device::new("drm", String::from("card0"), 0, 0, 0)
            .with_parent("virtio", String::from("virtio3"))
            .with_devnode("drm", String::from("dri/card0"), Some((226, 0))));
    drv::try_device_add(Arc::clone(&pci)).expect("pci registration");
    drv::try_device_add(Arc::clone(&virtio)).expect("virtio registration");
    drv::try_device_add(Arc::clone(&card)).expect("drm registration");

    let card_dir = make_devices_root_inode("pci")
        .lookup("0000:00:04.0").expect("pci device dir")
        .lookup("virtio3").expect("virtio under pci")
        .lookup("drm").expect("drm container")
        .lookup("card0").expect("card0 dir");
    let uevent = card_dir.lookup("uevent").expect("card0 uevent attr");
    assert_eq!(uevent.write(0, b"add\n"), Ok("add\n".len()));

    let msg = next_uevent_matching(&listener, &[
        b"ACTION=add",
        b"DEVPATH=/devices/pci0000:00/0000:00:04.0/virtio3/drm/card0",
        b"SUBSYSTEM=drm",
        b"DEVNAME=dri/card0",
        b"MAJOR=226",
        b"MINOR=0",
        b"DEVTYPE=drm_minor",
    ]);
    assert!(uevent_has_entry(&msg, b"DEVPATH=/devices/pci0000:00/0000:00:04.0/virtio3/drm/card0"));
    assert!(!uevent_has_entry(&msg, b"DEVPATH=/devices/virtual/drm/card0"));

    drv::device_del(&card);
    drv::device_del(&virtio);
    drv::device_del(&pci);
}

#[test]
fn parented_drm_card_sd_device_devnum_chain_is_complete() {
    let pci = Arc::new(
        drv::Device::new("pci", String::from("0000:00:04.1"), 0x1af4, 0x1050, 0x030000));
    let virtio = Arc::new(
        drv::Device::new("virtio", String::from("virtio13"), 0x1af4, 16, 0)
            .with_parent("pci", String::from("0000:00:04.1")));
    let card = Arc::new(
        drv::Device::new("drm", String::from("card13"), 0, 0, 0)
            .with_parent("virtio", String::from("virtio13"))
            .with_devnode("drm", String::from("dri/card13"), Some((226, 13))));
    drv::try_device_add(Arc::clone(&pci)).expect("pci registration");
    drv::try_device_add(Arc::clone(&virtio)).expect("virtio registration");
    drv::try_device_add(Arc::clone(&card)).expect("drm registration");

    let index = make_sys_dev_index_inode(DevIndexKind::Char);
    let link = index.lookup("226:13").expect("/sys/dev/char/226:13");
    assert_eq!(
        link.readlink().expect("readlink /sys/dev/char/226:13"),
        b"../../devices/pci0000:00/0000:00:04.1/virtio13/drm/card13".to_vec());

    let card_dir = make_devices_root_inode("pci")
        .lookup("0000:00:04.1").expect("pci device dir")
        .lookup("virtio13").expect("virtio under pci")
        .lookup("drm").expect("drm container")
        .lookup("card13").expect("card13 dir");

    let mut dev_buf = [0u8; 16];
    let dev_attr = card_dir.lookup("dev").expect("card dev attr");
    let n = dev_attr.read(0, &mut dev_buf).expect("read dev attr");
    assert_eq!(&dev_buf[..n], b"226:13\n");

    let subsystem = card_dir.lookup("subsystem").expect("card subsystem");
    assert_eq!(
        subsystem.readlink().expect("read subsystem"),
        b"../../../../../../class/drm".to_vec());

    let device = card_dir.lookup("device").expect("card device parent link");
    assert_eq!(device.readlink().expect("read device link"), b"../..".to_vec());

    drv::device_del(&card);
    drv::device_del(&virtio);
    drv::device_del(&pci);
}
