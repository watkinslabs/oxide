use super::*;

#[test]
fn device_uevent_replay_uses_nested_canonical_devpath() {
    use netlink::{proto, NetlinkSocket};

    let listener = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT));
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
