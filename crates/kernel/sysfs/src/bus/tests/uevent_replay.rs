use super::*;

const TEST_VIRTIO_VENDOR_ID: u16 = 0x1af4;
const TEST_VIRTIO_BLOCK_DEVICE_ID: u16 = 2;
const TEST_VIRTIO_GPU_DEVICE_ID: u16 = 16;
const TEST_PARENT_PCI_DEVICE_ID: u16 = 0x1000;
const TEST_STORAGE_PCI_CLASS: u32 = 0x010000;
const TEST_GPU_PCI_DEVICE_ID: u16 = 0x1050;
const TEST_GPU_PCI_CLASS: u32 = 0x030000;
const INDEXED_CARD_MINOR: u32 = 13;
const ATTRIBUTE_READ_BUFFER_BYTES: usize = 16;

#[test]
fn device_uevent_replay_uses_nested_canonical_devpath() {
    use netlink::{proto, NetlinkSocket};

    let listener = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT, &network_namespace::initial()));
    listener.set_group_mask(netlink::KOBJECT_UEVENT_KERNEL_GROUP_MASK);
    netlink::register_uevent_listener(&listener);

    let parent = Arc::new(drv::Device::new(
        "pci",
        String::from("0000:00:31.0"),
        TEST_VIRTIO_VENDOR_ID,
        TEST_PARENT_PCI_DEVICE_ID,
        TEST_STORAGE_PCI_CLASS,
    ));
    drv::try_device_add(Arc::clone(&parent)).expect("parent registered");
    let child = Arc::new(drv::Device::new(
        "virtio",
        String::from("sysfs-replay-child0"),
        0,
        TEST_VIRTIO_BLOCK_DEVICE_ID,
        0,
    )
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
    listener.set_group_mask(netlink::KOBJECT_UEVENT_KERNEL_GROUP_MASK);
    netlink::register_uevent_listener(&listener);

    let pci = Arc::new(
        drv::Device::new(
            "pci",
            String::from("0000:00:04.0"),
            TEST_VIRTIO_VENDOR_ID,
            TEST_GPU_PCI_DEVICE_ID,
            TEST_GPU_PCI_CLASS,
        ));
    let virtio = Arc::new(
        drv::Device::new(
            "virtio",
            String::from("virtio3"),
            TEST_VIRTIO_VENDOR_ID,
            TEST_VIRTIO_GPU_DEVICE_ID,
            0,
        )
            .with_parent("pci", String::from("0000:00:04.0")));
    let card = Arc::new(
        drv::Device::new("drm", String::from("card0"), 0, 0, 0)
            .with_parent("virtio", String::from("virtio3"))
            .with_sysfs_relpath(String::from("drm/card0"))
            .with_devnode("drm", String::from("dri/card0"), Some((::drm::DRM_MAJOR, 0))));
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

    let major_env = alloc::format!("MAJOR={}", ::drm::DRM_MAJOR);
    let msg = next_uevent_matching(&listener, &[
        b"ACTION=add",
        b"DEVPATH=/devices/pci0000:00/0000:00:04.0/virtio3/drm/card0",
        b"SUBSYSTEM=drm",
        b"DEVNAME=dri/card0",
        major_env.as_bytes(),
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
        drv::Device::new(
            "pci",
            String::from("0000:00:04.1"),
            TEST_VIRTIO_VENDOR_ID,
            TEST_GPU_PCI_DEVICE_ID,
            TEST_GPU_PCI_CLASS,
        ));
    let virtio = Arc::new(
        drv::Device::new(
            "virtio",
            String::from("virtio13"),
            TEST_VIRTIO_VENDOR_ID,
            TEST_VIRTIO_GPU_DEVICE_ID,
            0,
        )
            .with_parent("pci", String::from("0000:00:04.1")));
    let card = Arc::new(
        drv::Device::new("drm", String::from("card13"), 0, 0, 0)
            .with_parent("virtio", String::from("virtio13"))
            .with_sysfs_relpath(String::from("drm/card13"))
            .with_devnode(
                "drm",
                String::from("dri/card13"),
                Some((::drm::DRM_MAJOR, INDEXED_CARD_MINOR)),
            ));
    drv::try_device_add(Arc::clone(&pci)).expect("pci registration");
    drv::try_device_add(Arc::clone(&virtio)).expect("virtio registration");
    drv::try_device_add(Arc::clone(&card)).expect("drm registration");

    let index = make_sys_dev_index_inode(DevIndexKind::Char);
    let card_index = alloc::format!("{}:{INDEXED_CARD_MINOR}", ::drm::DRM_MAJOR);
    let link = index.lookup(&card_index).expect("DRM char index");
    assert_eq!(
        link.readlink().expect("readlink DRM char index"),
        b"../../devices/pci0000:00/0000:00:04.1/virtio13/drm/card13".to_vec());

    let card_dir = make_devices_root_inode("pci")
        .lookup("0000:00:04.1").expect("pci device dir")
        .lookup("virtio13").expect("virtio under pci")
        .lookup("drm").expect("drm container")
        .lookup("card13").expect("card13 dir");

    let mut dev_buf = [0u8; ATTRIBUTE_READ_BUFFER_BYTES];
    let dev_attr = card_dir.lookup("dev").expect("card dev attr");
    let n = dev_attr.read(0, &mut dev_buf).expect("read dev attr");
    let expected_dev = alloc::format!("{card_index}\n");
    assert_eq!(&dev_buf[..n], expected_dev.as_bytes());

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
