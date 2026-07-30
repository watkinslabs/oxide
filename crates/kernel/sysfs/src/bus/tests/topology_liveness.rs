use super::*;

const TEST_VIRTIO_VENDOR_ID: u16 = 0x1af4;
const TEST_VIRTIO_INPUT_DEVICE_ID: u16 = 18;
const TEST_PCI_DEVICE_ID: u16 = 0x1052;
const TEST_CHILD_MAJOR: u32 = 240;
const TEST_CHILD_MINOR: u32 = 199;
const OLD_PLATFORM_VENDOR_ID: u16 = 0x1111;
const REPLACEMENT_PLATFORM_VENDOR_ID: u16 = 0x2222;
const REPLACEMENT_PLATFORM_DEVICE_ID: u16 = 2;
const ATTRIBUTE_READ_BUFFER_BYTES: usize = 64;

#[test]
fn ancestor_removal_hides_child_from_every_generic_projection() {
    let pci_addr = "0000:00:2c.0";
    let child_addr = "sysfs-orphan-child0";
    let pci = drv::try_device_add(Arc::new(drv::Device::new(
        "pci",
        String::from(pci_addr),
        TEST_VIRTIO_VENDOR_ID,
        TEST_PCI_DEVICE_ID,
        0,
    ))).expect("PCI ancestor");
    let child = drv::try_device_add(Arc::new(
        drv::Device::new(
            "virtio",
            String::from(child_addr),
            TEST_VIRTIO_VENDOR_ID,
            TEST_VIRTIO_INPUT_DEVICE_ID,
            0,
        )
            .with_parent("pci", String::from(pci_addr))
            .with_devnode(
                "misc",
                String::from("orphan-child0"),
                Some((TEST_CHILD_MAJOR, TEST_CHILD_MINOR)),
            ),
    )).expect("nested child");

    let bus_devices = make_bus_devices_inode("virtio");
    let bus_link = bus_devices.lookup(child_addr).expect("bus device link");
    assert_eq!(
        bus_link.readlink().expect("readlink"),
        b"../../../devices/pci0000:00/0000:00:2c.0/sysfs-orphan-child0".to_vec(),
    );
    let child_dir = make_devices_root_inode("pci")
        .lookup(pci_addr).expect("PCI directory")
        .lookup(child_addr).expect("nested child directory");
    let retained_uevent = child_dir.lookup("uevent").expect("child uevent");
    let index = make_sys_dev_index_inode(DevIndexKind::Char);
    let child_index = alloc::format!("{TEST_CHILD_MAJOR}:{TEST_CHILD_MINOR}");
    let index_link = index.lookup(&child_index).expect("char index");
    assert_eq!(
        index_link.readlink().expect("readlink"),
        b"../../devices/pci0000:00/0000:00:2c.0/sysfs-orphan-child0".to_vec(),
    );
    assert_eq!(
        dev_devpath(&child).as_deref(),
        Some("/devices/pci0000:00/0000:00:2c.0/sysfs-orphan-child0"),
    );

    drv::device_del(&pci);
    assert_eq!(drv::device_canon("virtio", child_addr), None);
    assert_eq!(bus_devices.lookup(child_addr).err(), Some(VfsError::Enoent));
    assert_eq!(index.lookup(&child_index).err(), Some(VfsError::Enoent));
    assert_eq!(bus_link.readlink().err(), Some(VfsError::Enoent));
    assert_eq!(index_link.readlink().err(), Some(VfsError::Enoent));
    assert_eq!(dev_devpath(&child), None);
    assert_eq!(child_dir.lookup("subsystem").err(), Some(VfsError::Enoent));
    assert_eq!(
        retained_uevent.write(0, b"change\n").err(),
        Some(VfsError::Enoent),
    );

    let replacement = drv::try_device_add(Arc::new(drv::Device::new(
        "pci",
        String::from(pci_addr),
        TEST_VIRTIO_VENDOR_ID,
        TEST_PCI_DEVICE_ID,
        0,
    ))).expect("same-name replacement ancestor");
    assert_eq!(drv::device_canon("virtio", child_addr), None);
    assert_eq!(bus_devices.lookup(child_addr).err(), Some(VfsError::Enoent));

    drv::device_del(&child);
    drv::device_del(&replacement);
}

#[test]
fn retained_device_inode_does_not_alias_same_name_replacement() {
    let addr = "sysfs-retained-reuse0";
    let old = drv::try_device_add(Arc::new(drv::Device::new(
        "platform",
        String::from(addr),
        OLD_PLATFORM_VENDOR_ID,
        1,
        0,
    ))).expect("old device");
    let root = make_devices_root_inode("platform");
    let old_dir = root.lookup(addr).expect("old directory");
    let old_vendor = old_dir.lookup("modalias").expect("old attribute");
    let old_subsystem = old_dir.lookup("subsystem").expect("old symlink");

    drv::device_del(&old);
    assert!(matches!(
        drv::try_device_add(Arc::clone(&old)),
        Err(drv::Error::Removed),
    ));
    let replacement = drv::try_device_add(Arc::new(drv::Device::new(
        "platform",
        String::from(addr),
        REPLACEMENT_PLATFORM_VENDOR_ID,
        REPLACEMENT_PLATFORM_DEVICE_ID,
        0,
    ))).expect("replacement device");

    let mut buf = [0u8; ATTRIBUTE_READ_BUFFER_BYTES];
    assert_eq!(old_vendor.read(0, &mut buf).err(), Some(VfsError::Enodev));
    assert_eq!(old_subsystem.readlink().err(), Some(VfsError::Enoent));
    assert_eq!(old_dir.lookup("modalias").err(), Some(VfsError::Enoent));
    let current = root.lookup(addr).expect("replacement directory");
    let attr = current.lookup("modalias").expect("replacement attribute");
    let n = attr.read(0, &mut buf).expect("read replacement");
    assert_eq!(&buf[..n], b"platform:sysfs-retained-reuse0\n");

    drv::device_del(&replacement);
}
