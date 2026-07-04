use super::*;

#[test]
fn addr_formatting_pci() {
    let a = alloc::format!("{:04x}:{:02x}:{:02x}.{}", 0u16, 0u8, 3u8, 0u8);
    assert_eq!(a, "0000:00:03.0");
}

#[test]
fn device_add_and_bind() {
    let d = device_add(Arc::new(Device::new(
        "pci", alloc::string::String::from("0000:00:09.0"), 0x1AF4, 0x1042, 0x010000)));
    register_driver(&FAKE);
    assert_eq!(d.bound(), Some("fake-virtio-blk"));
    assert_eq!(bind(&d, "fake-virtio-blk"), Err(crate::Error::AlreadyBound));
    assert!(devices().iter().any(|x| x.addr == "0000:00:09.0"));
}

#[test]
fn matches_on_device_id() {
    register_driver(&FAKE);
    let dev = Device::new("pci", alloc::string::String::from("0000:00:0a.0"), 0x1AF4, 0x1042, 0);
    assert_eq!(match_driver(&dev), Some("fake-virtio-blk"));
    let other = Device::new("pci", alloc::string::String::from("0000:00:0b.0"), 0x1AF4, 0x1041, 0);
    assert_eq!(match_driver(&other), None);
    assert!(driver_names().contains(&"fake-virtio-blk"));
}

#[test]
fn driver_override_controls_matching_and_bind() {
    register_driver(&FAKE);
    register_driver(&OVERRIDE);
    let d = Arc::new(Device::new(
        "pci", alloc::string::String::from("0000:00:0e.0"), 0x1AF4, 0x1042, 0));
    d.set_driver_override(Some(String::from("override-only")));
    let d = device_add(d);
    assert_eq!(match_driver(&d), Some("override-only"));
    assert_eq!(d.bound(), Some("override-only"));
    assert_eq!(bind(&d, "fake-virtio-blk"), Err(crate::Error::AlreadyBound));
}

#[test]
fn driver_names_are_bus_scoped() {
    register_driver(&FAKE);
    register_driver(&PLATFORM);
    assert!(driver_names_for_bus("pci").contains(&"fake-virtio-blk"));
    assert!(!driver_names_for_bus("pci").contains(&"platform-test"));
    assert!(driver_names_for_bus("platform").contains(&"platform-test"));
    assert!(!driver_names_for_bus("platform").contains(&"fake-virtio-blk"));
}

#[test]
fn bind_resolves_driver_on_device_bus() {
    register_driver(&PLATFORM);
    let platform = device_add(Arc::new(Device::new(
        "platform", String::from("test0"), 0, 0, 0)));
    let pci = device_add(Arc::new(Device::new(
        "pci", String::from("0000:00:0f.0"), 0, 0, 0)));
    assert_eq!(platform.bound(), Some("platform-test"));
    assert_eq!(bind(&platform, "platform-test"), Err(crate::Error::AlreadyBound));
    assert_eq!(bind(&pci, "platform-test"), Err(crate::Error::NotFound));
}

#[test]
fn child_device_records_parent_identity() {
    let virtio = Device::new("virtio", String::from("virtio0"), 0x1AF4, 2, 0)
        .with_parent("pci", String::from("0000:00:04.0"));
    assert_eq!(virtio.parent(), Some(("pci", "0000:00:04.0")));
}

#[test]
fn driver_override_stays_on_device_bus() {
    register_driver(&PLATFORM);
    let pci = Device::new("pci", String::from("0000:00:10.0"), 0, 0, 0);
    pci.set_driver_override(Some(String::from("platform-test")));
    assert_eq!(match_driver(&pci), None);
}
