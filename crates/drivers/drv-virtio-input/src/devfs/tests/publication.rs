use alloc::{string::String, sync::Arc};

use crate::devfs::{make_evdev_inode, register_node, unregister_node};
use crate::devfs::shared::EVDEV_DEVICES;
use crate::evdev_queue::MAX_EVDEV;

const VIRTIO_VENDOR_ID: u16 = 0x1af4;
const VIRTIO_INPUT_DEVICE_ID: u16 = 18;

#[test]
fn register_node_is_idempotent_without_republishing() {
    let id = (MAX_EVDEV - 1) as u32;
    let _ = unregister_node(id);

    assert!(register_node(id, None));
    assert!(!register_node(id, None));
    assert_eq!(
        drv::devices()
            .iter()
            .filter(|d| d.bus == "input" && d.addr == alloc::format!("event{id}"))
            .count(),
        1
    );
    assert!(unregister_node(id));
}

#[test]
fn evdev_inode_reports_linux_input_dev_t() {
    let id = (MAX_EVDEV - 1) as u32;
    let inode = make_evdev_inode(id);
    assert_eq!(
        inode.rdev(),
        vfs::Devt::new(input::INPUT_MAJOR, input::EVENT_MINOR_BASE + id).raw(),
    );
}

#[test]
fn register_node_records_exact_parent_and_owned_sysfs_path() {
    let id = (MAX_EVDEV - 4) as u32;
    let addr = alloc::format!("event{id}");
    let parent_addr = String::from("virtio-input-parent0");
    let _ = unregister_node(id);
    let parent = drv::try_device_add(Arc::new(drv::Device::new(
        "virtio",
        parent_addr.clone(),
        VIRTIO_VENDOR_ID,
        VIRTIO_INPUT_DEVICE_ID,
        0,
    ))).expect("parent registration");

    assert!(register_node(id, Some(&parent)));
    let dev = drv::devices()
        .into_iter()
        .find(|d| d.bus == "input" && d.addr == addr)
        .expect("registered input event device");
    assert_eq!(dev.parent(), Some(("virtio", parent_addr.as_str())));
    assert!(drv::device_canon_exact(&dev)
        .expect("canonical input path")
        .contains("/input/input"));

    assert!(unregister_node(id));
    drv::device_del(&parent);
}

#[test]
fn register_node_rejects_removed_exact_parent() {
    let id = (MAX_EVDEV - 5) as u32;
    let _ = unregister_node(id);
    let parent = drv::try_device_add(Arc::new(drv::Device::new(
        "virtio",
        String::from("removed-virtio-input-parent"),
        VIRTIO_VENDOR_ID,
        VIRTIO_INPUT_DEVICE_ID,
        0,
    ))).expect("parent registration");
    drv::device_del(&parent);

    assert!(!register_node(id, Some(&parent)));
    assert!(EVDEV_DEVICES.lock()[id as usize].is_none());
}

#[test]
fn register_node_rejects_parent_with_removed_transitive_ancestor() {
    const PCI_DEVICE_ID: u16 = 0x1052;

    let id = (MAX_EVDEV - 6) as u32;
    let pci_addr = String::from("0000:00:2d.0");
    let parent_addr = String::from("virtio-input-orphan");
    let _ = unregister_node(id);
    let pci = drv::try_device_add(Arc::new(drv::Device::new(
        "pci",
        pci_addr.clone(),
        VIRTIO_VENDOR_ID,
        PCI_DEVICE_ID,
        0,
    ))).expect("pci ancestor");
    let parent = drv::try_device_add(Arc::new(
        drv::Device::new(
            "virtio",
            parent_addr,
            VIRTIO_VENDOR_ID,
            VIRTIO_INPUT_DEVICE_ID,
            0,
        ).with_parent("pci", pci_addr),
    )).expect("virtio parent");
    drv::device_del(&pci);

    assert!(!register_node(id, Some(&parent)));
    assert!(EVDEV_DEVICES.lock()[id as usize].is_none());
    drv::device_del(&parent);
}

#[test]
fn unregister_then_register_restores_model_owned_event_node() {
    let id = (MAX_EVDEV - 3) as u32;
    let addr = alloc::format!("event{id}");
    let _ = unregister_node(id);

    for _ in 0..2 {
        assert!(register_node(id, None));
        assert!(EVDEV_DEVICES.lock()[id as usize].is_some());
        assert_eq!(
            drv::devices()
                .iter()
                .filter(|d| d.bus == "input" && d.addr == addr)
                .count(),
            1,
        );
        assert!(unregister_node(id));
        assert!(EVDEV_DEVICES.lock()[id as usize].is_none());
    }
}

#[test]
fn register_node_leaves_slot_free_when_model_publication_conflicts() {
    let id = (MAX_EVDEV - 2) as u32;
    let _ = unregister_node(id);
    let addr = alloc::format!("event{id}");
    let conflict = drv::try_device_add(Arc::new(
        drv::Device::new("input", String::from(addr.as_str()), 0, 0, id)
            .with_devnode(
                "input",
                alloc::format!("input/event{id}"),
                Some((input::INPUT_MAJOR, input::EVENT_MINOR_BASE + id)),
            ),
    )).expect("conflict device registration");

    assert!(!register_node(id, None));
    assert!(EVDEV_DEVICES.lock()[id as usize].is_none());
    drv::device_del(&conflict);
    assert!(register_node(id, None));
    assert!(unregister_node(id));
}
