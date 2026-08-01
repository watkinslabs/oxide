use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::model::{devices, Device};
use crate::KResult;

const BLOCK_ROOT: &str = "devices/virtual/block";
const DRM_ROOT: &str = "devices/virtual/drm";
const GRAPHICS_ROOT: &str = "devices/virtual/graphics";
const INPUT_ROOT: &str = "devices/virtual/input";
const MEM_ROOT: &str = "devices/virtual/mem";
const MISC_ROOT: &str = "devices/virtual/misc";
const PCI_ROOT: &str = "devices/pci0000:00";
const PLATFORM_ROOT: &str = "devices/platform";
const SOUND_ROOT: &str = "devices/virtual/sound";
const TTY_ROOT: &str = "devices/virtual/tty";
const VIRTIO_ROOT: &str = "devices/virtio";

/// Reject path components that cannot identify one canonical sysfs object.
/// # C: O(path length)
pub(crate) fn validate_sysfs_relpath(dev: &Device) -> KResult<()> {
    let Some(path) = dev.sysfs_relpath.as_deref() else { return Ok(()); };
    if path.is_empty()
        || path.split('/').any(|component| {
            component.is_empty() || component == "." || component == ".."
        })
    {
        return Err(crate::Error::Invalid);
    }
    Ok(())
}

fn sysfs_relpath(dev: &Device) -> &str {
    dev.sysfs_relpath.as_deref().unwrap_or(dev.addr.as_str())
}

/// Canonical driver-model root below `/sys` for a bus/class. # C: O(1)
pub fn device_root_canon(bus: &str) -> Option<&'static str> {
    Some(match bus {
        "pci" => PCI_ROOT,
        "virtio" => VIRTIO_ROOT,
        "platform" => PLATFORM_ROOT,
        "block" => BLOCK_ROOT,
        "input" => INPUT_ROOT,
        "drm" => DRM_ROOT,
        "mem" => MEM_ROOT,
        "misc" => MISC_ROOT,
        "sound" => SOUND_ROOT,
        "graphics" => GRAPHICS_ROOT,
        "tty" => TTY_ROOT,
        _ => return None,
    })
}

fn find<'a>(devices: &'a [Arc<Device>], bus: &str, addr: &str) -> Option<&'a Arc<Device>> {
    devices.iter().find(|dev| dev.bus == bus && dev.addr == addr)
}

/// Capture the exact direct parent and every live transitive ancestor while
/// the model registry is locked. Supplying a previously resolved parent also
/// closes remove/re-add ABA races by pointer.
/// # C: O(parent depth * N_devices)
pub(crate) fn bind_parent_chain(
    devices: &[Arc<Device>],
    child: &Device,
    expected: Option<&Arc<Device>>,
) -> KResult<()> {
    child.parent_chain.lock().clear();
    let Some((bus, addr)) = child.parent() else {
        return if expected.is_some() { Err(crate::Error::NoMatch) } else { Ok(()) };
    };
    let Some(mut current) = find(devices, bus, addr) else {
        return Err(crate::Error::NotFound);
    };
    if let Some(expected) = expected {
        if expected.bus != bus || expected.addr != addr {
            return Err(crate::Error::NoMatch);
        }
        if !Arc::ptr_eq(current, expected) {
            return Err(crate::Error::NotFound);
        }
    }
    let mut chain = Vec::new();
    for _ in 0..devices.len() {
        if !current.lifecycle.is_live() {
            return Err(crate::Error::NotFound);
        }
        chain.push(Arc::clone(current));
        let Some((parent_bus, parent_addr)) = current.parent() else {
            *child.parent_chain.lock() = chain;
            return Ok(());
        };
        let Some(parent) = find(devices, parent_bus, parent_addr) else {
            return Err(crate::Error::NotFound);
        };
        current = parent;
    }
    Err(crate::Error::NotFound)
}

fn parent_chain_canon(dev: &Device) -> Option<String> {
    let chain = dev.parent_chain.lock();
    let direct = chain.first()?;
    let (bus, addr) = dev.parent()?;
    if direct.bus != bus || direct.addr != addr {
        return None;
    }
    if chain.iter().any(|ancestor| !ancestor.lifecycle.is_visible()) {
        return None;
    }
    let root = chain.last()?;
    let mut canon = alloc::format!(
        "{}/{}",
        device_root_canon(root.bus)?,
        sysfs_relpath(root),
    );
    for ancestor in chain.iter().rev().skip(1) {
        canon.push('/');
        canon.push_str(sysfs_relpath(ancestor));
    }
    Some(canon)
}

fn registered_device_canon(dev: &Device) -> Option<String> {
    if !dev.lifecycle.is_visible() {
        return None;
    }
    let relpath = sysfs_relpath(dev);
    match dev.parent() {
        Some(_) => Some(alloc::format!("{}/{}", parent_chain_canon(dev)?, relpath)),
        None => Some(alloc::format!("{}/{}", device_root_canon(dev.bus)?, relpath)),
    }
}

/// Canonical path for the current live object at this model identity. Missing
/// devices or incomplete ancestry return `None`; no alternate root is invented.
/// # C: O(N_devices + parent depth)
pub fn device_canon(bus: &str, addr: &str) -> Option<String> {
    let snapshot = devices();
    registered_device_canon(find(&snapshot, bus, addr)?)
}

/// Canonical path for this exact object. A removed object does not alias a
/// same-name replacement, and incomplete ancestry fails closed.
/// # C: O(N_devices + parent depth)
pub fn device_canon_exact(dev: &Device) -> Option<String> {
    let snapshot = devices();
    let current = find(&snapshot, dev.bus, &dev.addr)?;
    if !core::ptr::eq(current.as_ref(), dev) {
        return None;
    }
    registered_device_canon(dev)
}

/// Canonical direct-parent path captured when this exact child was added.
/// # C: O(N_devices + parent depth)
pub fn device_parent_canon_exact(dev: &Device) -> Option<String> {
    device_canon_exact(dev)?;
    dev.parent()?;
    parent_chain_canon(dev)
}

#[cfg(test)]
mod tests {
    use alloc::string::String;
    use alloc::sync::Arc;

    use super::*;

    const TEST_EVENT_RELPATH: &str = "input/input17/event4";

    fn device(bus: &'static str, addr: &str) -> Arc<Device> {
        Arc::new(Device::new(bus, String::from(addr), 0, 0, 0))
    }

    #[test]
    fn unknown_bus_has_no_invented_root() {
        let _model = crate::model::test_claim::claim_model();
        assert_eq!(device_root_canon("unknown"), None);
    }

    #[test]
    fn canonical_relative_path_does_not_replace_bus_identity() {
        let _model = crate::model::test_claim::claim_model();
        let dev = crate::try_device_add(Arc::new(
            Device::new("input", String::from("event4"), 0, 0, 0)
                .with_sysfs_relpath(String::from("input17/event4")),
        )).expect("relative-path device");

        assert_eq!(dev.addr, "event4");
        assert_eq!(
            device_canon_exact(&dev),
            Some(String::from("devices/virtual/input/input17/event4")),
        );
        crate::device_del(&dev);
    }

    #[test]
    fn malformed_canonical_relative_path_is_rejected_before_publication() {
        let _model = crate::model::test_claim::claim_model();
        for path in ["", "/event4", "input17/", "input17//event4", "../event4"] {
            let dev = Arc::new(
                Device::new("input", String::from("event4"), 0, 0, 0)
                    .with_sysfs_relpath(String::from(path)),
            );
            assert!(matches!(
                crate::try_device_add(Arc::clone(&dev)),
                Err(crate::Error::Invalid),
            ));
            assert!(devices().iter().all(|present| !Arc::ptr_eq(present, &dev)));
        }
    }

    #[test]
    fn input_path_uses_exact_live_transitive_ancestry_and_fails_closed() {
        let _model = crate::model::test_claim::claim_model();
        let pci_addr = "0000:00:2e.0";
        let virtio_addr = "virtio-path-test";
        let pci = crate::try_device_add(device("pci", pci_addr)).expect("pci path parent");
        let virtio = crate::try_device_add(Arc::new(
            Device::new("virtio", String::from(virtio_addr), 0, 0, 0)
                .with_parent("pci", String::from(pci_addr)),
        )).expect("virtio path parent");
        let event = crate::try_device_add_with_parent(Arc::new(
            Device::new("input", String::from("event-node"), 0, 0, 0)
                .with_parent("virtio", String::from(virtio_addr))
                .with_sysfs_relpath(String::from(TEST_EVENT_RELPATH)),
        ), &virtio).expect("input child");

        assert_eq!(
            device_canon_exact(&event),
            Some(alloc::format!(
                "devices/pci0000:00/{pci_addr}/{virtio_addr}/{TEST_EVENT_RELPATH}",
            )),
        );
        assert_eq!(
            device_canon("virtio", virtio_addr),
            Some(String::from(
                "devices/pci0000:00/0000:00:2e.0/virtio-path-test",
            )),
        );
        crate::device_del(&pci);
        assert_eq!(device_canon_exact(&event), None);
        assert_eq!(device_canon("virtio", virtio_addr), None);
        assert_eq!(device_canon_exact(&virtio), None);
        let replacement = crate::try_device_add(device("pci", pci_addr))
            .expect("replacement pci identity");
        assert_eq!(
            device_canon_exact(&event),
            None,
            "must not reattach by name",
        );
        assert_eq!(device_canon("virtio", virtio_addr), None);

        crate::device_del(&event);
        crate::device_del(&virtio);
        crate::device_del(&replacement);
    }

    #[test]
    fn strict_child_add_revalidates_exact_parent_at_publication() {
        let _model = crate::model::test_claim::claim_model();
        let parent_addr = "virtio-path-race";
        let old_parent = crate::try_device_add(device("virtio", parent_addr))
            .expect("old parent");
        crate::device_del(&old_parent);
        let replacement = crate::try_device_add(device("virtio", parent_addr))
            .expect("replacement parent");
        let stale_child = Arc::new(
            Device::new("input", String::from("event5"), 0, 0, 0)
                .with_parent("virtio", String::from(parent_addr))
                .with_sysfs_relpath(String::from(TEST_EVENT_RELPATH)),
        );

        assert!(matches!(
            crate::try_device_add_with_parent(Arc::clone(&stale_child), &old_parent),
            Err(crate::Error::NotFound),
        ));
        assert!(devices().iter().all(|dev| !Arc::ptr_eq(dev, &stale_child)));
        let child = crate::try_device_add_with_parent(stale_child, &replacement)
            .expect("live replacement parent");
        assert!(device_canon_exact(&child).is_some());

        crate::device_del(&child);
        crate::device_del(&replacement);
    }

    #[test]
    fn exact_canonical_path_does_not_alias_same_name_replacement() {
        let _model = crate::model::test_claim::claim_model();
        let old = crate::try_device_add(device("platform", "canon-reuse"))
            .expect("old object");
        assert!(device_canon_exact(&old).is_some());
        crate::device_del(&old);
        let replacement = crate::try_device_add(device("platform", "canon-reuse"))
            .expect("replacement object");

        assert_eq!(device_canon_exact(&old), None);
        assert_eq!(
            device_canon("platform", "canon-reuse"),
            Some(String::from("devices/platform/canon-reuse")),
        );

        crate::device_del(&replacement);
    }

    #[test]
    fn removed_device_object_cannot_be_registered_again() {
        let _model = crate::model::test_claim::claim_model();
        let dev = crate::try_device_add(device("platform", "canon-dead-object"))
            .expect("first lifecycle");
        crate::device_del(&dev);

        assert!(matches!(
            crate::try_device_add(Arc::clone(&dev)),
            Err(crate::Error::Removed),
        ));
        assert_eq!(device_canon_exact(&dev), None);
        assert_eq!(device_canon("platform", "canon-dead-object"), None);
    }

    #[test]
    fn ordinary_parented_add_rejects_missing_ancestor() {
        let _model = crate::model::test_claim::claim_model();
        let direct_orphan = Arc::new(
            Device::new("virtio", String::from("virtio-broken-chain"), 0, 0, 0)
                .with_parent("pci", String::from("0000:00:2f.0")),
        );

        assert!(matches!(
            crate::try_device_add(Arc::clone(&direct_orphan)),
            Err(crate::Error::NotFound),
        ));
        assert!(devices().iter().all(|dev| !Arc::ptr_eq(dev, &direct_orphan)));

        let pci = crate::try_device_add(device("pci", "0000:00:2f.1"))
            .expect("temporary root ancestor");
        let parent = crate::try_device_add(Arc::new(
            Device::new("virtio", String::from("virtio-transitive-orphan"), 0, 0, 0)
                .with_parent("pci", String::from("0000:00:2f.1")),
        )).expect("parent with initially live chain");
        crate::device_del(&pci);
        let child = Arc::new(
            Device::new("input", String::from("event6"), 0, 0, 0)
                .with_parent("virtio", String::from("virtio-transitive-orphan")),
        );

        assert!(matches!(
            crate::try_device_add(Arc::clone(&child)),
            Err(crate::Error::NotFound),
        ));
        assert!(devices().iter().all(|dev| !Arc::ptr_eq(dev, &child)));
        crate::device_del(&parent);
    }
}
