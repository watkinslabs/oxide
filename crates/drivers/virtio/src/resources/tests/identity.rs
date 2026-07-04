use super::*;
use alloc::vec;
use std::sync::{Arc, Mutex};

#[test]
fn child_driver_id_matches_virtio_child_devices() {
    let id = VirtioChildDriverId::new("virtio-test", 42);

    assert_eq!(id.name, "virtio-test");
    assert!(id.matches_device(VIRTIO_CHILD_BUS, VIRTIO_VENDOR_ID, 42));
    assert!(!id.matches_device("pci", VIRTIO_VENDOR_ID, 42));
    assert!(!id.matches_device(VIRTIO_CHILD_BUS, 0x1234, 42));
    assert!(!id.matches_device(VIRTIO_CHILD_BUS, VIRTIO_VENDOR_ID, 43));
}

#[test]
fn child_model_identity_maps_modern_pci_device() {
    let child = VirtioChildModelIdentity::modern_from_pci(0x1AF4, 0x1041, 2)
        .expect("modern virtio block id");

    assert_eq!(child.bus, VIRTIO_CHILD_BUS);
    assert_eq!(child.addr, "virtio2");
    assert_eq!(child.vendor_id, 0x1AF4);
    assert_eq!(child.device_id, 1);
    assert_eq!(child.class, VIRTIO_CHILD_CLASS);
}

#[test]
fn child_model_identity_rejects_non_modern_pci_device() {
    assert!(VirtioChildModelIdentity::modern_from_pci(0x1AF4, 0x1000, 0).is_none());
    assert!(VirtioChildModelIdentity::modern_from_pci(0x1AF4, 0x9999, 0).is_none());
}

#[test]
fn child_parent_match_requires_virtio_bus_and_matching_parent() {
    assert!(virtio_child_has_parent(
        VIRTIO_CHILD_BUS,
        Some(("pci", "0000:00:01.0")),
        "pci",
        "0000:00:01.0",
    ));
    assert!(!virtio_child_has_parent(
        "pci",
        Some(("pci", "0000:00:01.0")),
        "pci",
        "0000:00:01.0",
    ));
    assert!(!virtio_child_has_parent(
        VIRTIO_CHILD_BUS,
        Some(("pci", "0000:00:02.0")),
        "pci",
        "0000:00:01.0",
    ));
    assert!(!virtio_child_has_parent(
        VIRTIO_CHILD_BUS,
        None,
        "pci",
        "0000:00:01.0",
    ));
}

#[test]
fn child_device_key_is_constructed_from_transport_location() {
    let location = VirtioTransportLocation::new(0x12, 0x03, 0x04);
    let key = VirtioChildDeviceKey::from_location(location);

    assert_eq!(key.raw(), 0x0012_0304);
    assert_eq!(VirtioChildDeviceKey::from_raw(0x0012_0304), key);
}

#[test]
fn probe_lease_take_is_idempotent() {
    let mut lease = VirtioProbeLease::live();

    assert!(lease.is_live());
    assert!(lease.take());
    assert!(!lease.is_live());
    assert!(!lease.take());
}

#[test]
fn default_probe_lease_is_empty() {
    let mut lease = VirtioProbeLease::default();

    assert!(!lease.is_live());
    assert!(!lease.take());
}

#[derive(Default)]
struct ProbeLifecycle {
    published: bool,
    released: bool,
}

struct ProbeSession {
    lifecycle: Arc<Mutex<ProbeLifecycle>>,
}

impl ProbeSession {
    fn new(lifecycle: Arc<Mutex<ProbeLifecycle>>) -> Self {
        Self { lifecycle }
    }
}

impl VirtioChildTransportSession for ProbeSession {
    fn device_key(&self) -> VirtioChildDeviceKey {
        VirtioChildDeviceKey::from_raw(1)
    }

    fn location(&self) -> VirtioTransportLocation {
        VirtioTransportLocation::new(0, 1, 0)
    }

    fn device_addr(&self) -> &str {
        "virtio-test0"
    }

    fn drv_features(&self) -> u64 {
        0
    }

    fn net_boot_payloads(&self) -> VirtioNetBootPayloads {
        VirtioNetBootPayloads::default()
    }

    fn child_resources(&self) -> Option<VirtioResources> {
        None
    }

    fn release_failed_child(&mut self) {
        self.lifecycle.lock().unwrap().released = true;
    }

    fn publish(self) {
        self.lifecycle.lock().unwrap().published = true;
    }
}

#[test]
fn child_probe_lifecycle_publishes_only_after_success() {
    let lifecycle = Arc::new(Mutex::new(ProbeLifecycle::default()));
    let result = run_child_probe(ProbeSession::new(lifecycle.clone()), |session| {
        assert_eq!(session.device_key().raw(), 1);
        Ok::<(), ()>(())
    });

    assert_eq!(result, Ok(()));
    let lifecycle = lifecycle.lock().unwrap();
    assert!(lifecycle.published);
    assert!(!lifecycle.released);
}

#[test]
fn child_probe_lifecycle_releases_on_child_error() {
    let lifecycle = Arc::new(Mutex::new(ProbeLifecycle::default()));
    let result = run_child_probe(ProbeSession::new(lifecycle.clone()), |_session| {
        Err::<(), u8>(7)
    });

    assert_eq!(result, Err(7));
    let lifecycle = lifecycle.lock().unwrap();
    assert!(!lifecycle.published);
    assert!(lifecycle.released);
}

#[test]
fn child_remove_lifecycle_removes_before_unpublish() {
    let key = VirtioChildDeviceKey::from_raw(0x12);
    let calls = Arc::new(Mutex::new(Vec::new()));
    let remove_calls = calls.clone();
    let unpublish_calls = calls.clone();

    run_child_remove(
        key,
        |device_key| remove_calls.lock().unwrap().push(("remove", device_key.raw())),
        |device_key| {
            unpublish_calls
                .lock()
                .unwrap()
                .push(("unpublish", device_key.raw()))
        },
    );

    assert_eq!(*calls.lock().unwrap(), vec![("remove", 0x12), ("unpublish", 0x12)]);
}

#[test]
fn child_shutdown_lifecycle_passes_stable_key() {
    let key = VirtioChildDeviceKey::from_raw(0x34);
    let calls = Arc::new(Mutex::new(Vec::new()));
    let shutdown_calls = calls.clone();

    run_child_shutdown(key, |device_key| shutdown_calls.lock().unwrap().push(device_key.raw()));

    assert_eq!(*calls.lock().unwrap(), vec![0x34]);
}
