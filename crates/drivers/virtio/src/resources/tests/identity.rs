use super::*;
use alloc::string::String;
use alloc::vec;
use std::sync::{Arc, Mutex, OnceLock};

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
fn child_model_identity_can_be_constructed_without_pci_identity() {
    let child = VirtioChildModelIdentity::modern(2, 5);

    assert_eq!(child.bus, VIRTIO_CHILD_BUS);
    assert_eq!(child.addr, "virtio5");
    assert_eq!(child.vendor_id, VIRTIO_VENDOR_ID);
    assert_eq!(child.device_id, 2);
    assert_eq!(child.class, VIRTIO_CHILD_CLASS);
}

#[test]
fn child_model_identity_rejects_non_modern_pci_device() {
    assert!(VirtioChildModelIdentity::modern_from_pci(0x1234, 0x1041, 0).is_none());
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
fn child_device_key_is_constructed_from_child_model_address() {
    let child = VirtioChildModelIdentity::modern_from_pci(0x1AF4, 0x1042, 7)
        .expect("modern virtio block id");
    let key = VirtioChildDeviceKey::from_child_addr(&child.addr).expect("virtio child key");

    assert_eq!(child.addr, "virtio7");
    assert_eq!(key.raw(), 8);
    assert_eq!(VirtioChildDeviceKey::from_child_addr("virtio0").unwrap().raw(), 1);
    assert!(VirtioChildDeviceKey::from_child_addr("pci0").is_none());
    assert!(VirtioChildDeviceKey::from_child_addr("virtio").is_none());
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
    release_count: usize,
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
        self.lifecycle.lock().unwrap().release_count += 1;
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
    assert_eq!(lifecycle.release_count, 0);
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
    assert_eq!(lifecycle.release_count, 1);
}

#[test]
fn child_probe_lifecycle_releases_once_at_each_fault_point() {
    for fail_step in 0..4 {
        let lifecycle = Arc::new(Mutex::new(ProbeLifecycle::default()));
        let result = run_child_probe(ProbeSession::new(lifecycle.clone()), |session| {
            if fail_step == 0 { return Err::<(), usize>(fail_step); }
            let _ = session.device_key();
            if fail_step == 1 { return Err::<(), usize>(fail_step); }
            let _ = session.device_addr();
            if fail_step == 2 { return Err::<(), usize>(fail_step); }
            let _ = session.child_resources();
            Err::<(), usize>(fail_step)
        });

        assert_eq!(result, Err(fail_step));
        let lifecycle = lifecycle.lock().unwrap();
        assert!(!lifecycle.published);
        assert_eq!(lifecycle.release_count, 1);
    }
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

const MODEL_FAULT_DRIVER: &str = "b593-virtio-fault";
const MODEL_FAULT_DEVICE_ID: u16 = 0x5d93;
const MODEL_FAULT_ADDR: &str = "virtio593";
const MODEL_FAULT_PARENT: &str = "0000:00:59.3";
const MODEL_FAULT_FEATURES: u64 = 0xb593;
const MODEL_FAULT_KEY_RAW: u64 = 594;
static MODEL_FAULT_DRV: VirtioChildDriver<ModelFaultBus, ModelFaultOps> = VirtioChildDriver::new();

#[derive(Copy, Clone, Eq, PartialEq)]
enum ModelFaultMode {
    BeginFail,
    ChildFail,
    Success,
}

impl Default for ModelFaultMode {
    fn default() -> Self { Self::Success }
}

#[derive(Default)]
struct ModelFaultState {
    mode: ModelFaultMode,
    events: Vec<(&'static str, u64)>,
}

struct ModelFaultBus;
struct ModelFaultOps;

struct ModelFaultSession {
    key: VirtioChildDeviceKey,
    addr: String,
}

fn model_fault_state() -> &'static Mutex<ModelFaultState> {
    static STATE: OnceLock<Mutex<ModelFaultState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(ModelFaultState::default()))
}

fn reset_model_fault_state(mode: ModelFaultMode) {
    let mut state = model_fault_state().lock().unwrap();
    state.mode = mode;
    state.events.clear();
}

fn model_fault_events() -> Vec<(&'static str, u64)> {
    model_fault_state().lock().unwrap().events.clone()
}

fn remove_model_fault_devices() {
    for dev in drv::devices() {
        if dev.bus == VIRTIO_CHILD_BUS && dev.addr == MODEL_FAULT_ADDR {
            drv::device_del(&dev);
        }
    }
}

fn model_fault_device() -> Arc<drv::Device> {
    Arc::new(
        drv::Device::new(
            VIRTIO_CHILD_BUS,
            String::from(MODEL_FAULT_ADDR),
            VIRTIO_VENDOR_ID,
            MODEL_FAULT_DEVICE_ID,
            VIRTIO_CHILD_CLASS,
        )
        .with_parent("pci", String::from(MODEL_FAULT_PARENT)))
}

impl VirtioChildTransportSession for ModelFaultSession {
    fn device_key(&self) -> VirtioChildDeviceKey {
        self.key
    }

    fn device_addr(&self) -> &str {
        &self.addr
    }

    fn drv_features(&self) -> u64 {
        MODEL_FAULT_FEATURES
    }

    fn net_boot_payloads(&self) -> VirtioNetBootPayloads {
        VirtioNetBootPayloads::default()
    }

    fn child_resources(&self) -> Option<VirtioResources> {
        None
    }

    fn release_failed_child(&mut self) {
        model_fault_state()
            .lock()
            .unwrap()
            .events
            .push(("release", self.key.raw() as u64));
    }

    fn publish(self) {
        model_fault_state()
            .lock()
            .unwrap()
            .events
            .push(("publish", self.key.raw() as u64));
    }
}

impl VirtioChildBus for ModelFaultBus {
    type Session = ModelFaultSession;

    fn begin_session(
        dev: &drv::Device,
        profile: VirtioTransportProfile,
    ) -> drv::KResult<Self::Session> {
        let mut state = model_fault_state().lock().unwrap();
        state.events.push(("begin", profile.drv_features));
        if state.mode == ModelFaultMode::BeginFail {
            return Err(drv::Error::ProbeFailed);
        }
        Ok(ModelFaultSession {
            key: VirtioChildDeviceKey::from_child_addr(&dev.addr).unwrap(),
            addr: dev.addr.clone(),
        })
    }

    fn parent_key(dev: &drv::Device) -> Option<VirtioChildDeviceKey> {
        VirtioChildDeviceKey::from_child_addr(&dev.addr)
    }

    fn unpublish_transport(device_key: VirtioChildDeviceKey) {
        model_fault_state()
            .lock()
            .unwrap()
            .events
            .push(("unpublish", device_key.raw() as u64));
    }
}

impl VirtioChildDriverOps<ModelFaultSession> for ModelFaultOps {
    const DRIVER_ID: VirtioChildDriverId =
        VirtioChildDriverId::new(MODEL_FAULT_DRIVER, MODEL_FAULT_DEVICE_ID);

    fn profile() -> VirtioTransportProfile {
        VirtioTransportProfile::q0(MODEL_FAULT_FEATURES, None)
    }

    fn probe_child(
        _parent: &Arc<drv::Device>,
        session: &mut ModelFaultSession,
    ) -> drv::KResult<()> {
        let mut state = model_fault_state().lock().unwrap();
        state.events.push(("probe", session.device_key().raw() as u64));
        if state.mode == ModelFaultMode::ChildFail {
            return Err(drv::Error::ProbeFailed);
        }
        Ok(())
    }

    fn remove_child(device_key: VirtioChildDeviceKey) {
        model_fault_state()
            .lock()
            .unwrap()
            .events
            .push(("remove", device_key.raw() as u64));
    }

    fn shutdown_child(device_key: VirtioChildDeviceKey) {
        model_fault_state()
            .lock()
            .unwrap()
            .events
            .push(("shutdown", device_key.raw() as u64));
    }
}

#[test]
fn child_model_driver_faults_release_without_transport_publish() {
    drv::register_driver(&MODEL_FAULT_DRV);
    remove_model_fault_devices();
    let parent = drv::try_device_add(Arc::new(drv::Device::new(
        "pci",
        String::from(MODEL_FAULT_PARENT),
        VIRTIO_VENDOR_ID,
        0,
        0,
    ))).expect("fault-test PCI parent");

    reset_model_fault_state(ModelFaultMode::BeginFail);
    let begin_fail = drv::try_device_add(model_fault_device()).unwrap();
    assert!(begin_fail.bound().is_none());
    assert_eq!(model_fault_events(), vec![("begin", MODEL_FAULT_FEATURES)]);
    drv::device_del(&begin_fail);

    reset_model_fault_state(ModelFaultMode::ChildFail);
    let child_fail = drv::try_device_add(model_fault_device()).unwrap();
    assert!(child_fail.bound().is_none());
    assert_eq!(
        model_fault_events(),
        vec![
            ("begin", MODEL_FAULT_FEATURES),
            ("probe", MODEL_FAULT_KEY_RAW),
            ("release", MODEL_FAULT_KEY_RAW),
        ]);

    reset_model_fault_state(ModelFaultMode::Success);
    assert_eq!(drv::bind(&child_fail, MODEL_FAULT_DRIVER), Ok(()));
    assert_eq!(child_fail.bound(), Some(MODEL_FAULT_DRIVER));
    assert_eq!(
        model_fault_events(),
        vec![
            ("begin", MODEL_FAULT_FEATURES),
            ("probe", MODEL_FAULT_KEY_RAW),
            ("publish", MODEL_FAULT_KEY_RAW),
        ]);

    reset_model_fault_state(ModelFaultMode::Success);
    assert_eq!(drv::unbind(&child_fail), Ok(()));
    assert!(child_fail.bound().is_none());
    assert_eq!(
        model_fault_events(),
        vec![("remove", MODEL_FAULT_KEY_RAW), ("unpublish", MODEL_FAULT_KEY_RAW)]);

    drv::device_del(&child_fail);
    drv::device_del(&parent);
}
