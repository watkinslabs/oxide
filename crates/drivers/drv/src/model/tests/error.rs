use super::*;

const ERROR_DEVICE_ID: u16 = 0xea11;
static ERROR_DETECTED: AtomicU32 = AtomicU32::new(0);
static MMIO_ENABLED: AtomicU32 = AtomicU32::new(0);
static SLOT_RESET: AtomicU32 = AtomicU32::new(0);
static RESUMED: AtomicU32 = AtomicU32::new(0);

fn error_detected(_dev: &Device, state: PciChannelState) -> PciErsResult {
    ERROR_DETECTED.store(state as u32, Ordering::Release);
    PciErsResult::NeedReset
}
fn mmio_enabled(_dev: &Device) -> PciErsResult {
    MMIO_ENABLED.fetch_add(1, Ordering::Release);
    PciErsResult::Recovered
}
fn slot_reset(_dev: &Device) -> PciErsResult {
    SLOT_RESET.fetch_add(1, Ordering::Release);
    PciErsResult::Recovered
}
fn resume(_dev: &Device) { RESUMED.fetch_add(1, Ordering::Release); }

static ERROR_HANDLERS: PciErrorHandlers = PciErrorHandlers {
    error_detected: Some(error_detected), mmio_enabled: Some(mmio_enabled),
    slot_reset: Some(slot_reset), resume: Some(resume),
};

struct ErrorDriver;
impl Driver for ErrorDriver {
    fn name(&self) -> &'static str { "pci-error-test" }
    fn matches(&self, dev: &Device) -> bool { dev.device_id == ERROR_DEVICE_ID }
    fn pci_error_handlers(&self) -> Option<&'static PciErrorHandlers> { Some(&ERROR_HANDLERS) }
}
static ERROR_DRIVER: ErrorDriver = ErrorDriver;

#[test]
fn pci_error_handlers_follow_the_live_bound_driver() {
    let _model = crate::model::test_claim::claim_model();
    ERROR_DETECTED.store(0, Ordering::Release);
    MMIO_ENABLED.store(0, Ordering::Release);
    SLOT_RESET.store(0, Ordering::Release);
    RESUMED.store(0, Ordering::Release);
    register_driver(&ERROR_DRIVER);
    let dev = try_device_add(Arc::new(Device::new(
        "pci", String::from("0000:00:ea.0"), 0, ERROR_DEVICE_ID, 0))).unwrap();

    let handlers = bound_pci_error_handlers(&dev).expect("bound PCI handlers");
    assert_eq!(handlers.error_detected.unwrap()(&dev, PciChannelState::Frozen), PciErsResult::NeedReset);
    assert_eq!(handlers.mmio_enabled.unwrap()(&dev), PciErsResult::Recovered);
    assert_eq!(handlers.slot_reset.unwrap()(&dev), PciErsResult::Recovered);
    handlers.resume.unwrap()(&dev);
    assert_eq!(ERROR_DETECTED.load(Ordering::Acquire), PciChannelState::Frozen as u32);
    assert_eq!(MMIO_ENABLED.load(Ordering::Acquire), 1);
    assert_eq!(SLOT_RESET.load(Ordering::Acquire), 1);
    assert_eq!(RESUMED.load(Ordering::Acquire), 1);

    assert_eq!(unbind(&dev), Ok(()));
    assert!(bound_pci_error_handlers(&dev).is_none());
    device_del(&dev);
}

#[test]
fn pci_error_handlers_do_not_escape_the_pci_bound_driver() {
    let _model = crate::model::test_claim::claim_model();
    register_driver(&ERROR_DRIVER);
    let platform = try_device_add(Arc::new(Device::new(
        "platform", String::from("error-platform"), 0, ERROR_DEVICE_ID, 0))).unwrap();
    assert!(platform.bound().is_none());
    assert!(bound_pci_error_handlers(&platform).is_none());
    device_del(&platform);
}
