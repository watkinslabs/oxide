// Module manifest:
// - `binding`: driver matching, override, bus scoping, and parent identity tests.
// - `hooks`: devtmpfs, sysfs, and bind-event ordering tests.
// - `lifecycle`: registration, probe failure, unbind, remove, and shutdown tests.

mod binding;
mod hooks;
mod lifecycle;

use super::*;
use alloc::vec::Vec;
use core::sync::atomic::AtomicU32;
use sync::Spinlock as TestLock;

struct FakeDrv;
impl Driver for FakeDrv {
    fn name(&self) -> &'static str { "fake-virtio-blk" }
    fn matches(&self, dev: &Device) -> bool { dev.device_id == 0x1042 }
}
static FAKE: FakeDrv = FakeDrv;

struct OverrideDrv;
impl Driver for OverrideDrv {
    fn name(&self) -> &'static str { "override-only" }
    fn matches(&self, _dev: &Device) -> bool { false }
}
static OVERRIDE: OverrideDrv = OverrideDrv;

struct PlatformDrv;
impl Driver for PlatformDrv {
    fn bus(&self) -> &'static str { "platform" }
    fn name(&self) -> &'static str { "platform-test" }
    fn matches(&self, dev: &Device) -> bool { dev.bus == "platform" && dev.addr == "test0" }
}
static PLATFORM: PlatformDrv = PlatformDrv;

static REMOVE_HITS: AtomicU32 = AtomicU32::new(0);
struct RemoveDrv;
impl Driver for RemoveDrv {
    fn name(&self) -> &'static str { "remove-test" }
    fn matches(&self, dev: &Device) -> bool { dev.device_id == 0x7777 }
    fn remove(&self, _dev: &Device) {
        REMOVE_HITS.fetch_add(1, Ordering::Release);
    }
}
static REMOVE_DRV: RemoveDrv = RemoveDrv;

static FAIL_PROBES: AtomicU32 = AtomicU32::new(0);
struct FailingProbeDrv;
impl Driver for FailingProbeDrv {
    fn name(&self) -> &'static str { "failing-probe" }
    fn matches(&self, dev: &Device) -> bool { dev.device_id == 0xf00d }
    fn probe(&self, _dev: &Arc<Device>) -> KResult<()> {
        FAIL_PROBES.fetch_add(1, Ordering::Release);
        Err(crate::Error::ProbeFailed)
    }
}
static FAILING_PROBE_DRV: FailingProbeDrv = FailingProbeDrv;

static PCI_IDENTITY_PROBES: AtomicU32 = AtomicU32::new(0);
struct PciIdentityDrv;
impl Driver for PciIdentityDrv {
    fn name(&self) -> &'static str { "pci-identity-test" }
    fn matches(&self, dev: &Device) -> bool {
        dev.bus == "pci" && dev.vendor_id == 0x1af4 && dev.device_id == 0x1041 && dev.class == 0x010000
    }
    fn probe(&self, _dev: &Arc<Device>) -> KResult<()> {
        PCI_IDENTITY_PROBES.fetch_add(1, Ordering::Release);
        Ok(())
    }
}
static PCI_IDENTITY_DRV: PciIdentityDrv = PciIdentityDrv;

static PCI_MISMATCH_PROBES: AtomicU32 = AtomicU32::new(0);
struct PciMismatchDrv;
impl Driver for PciMismatchDrv {
    fn name(&self) -> &'static str { "pci-mismatch-test" }
    fn matches(&self, dev: &Device) -> bool {
        dev.bus == "pci" && dev.vendor_id == 0x1af4 && dev.device_id == 0x1042 && dev.class == 0x020000
    }
    fn probe(&self, _dev: &Arc<Device>) -> KResult<()> {
        PCI_MISMATCH_PROBES.fetch_add(1, Ordering::Release);
        Ok(())
    }
}
static PCI_MISMATCH_DRV: PciMismatchDrv = PciMismatchDrv;

static LOOP_PROBES: AtomicU32 = AtomicU32::new(0);
static LOOP_REMOVES: AtomicU32 = AtomicU32::new(0);
struct LoopLifecycleDrv;
impl Driver for LoopLifecycleDrv {
    fn bus(&self) -> &'static str { "platform" }
    fn name(&self) -> &'static str { "loop-lifecycle-test" }
    fn matches(&self, dev: &Device) -> bool {
        dev.bus == "platform" && dev.device_id == 0x51fe
    }
    fn probe(&self, _dev: &Arc<Device>) -> KResult<()> {
        LOOP_PROBES.fetch_add(1, Ordering::Release);
        Ok(())
    }
    fn remove(&self, _dev: &Device) {
        LOOP_REMOVES.fetch_add(1, Ordering::Release);
    }
}
static LOOP_LIFECYCLE_DRV: LoopLifecycleDrv = LoopLifecycleDrv;

static READD_PROBES: AtomicU32 = AtomicU32::new(0);
static READD_REMOVES: AtomicU32 = AtomicU32::new(0);
struct ReaddLifecycleDrv;
impl Driver for ReaddLifecycleDrv {
    fn bus(&self) -> &'static str { "platform" }
    fn name(&self) -> &'static str { "readd-lifecycle-test" }
    fn matches(&self, dev: &Device) -> bool {
        dev.bus == "platform" && dev.device_id == 0x51ff
    }
    fn probe(&self, _dev: &Arc<Device>) -> KResult<()> {
        READD_PROBES.fetch_add(1, Ordering::Release);
        Ok(())
    }
    fn remove(&self, _dev: &Device) {
        READD_REMOVES.fetch_add(1, Ordering::Release);
    }
}
static READD_LIFECYCLE_DRV: ReaddLifecycleDrv = ReaddLifecycleDrv;

static LATE_PROBES: AtomicU32 = AtomicU32::new(0);
static LATE_REMOVES: AtomicU32 = AtomicU32::new(0);
struct LateRegisterDrv;
impl Driver for LateRegisterDrv {
    fn bus(&self) -> &'static str { "platform" }
    fn name(&self) -> &'static str { "late-register-test" }
    fn matches(&self, dev: &Device) -> bool {
        dev.bus == "platform" && dev.device_id == 0x6200
    }
    fn probe(&self, _dev: &Arc<Device>) -> KResult<()> {
        LATE_PROBES.fetch_add(1, Ordering::Release);
        Ok(())
    }
    fn remove(&self, _dev: &Device) {
        LATE_REMOVES.fetch_add(1, Ordering::Release);
    }
}
static LATE_REGISTER_DRV: LateRegisterDrv = LateRegisterDrv;

static DUP_REGISTER_PROBES: AtomicU32 = AtomicU32::new(0);
static DUP_REGISTER_REMOVES: AtomicU32 = AtomicU32::new(0);
struct DuplicateRegisterDrv;
impl Driver for DuplicateRegisterDrv {
    fn bus(&self) -> &'static str { "platform" }
    fn name(&self) -> &'static str { "duplicate-register-test" }
    fn matches(&self, dev: &Device) -> bool {
        dev.bus == "platform" && dev.device_id == 0x6201
    }
    fn probe(&self, _dev: &Arc<Device>) -> KResult<()> {
        DUP_REGISTER_PROBES.fetch_add(1, Ordering::Release);
        Ok(())
    }
    fn remove(&self, _dev: &Device) {
        DUP_REGISTER_REMOVES.fetch_add(1, Ordering::Release);
    }
}
static DUPLICATE_REGISTER_DRV: DuplicateRegisterDrv = DuplicateRegisterDrv;

static UNREGISTER_PROBES: AtomicU32 = AtomicU32::new(0);
static UNREGISTER_REMOVES: AtomicU32 = AtomicU32::new(0);
struct UnregisterDrv;
impl Driver for UnregisterDrv {
    fn bus(&self) -> &'static str { "platform" }
    fn name(&self) -> &'static str { "unregister-test" }
    fn matches(&self, dev: &Device) -> bool { dev.device_id == 0x6202 }
    fn probe(&self, _dev: &Arc<Device>) -> KResult<()> {
        UNREGISTER_PROBES.fetch_add(1, Ordering::Release);
        Ok(())
    }
    fn remove(&self, _dev: &Device) {
        UNREGISTER_REMOVES.fetch_add(1, Ordering::Release);
    }
}
static UNREGISTER_DRV: UnregisterDrv = UnregisterDrv;

static UNBIND_ORDER_REMOVE_SAW_BOUND: AtomicU32 = AtomicU32::new(0);
struct UnbindOrderDrv;
impl Driver for UnbindOrderDrv {
    fn bus(&self) -> &'static str { "platform" }
    fn name(&self) -> &'static str { "unbind-order-test" }
    fn matches(&self, dev: &Device) -> bool { dev.device_id == 0x6204 }
    fn remove(&self, dev: &Device) {
        if dev.bound() == Some("unbind-order-test") {
            UNBIND_ORDER_REMOVE_SAW_BOUND.store(1, Ordering::Release);
        }
    }
}
static UNBIND_ORDER_DRV: UnbindOrderDrv = UnbindOrderDrv;

static ADD_ORDER: TestLock<Vec<&'static str>, DriverListClass> = TestLock::new(Vec::new());
static ADD_PROBES: AtomicU32 = AtomicU32::new(0);
static ADD_SYSFS_SAW_BOUND: AtomicU32 = AtomicU32::new(0);
static ADD_BIND_EVENTS: AtomicU32 = AtomicU32::new(0);
const ROLLBACK_KEEP_ADDR: &str = "rollback-existing-tty0";
const ROLLBACK_DROP_ADDR: &str = "rollback-new-tty0";
const ROLLBACK_KEEP_ID: u16 = 0x6600;
const ROLLBACK_DROP_ID: u16 = 0x6601;
const ROLLBACK_CONFLICT_ID: u16 = 0x6602;
const PLATFORM_REUSE_ADDR: &str = "platform-reuse0";
const PLATFORM_REUSE_PARENT_ADDR: &str = "platform-reuse-parent0";
const PLATFORM_REUSE_DEVNODE_CLASS: &str = "misc";
const PLATFORM_REUSE_DEVNODE_NAME: &str = "platform-reuse-node";
const PLATFORM_REUSE_VENDOR_ID: u16 = 0;
const PLATFORM_REUSE_DEVICE_ID: u16 = 0;
const PLATFORM_REUSE_CLASS: u32 = 0;
const PLATFORM_REUSE_DEV_MAJOR: u32 = 10;
const PLATFORM_REUSE_DEV_MINOR: u32 = 250;
const PLATFORM_REUSE_RESOURCE_BAR: u8 = 0;
const PLATFORM_REUSE_RESOURCE_START: u64 = 0x6800_0000;
const PLATFORM_REUSE_RESOURCE_END: u64 = 0x6800_0fff;
const PLATFORM_CONFLICT_ADDR: &str = "platform-conflict0";
const PLATFORM_CONFLICT_DEVNODE_CLASS: &str = "misc";
const PLATFORM_CONFLICT_DEVNODE_NAME: &str = "platform-conflict-node";
const PLATFORM_CONFLICT_DEV_MAJOR: u32 = 10;
const PLATFORM_CONFLICT_DEV_MINOR: u32 = 249;
struct AddOrderDrv;
impl Driver for AddOrderDrv {
    fn bus(&self) -> &'static str { "platform" }
    fn name(&self) -> &'static str { "device-add-order-test" }
    fn matches(&self, dev: &Device) -> bool {
        dev.bus == "platform" && dev.device_id == 0x6300
    }
    fn probe(&self, _dev: &Arc<Device>) -> KResult<()> {
        ADD_PROBES.fetch_add(1, Ordering::Release);
        ADD_ORDER.lock().push("probe");
        Ok(())
    }
}
static ADD_ORDER_DRV: AddOrderDrv = AddOrderDrv;

static DEVICE_DEL_ORDER: TestLock<Vec<&'static str>, DriverListClass> = TestLock::new(Vec::new());
static DEVICE_DEL_ORDER_ACTIVE: AtomicU32 = AtomicU32::new(0);
struct DeviceDelOrderDrv;
impl Driver for DeviceDelOrderDrv {
    fn bus(&self) -> &'static str { "platform" }
    fn name(&self) -> &'static str { "device-del-order-test" }
    fn matches(&self, dev: &Device) -> bool { dev.device_id == 0x6203 }
    fn remove(&self, _dev: &Device) {
        DEVICE_DEL_ORDER.lock().push("driver-remove");
    }
}
static DEVICE_DEL_ORDER_DRV: DeviceDelOrderDrv = DeviceDelOrderDrv;

static SHUTDOWN_REMOVES: AtomicU32 = AtomicU32::new(0);
static SHUTDOWN_UNBOUND_EVENTS: AtomicU32 = AtomicU32::new(0);
static SHUTDOWN_EVENT_ACTIVE: AtomicU32 = AtomicU32::new(0);
const HARDEN_LOOP_COUNT: u32 = 8;
const HARDEN_PLATFORM_ID: u16 = 0x6501;
const HARDEN_PCI_VENDOR: u16 = 0x1af4;
const HARDEN_PCI_ID: u16 = 0x6502;
const HARDEN_FAIL_ID: u16 = 0x6503;
const HARDEN_CLASS: u32 = 0x010000;
const HARDEN_PLATFORM_ADDRS: [&str; 2] = ["hardening-platform0", "hardening-platform1"];
const HARDEN_PCI_ADDR: &str = "0000:00:65.0";
const HARDEN_FAIL_ADDR: &str = "hardening-fail0";
static HARDEN_PLATFORM_PROBES: AtomicU32 = AtomicU32::new(0);
static HARDEN_PLATFORM_REMOVES: AtomicU32 = AtomicU32::new(0);
static HARDEN_PCI_PROBES: AtomicU32 = AtomicU32::new(0);
static HARDEN_PCI_REMOVES: AtomicU32 = AtomicU32::new(0);
static HARDEN_FAIL_PROBES: AtomicU32 = AtomicU32::new(0);

struct HardeningPlatformDrv;
impl Driver for HardeningPlatformDrv {
    fn bus(&self) -> &'static str { "platform" }
    fn name(&self) -> &'static str { "hardening-platform-test" }
    fn matches(&self, dev: &Device) -> bool { dev.bus == "platform" && dev.device_id == HARDEN_PLATFORM_ID }
    fn probe(&self, _dev: &Arc<Device>) -> KResult<()> {
        HARDEN_PLATFORM_PROBES.fetch_add(1, Ordering::Release);
        Ok(())
    }
    fn remove(&self, _dev: &Device) {
        HARDEN_PLATFORM_REMOVES.fetch_add(1, Ordering::Release);
    }
}
static HARDENING_PLATFORM_DRV: HardeningPlatformDrv = HardeningPlatformDrv;

struct HardeningPciDrv;
impl Driver for HardeningPciDrv {
    fn name(&self) -> &'static str { "hardening-pci-test" }
    fn matches(&self, dev: &Device) -> bool { dev.bus == "pci" && dev.device_id == HARDEN_PCI_ID }
    fn probe(&self, _dev: &Arc<Device>) -> KResult<()> {
        HARDEN_PCI_PROBES.fetch_add(1, Ordering::Release);
        Ok(())
    }
    fn remove(&self, _dev: &Device) {
        HARDEN_PCI_REMOVES.fetch_add(1, Ordering::Release);
    }
}
static HARDENING_PCI_DRV: HardeningPciDrv = HardeningPciDrv;

struct HardeningFailDrv;
impl Driver for HardeningFailDrv {
    fn bus(&self) -> &'static str { "platform" }
    fn name(&self) -> &'static str { "hardening-fail-test" }
    fn matches(&self, dev: &Device) -> bool { dev.bus == "platform" && dev.device_id == HARDEN_FAIL_ID }
    fn probe(&self, _dev: &Arc<Device>) -> KResult<()> {
        HARDEN_FAIL_PROBES.fetch_add(1, Ordering::Release);
        Err(crate::Error::ProbeFailed)
    }
}
static HARDENING_FAIL_DRV: HardeningFailDrv = HardeningFailDrv;

fn device_del_order_sysfs_remove(dev: &Device) {
    if DEVICE_DEL_ORDER_ACTIVE.load(Ordering::Acquire) == 0 {
        return;
    }
    assert_eq!(dev.bound(), None);
    assert!(devices().iter().any(|d| d.bus == dev.bus && d.addr == dev.addr));
    assert_eq!(&*DEVICE_DEL_ORDER.lock(), &["driver-remove"]);
    DEVICE_DEL_ORDER.lock().push("sysfs-remove");
}

fn device_del_order_devtmpfs_del(name: &str) {
    if DEVICE_DEL_ORDER_ACTIVE.load(Ordering::Acquire) == 0 {
        return;
    }
    assert_eq!(name, "device-del-order-node");
    assert_eq!(&*DEVICE_DEL_ORDER.lock(), &["driver-remove", "sysfs-remove"]);
    DEVICE_DEL_ORDER.lock().push("devtmpfs-del");
    DEVICE_DEL_ORDER_ACTIVE.store(0, Ordering::Release);
}

fn shutdown_all_bind_event(_bus: &str, addr: &str, _driver: &'static str, event: BindEvent) {
    if SHUTDOWN_EVENT_ACTIVE.load(Ordering::Acquire) == 0 {
        return;
    }
    if event == BindEvent::Unbound && (addr == "0000:00:15.0" || addr == "0000:00:16.0") {
        SHUTDOWN_UNBOUND_EVENTS.fetch_add(1, Ordering::Release);
    }
}

fn device_add(d: Arc<Device>) -> Arc<Device> {
    try_device_add(d).expect("test device registration")
}
