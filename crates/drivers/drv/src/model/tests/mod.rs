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

static ADD_ORDER: TestLock<Vec<&'static str>, DriverListClass> = TestLock::new(Vec::new());
static ADD_PROBES: AtomicU32 = AtomicU32::new(0);
static ADD_SYSFS_SAW_BOUND: AtomicU32 = AtomicU32::new(0);
static ADD_BIND_EVENTS: AtomicU32 = AtomicU32::new(0);
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

fn device_add(d: Arc<Device>) -> Arc<Device> {
    try_device_add(d).expect("test device registration")
}
