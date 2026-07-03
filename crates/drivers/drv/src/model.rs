// Real driver model (drivers-plan D1a): Device / Driver registries +
// bus/driver binding, plus the sysfs-publish + bind hooks the kernel
// wires to the sysfs crate (this crate is no_std with no devfs dep,
// so it reaches sysfs through indirect `fn` hooks, not a direct dep).
//
// This is ADDITIVE alongside the legacy `DriverEntry`/`probe_all`
// path in `lib.rs`: the live virtio/serial drivers still bring up via
// inline code in `crates/kernel/pci-boot`; D1a only builds the model
// and publishes the device tree. Probe-driven bring-up (D1b) + a
// `linkme` distributed driver slice are deferred — they are a
// boot-risky rework with no current consumer (the device set is
// static at boot), so the explicit `register_driver` call from each
// driver's bring-up site stands in for the linkme slice for now.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use sync::{Spinlock, TaskList as DriverListClass};

use crate::KResult;

/// Factory that mints the `/dev` node inode for a device (devtmpfs path).
/// Boxed + `Arc` so the registry, the `Device`, and the `DEVTMPFS_HOOK`
/// callback share one closure. `InodeRef` is the only `vfs` type drv names
/// (see Cargo.toml note on the acyclic drv->vfs edge). A device that wants a
/// bespoke `/dev` node (e.g. the mem pseudo-devices' custom `FileOps`) supplies
/// one; a plain char/block node is built from `dev_t` by devtmpfs when absent.
pub type NodeFactory = Arc<dyn Fn() -> vfs::InodeRef + Send + Sync>;

/// One enumerated device on a bus. `driver` names the bound driver
/// (None = unbound). Held as `Arc<Device>` so the registry, the bound
/// driver, and the sysfs inode tree all share one instance.
pub struct Device {
    /// Bus kind: `"pci"` or `"virtio"`.
    pub bus:       &'static str,
    /// Bus address, e.g. `"0000:00:03.0"` (pci) or `"virtio2"`.
    pub addr:      String,
    /// PCI vendor id (0 for synthetic virtio bus devices).
    pub vendor_id: u16,
    /// PCI device id, or virtio device-id on the virtio bus.
    pub device_id: u16,
    /// 24-bit PCI class/subclass/prog-if (class<<16|sub<<8|progif).
    pub class:     u32,
    /// Bound driver name, None when unbound.
    pub driver:    Spinlock<Option<&'static str>, DriverListClass>,
    // --- /dev-node (devtmpfs) fields, Stage B -----------------------------
    // Populated only on devices brought up via `device_add`; the legacy
    // `register_device` path leaves them empty (additive — old `/dev`
    // registration still works). `class` (PCI class, above) is distinct from
    // `dev_class` (the devtmpfs class string), hence the different name.
    /// devtmpfs class: `"block"`/`"tty"`/`"mem"`/`"input"`/… (`""` = no node).
    pub dev_class: &'static str,
    /// `/dev` leaf or relative path (e.g. `"vda"`, `"input/event0"`); the
    /// node lands at `/dev/<devname>`. `None` = device has no `/dev` node.
    pub devname:   Option<String>,
    /// `(major, minor)` for a plain char/block node devtmpfs synthesises when
    /// no `node_factory` is given. `None` = bespoke node or non-device.
    pub dev_t:     Option<(u32, u32)>,
    /// Optional bespoke `/dev` node factory (overrides the `dev_t` node).
    pub node_factory: Option<NodeFactory>,
}

impl Device {
    /// Construct an unbound device with no `/dev` node. # C: O(1)
    pub fn new(bus: &'static str, addr: String, vendor_id: u16, device_id: u16, class: u32) -> Self {
        Self {
            bus, addr, vendor_id, device_id, class, driver: Spinlock::new(None),
            dev_class: "", devname: None, dev_t: None, node_factory: None,
        }
    }
    /// Currently-bound driver name, if any. # C: O(1)
    pub fn bound(&self) -> Option<&'static str> { *self.driver.lock() }
    /// Builder: declare a `/dev` node of `class` at `/dev/<name>` addressing
    /// `dev_t` (`None` ⇒ supply a [`Self::with_node_factory`] instead). # C: O(1)
    pub fn with_devnode(mut self, class: &'static str, name: String, dev_t: Option<(u32, u32)>) -> Self {
        self.dev_class = class; self.devname = Some(name); self.dev_t = dev_t; self
    }
    /// Builder: attach a bespoke `/dev` node factory (custom `FileOps`). # C: O(1)
    pub fn with_node_factory(mut self, f: NodeFactory) -> Self { self.node_factory = Some(f); self }
}

/// The driver contract (drivers-plan: Driver/DriverInstance/Device +
/// probe/remove/shutdown symmetry). Object-safe (`&'static dyn Driver`).
/// `matches` decides whether this driver claims `dev`; `probe` binds it
/// (default Ok — the live drivers already brought the device up, so the
/// registered model driver's probe is a no-op until D1b moves bring-up
/// here); `remove`/`shutdown` are the teardown symmetry.
pub trait Driver: Sync {
    /// Driver name (appears at `/sys/bus/<bus>/drivers/<name>`).
    fn name(&self) -> &'static str;
    /// True iff this driver claims `dev`.
    fn matches(&self, dev: &Device) -> bool;
    /// Bind `dev`. Default Ok — see trait note. # C: driver-defined
    fn probe(&self, _dev: &Arc<Device>) -> KResult<()> { Ok(()) }
    /// Release `dev` (hot-unplug). Default no-op. # C: driver-defined
    fn remove(&self, _dev: &Device) {}
    /// Quiesce `dev` for reboot/poweroff. Default no-op. # C: driver-defined
    fn shutdown(&self, _dev: &Device) {}
}

static DEVICES: Spinlock<Vec<Arc<Device>>, DriverListClass> = Spinlock::new(Vec::new());
static MODEL_DRIVERS: Spinlock<Vec<&'static dyn Driver>, DriverListClass> = Spinlock::new(Vec::new());
static DEV_COUNT: AtomicUsize = AtomicUsize::new(0);
static DRV_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Hook the kernel installs so this crate can publish a device into
/// the sysfs tree without depending on the sysfs/devfs crates.
type SysfsHook = fn(&Device);
/// Hook for publishing a bound-driver symlink: (bus, addr, driver).
type BindHook = fn(&str, &str, &'static str);
/// Hook for publishing a registered driver: (bus, name).
type DriverHook = fn(&str, &'static str);
/// Hook that mints a devtmpfs `/dev` node: (class, name, dev_t, factory).
/// Wired to `devfs::add_device_node` at boot — the indirection keeps drv free
/// of a devfs dependency (the SYSFS_HOOK pattern, applied to `/dev`).
type DevtmpfsHook = fn(&str, &str, Option<(u32, u32)>, Option<NodeFactory>);
/// Hook that removes a devtmpfs `/dev` node by name (`device_del` symmetry).
type DevtmpfsDelHook = fn(&str);

static SYSFS_HOOK:  Spinlock<Option<SysfsHook>,  DriverListClass> = Spinlock::new(None);
static BIND_HOOK:   Spinlock<Option<BindHook>,   DriverListClass> = Spinlock::new(None);
static DRIVER_HOOK: Spinlock<Option<DriverHook>, DriverListClass> = Spinlock::new(None);
static DEVTMPFS_HOOK:     Spinlock<Option<DevtmpfsHook>,    DriverListClass> = Spinlock::new(None);
static DEVTMPFS_DEL_HOOK: Spinlock<Option<DevtmpfsDelHook>, DriverListClass> = Spinlock::new(None);

/// Install the device-publish hook (kernel wires `sysfs::publish_device_cb`).
/// # C: O(1)
pub fn set_sysfs_hook(f: SysfsHook) { *SYSFS_HOOK.lock() = Some(f); }
/// Install the bind-publish hook (kernel wires `sysfs::bind_device_cb`).
/// # C: O(1)
pub fn set_bind_hook(f: BindHook) { *BIND_HOOK.lock() = Some(f); }
/// Install the driver-publish hook (kernel wires `sysfs::publish_driver_cb`).
/// # C: O(1)
pub fn set_driver_hook(f: DriverHook) { *DRIVER_HOOK.lock() = Some(f); }
/// Install the devtmpfs node-mint hook (kernel wires `devfs::add_device_node`).
/// # C: O(1)
pub fn set_devtmpfs_hook(f: DevtmpfsHook) { *DEVTMPFS_HOOK.lock() = Some(f); }
/// Install the devtmpfs node-remove hook (kernel wires `devfs::del_device_node`).
/// # C: O(1)
pub fn set_devtmpfs_del_hook(f: DevtmpfsDelHook) { *DEVTMPFS_DEL_HOOK.lock() = Some(f); }

/// Register an enumerated device. Pushes to the registry, fires the
/// sysfs-publish hook so `/sys/bus/<bus>/devices/<addr>` appears, and
/// returns the shared `Arc` (so the caller can later `bind` it).
/// # C: O(1) amortised
pub fn register_device(d: Arc<Device>) -> Arc<Device> {
    DEVICES.lock().push(Arc::clone(&d));
    DEV_COUNT.fetch_add(1, Ordering::Release);
    publish_device(&d);
    d
}

fn register_device_quiet(d: Arc<Device>) -> Arc<Device> {
    DEVICES.lock().push(Arc::clone(&d));
    DEV_COUNT.fetch_add(1, Ordering::Release);
    d
}

fn publish_device(d: &Device) {
    if let Some(h) = *SYSFS_HOOK.lock() { h(d); }
}

/// Snapshot of all registered devices. # C: O(N_devices)
pub fn devices() -> Vec<Arc<Device>> { DEVICES.lock().clone() }

/// Number of registered devices. # C: O(1)
pub fn device_count() -> usize { DEV_COUNT.load(Ordering::Acquire) }

/// Unified device registration (Linux `device_add`). ONE call publishes a
/// device to BOTH `/sys` and `/dev` from a single registration:
///   1. push to the registry so sysfs/devtmpfs views can resolve it;
///   2. if the device declares a `/dev` node (`devname.is_some()`), fire
///      `DEVTMPFS_HOOK` so devtmpfs mints `/dev/<devname>`;
///   3. fire `SYSFS_HOOK`, which emits the userspace-visible add uevent.
///
/// The devtmpfs step intentionally precedes the uevent: Linux creates the
/// device node as part of device_add before userspace observes the add event,
/// so udev/coldplug must not see an event before `/dev/<devname>` exists.
///
/// Deliberate oxide design (do NOT "fix" into Linux kset/kobject trees): `/sys`
/// directories are SYNTHESISED on demand from this registry by the sysfs crate
/// (`sysfs::bus`), so there is no eager kobject/kset dir tree or refcounting to
/// build here — registration is the single source of truth, dirs are a view.
/// # C: O(1) amortised
pub fn device_add(d: Arc<Device>) -> Arc<Device> {
    let d = register_device_quiet(d);
    if let Some(name) = d.devname.clone() {
        if let Some(h) = *DEVTMPFS_HOOK.lock() { h(d.dev_class, &name, d.dev_t, d.node_factory.clone()); }
    }
    publish_device(&d);
    d
}

/// Symmetric teardown (Linux `device_del`): drop the device from the registry
/// (so `/sys` synthesis stops listing it) and, if it owns a `/dev` node, fire
/// `DEVTMPFS_DEL_HOOK` to remove `/dev/<devname>`. # C: O(N_devices)
pub fn device_del(d: &Arc<Device>) {
    if let Some(driver_name) = d.bound() {
        if let Some(driver) = MODEL_DRIVERS.lock().iter().find(|x| x.name() == driver_name).copied() {
            driver.remove(d);
        }
        *d.driver.lock() = None;
    }
    DEVICES.lock().retain(|x| !Arc::ptr_eq(x, d));
    if DEV_COUNT.load(Ordering::Acquire) != 0 {
        DEV_COUNT.fetch_sub(1, Ordering::Release);
    }
    if let Some(name) = d.devname.clone() {
        if let Some(h) = *DEVTMPFS_DEL_HOOK.lock() { h(&name); }
    }
}

/// Register a model driver (called once from each driver's bring-up
/// success site). Fires the driver-publish hook so
/// `/sys/bus/<bus>/drivers/<name>` appears. The bus is inferred from
/// the first device the driver matches at publish time; for the
/// virtio/pci drivers we publish under both seen buses lazily, so we
/// pass the bus the binding device sits on via `bind`. Here we publish
/// under "pci" (the firmware bus) since every live driver also has a
/// pci function; the virtio-bus alias is published at bind.
/// # C: O(1)
pub fn register_driver(d: &'static dyn Driver) {
    {
        let mut l = MODEL_DRIVERS.lock();
        if l.iter().any(|x| x.name() == d.name()) { return; }
        l.push(d);
    }
    DRV_COUNT.fetch_add(1, Ordering::Release);
    if let Some(h) = *DRIVER_HOOK.lock() { h("pci", d.name()); }
}

/// Snapshot of registered model-driver names. # C: O(N_drivers)
pub fn driver_names() -> Vec<&'static str> {
    MODEL_DRIVERS.lock().iter().map(|d| d.name()).collect()
}

/// Number of registered model drivers. # C: O(1)
pub fn driver_count() -> usize { DRV_COUNT.load(Ordering::Acquire) }

/// First registered driver whose `matches(dev)` is true. # C: O(N_drivers)
pub fn match_driver(dev: &Device) -> Option<&'static str> {
    MODEL_DRIVERS.lock().iter().find(|d| d.matches(dev)).map(|d| d.name())
}

/// Bind `dev` to `driver_name`: stamps `dev.driver` and fires the
/// bind-publish hook so the `/sys/bus/<bus>/devices/<addr>/driver`
/// symlink appears. Idempotent.
/// # C: O(1)
pub fn bind(dev: &Arc<Device>, driver_name: &'static str) {
    *dev.driver.lock() = Some(driver_name);
    if let Some(h) = *BIND_HOOK.lock() { h(dev.bus, &dev.addr, driver_name); }
}

/// Probe-driven bind. This mirrors Linux's driver core order: reject an
/// already-bound device, run the driver's `probe`, and publish the binding only
/// after probe succeeds. A failed probe leaves the device unbound and retriable.
/// # C: driver-defined probe + O(1)
pub fn bind_driver(dev: &Arc<Device>, driver: &'static dyn Driver) -> KResult<()> {
    if dev.bound().is_some() { return Err(crate::Error::AlreadyBound); }
    driver.probe(dev)?;
    bind(dev, driver.name());
    Ok(())
}

/// Match the first registered driver for `dev` and bind it through
/// [`bind_driver`]. Failed probes leave the device unbound so later retries or
/// another driver-core pass can try again.
/// # C: O(N_drivers) + driver-defined probe
pub fn auto_bind(dev: &Arc<Device>) -> KResult<()> {
    let driver = MODEL_DRIVERS
        .lock()
        .iter()
        .find(|d| d.matches(dev))
        .copied()
        .ok_or(crate::Error::NoMatch)?;
    bind_driver(dev, driver)
}

/// Find the registered `Arc<Device>` at `(bus, addr)` and `bind` it to
/// `driver_name`. Convenience for bring-up sites that hold a bus addr
/// (not the Arc). No-op if the device isn't registered.
/// # C: O(N_devices)
pub fn bind_addr(bus: &str, addr: &str, driver_name: &'static str) {
    if let Some(d) = DEVICES.lock().iter().find(|d| d.bus == bus && d.addr == addr).cloned() {
        bind(&d, driver_name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::AtomicU32;

    struct FakeDrv;
    impl Driver for FakeDrv {
        fn name(&self) -> &'static str { "fake-virtio-blk" }
        fn matches(&self, dev: &Device) -> bool { dev.device_id == 0x1042 }
    }
    static FAKE: FakeDrv = FakeDrv;

    struct FailDrv;
    impl Driver for FailDrv {
        fn name(&self) -> &'static str { "fail-probe" }
        fn matches(&self, dev: &Device) -> bool { dev.device_id == 0xf001 }
        fn probe(&self, _dev: &Arc<Device>) -> KResult<()> { Err(crate::Error::ProbeFailed) }
    }
    static FAIL: FailDrv = FailDrv;

    struct RetryDrv;
    impl Driver for RetryDrv {
        fn name(&self) -> &'static str { "retry-probe" }
        fn matches(&self, dev: &Device) -> bool { dev.device_id == 0xf002 }
        fn probe(&self, _dev: &Arc<Device>) -> KResult<()> { Ok(()) }
    }
    static RETRY: RetryDrv = RetryDrv;

    struct RemoveDrv;
    impl Driver for RemoveDrv {
        fn name(&self) -> &'static str { "remove-probe" }
        fn matches(&self, dev: &Device) -> bool { dev.device_id == 0xf003 }
        fn remove(&self, _dev: &Device) { REMOVE_HITS.fetch_add(1, Ordering::Release); }
    }
    static REMOVE: RemoveDrv = RemoveDrv;
    static REMOVE_HITS: AtomicU32 = AtomicU32::new(0);

    #[test]
    fn addr_formatting_pci() {
        let a = alloc::format!("{:04x}:{:02x}:{:02x}.{}", 0u16, 0u8, 3u8, 0u8);
        assert_eq!(a, "0000:00:03.0");
    }

    #[test]
    fn register_device_and_bind() {
        let d = register_device(Arc::new(Device::new(
            "pci", alloc::string::String::from("0000:00:09.0"), 0x1AF4, 0x1042, 0x010000)));
        assert!(d.bound().is_none());
        bind(&d, "virtio-blk");
        assert_eq!(d.bound(), Some("virtio-blk"));
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
    fn device_add_fires_devtmpfs_hook_and_registers() {
        use sync::Spinlock as TestLock;
        // Record what the devtmpfs hook receives (mimics devfs::add_device_node).
        static SEEN: TestLock<Option<(&'static str, String, Option<(u32, u32)>)>, DriverListClass>
            = TestLock::new(None);
        fn cb(class: &str, name: &str, dev_t: Option<(u32, u32)>, _f: Option<NodeFactory>) {
            // class is &'static in practice (dev_class); store via a match for the test.
            let c: &'static str = if class == "block" { "block" } else { "other" };
            *SEEN.lock() = Some((c, String::from(name), dev_t));
        }
        set_devtmpfs_hook(cb);
        let dev = device_add(Arc::new(
            Device::new("virtio", String::from("virtio9"), 0x1AF4, 0x1042, 0)
                .with_devnode("block", String::from("vdz"), Some((254, 9)))));
        // /dev node minted via the hook with the right class/name/dev_t.
        let seen = SEEN.lock().clone();
        assert_eq!(seen, Some(("block", String::from("vdz"), Some((254, 9)))));
        // and the device appears in the drv registry.
        assert!(devices().iter().any(|x| x.addr == "virtio9"));
        assert_eq!(dev.dev_class, "block");
    }

    #[test]
    fn device_add_mints_devtmpfs_before_sysfs_event() {
        static STEP: AtomicU32 = AtomicU32::new(0);
        static DEVFS_STEP: AtomicU32 = AtomicU32::new(0);
        static SYSFS_STEP: AtomicU32 = AtomicU32::new(0);
        fn devfs_cb(_class: &str, name: &str, _dt: Option<(u32, u32)>, _f: Option<NodeFactory>) {
            if name == "order-test" {
                DEVFS_STEP.store(STEP.fetch_add(1, Ordering::AcqRel) + 1, Ordering::Release);
            }
        }
        fn sysfs_cb(dev: &Device) {
            if dev.addr == "order-test" {
                SYSFS_STEP.store(STEP.fetch_add(1, Ordering::AcqRel) + 1, Ordering::Release);
            }
        }
        STEP.store(0, Ordering::Release);
        DEVFS_STEP.store(0, Ordering::Release);
        SYSFS_STEP.store(0, Ordering::Release);
        set_devtmpfs_hook(devfs_cb);
        set_sysfs_hook(sysfs_cb);
        device_add(Arc::new(
            Device::new("misc", String::from("order-test"), 0, 0, 0)
                .with_devnode("misc", String::from("order-test"), Some((10, 241)))));
        let devfs = DEVFS_STEP.load(Ordering::Acquire);
        let sysfs = SYSFS_STEP.load(Ordering::Acquire);
        assert!(devfs != 0 && sysfs != 0 && devfs < sysfs,
            "device_add must create devtmpfs node before sysfs add uevent");
    }

    #[test]
    fn sysfs_hook_fires_on_register() {
        static HITS: AtomicU32 = AtomicU32::new(0);
        fn cb(_d: &Device) { HITS.fetch_add(1, Ordering::Release); }
        set_sysfs_hook(cb);
        let before = HITS.load(Ordering::Acquire);
        register_device(Arc::new(Device::new(
            "pci", alloc::string::String::from("0000:00:0c.0"), 0x1234, 0x5678, 0)));
        assert!(HITS.load(Ordering::Acquire) > before);
    }

    #[test]
    fn failed_probe_leaves_device_unbound_and_retriable() {
        register_driver(&FAIL);
        let dev = register_device(Arc::new(Device::new(
            "pci", String::from("0000:00:0d.0"), 0x1AF4, 0xf001, 0)));
        assert_eq!(auto_bind(&dev), Err(crate::Error::ProbeFailed));
        assert!(dev.bound().is_none());
        assert_eq!(auto_bind(&dev), Err(crate::Error::ProbeFailed));
        assert!(dev.bound().is_none());
    }

    #[test]
    fn bind_driver_rejects_duplicate_bind() {
        register_driver(&RETRY);
        let dev = register_device(Arc::new(Device::new(
            "pci", String::from("0000:00:0e.0"), 0x1AF4, 0xf002, 0)));
        assert_eq!(auto_bind(&dev), Ok(()));
        assert_eq!(dev.bound(), Some("retry-probe"));
        assert_eq!(bind_driver(&dev, &RETRY), Err(crate::Error::AlreadyBound));
        assert_eq!(dev.bound(), Some("retry-probe"));
    }

    #[test]
    fn device_del_calls_bound_driver_remove_once() {
        register_driver(&REMOVE);
        let dev = device_add(Arc::new(Device::new(
            "pci", String::from("0000:00:0f.0"), 0x1AF4, 0xf003, 0)
                .with_devnode("misc", String::from("remove-test"), Some((10, 240)))));
        assert_eq!(auto_bind(&dev), Ok(()));
        let before = REMOVE_HITS.load(Ordering::Acquire);
        device_del(&dev);
        assert_eq!(REMOVE_HITS.load(Ordering::Acquire), before + 1);
        assert!(dev.bound().is_none());
        assert!(!devices().iter().any(|x| Arc::ptr_eq(x, &dev)));
    }
}
