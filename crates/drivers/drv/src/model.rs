// Real driver model (drivers-plan D1a): Device / Driver registries +
// bus/driver binding, plus the sysfs-publish + bind hooks the kernel
// wires to the sysfs crate (this crate is no_std with no devfs dep,
// so it reaches sysfs through indirect `fn` hooks, not a direct dep).
//
// This is the authoritative driver path. Buses register devices, drivers
// register `Driver` objects, and binding calls `Driver::probe` before model
// state is published as bound. A future distributed driver slice can replace
// explicit boot-time `register_driver` calls without changing this contract.

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

/// Bus resource range associated with a device, usually a PCI BAR. `flags`
/// uses Linux `IORESOURCE_*` values so sysfs can expose the same contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Resource {
    pub start: u64,
    pub end:   u64,
    pub flags: u64,
}

/// One enumerated device on a bus. `driver` names the bound driver
/// (None = unbound). Held as `Arc<Device>` so the registry, the bound
/// driver, and the sysfs inode tree all share one instance.
pub struct Device {
    /// Bus kind: `"pci"` or `"virtio"`.
    pub bus:       &'static str,
    /// Bus address, e.g. `"0000:00:03.0"` (pci) or `"virtio2"`.
    pub addr:      String,
    /// Parent bus for child devices, e.g. a virtio device's PCI transport.
    pub parent_bus:  Option<&'static str>,
    /// Parent bus address, paired with `parent_bus`.
    pub parent_addr: Option<String>,
    /// PCI vendor id (0 for synthetic virtio bus devices).
    pub vendor_id: u16,
    /// PCI device id, or virtio device-id on the virtio bus.
    pub device_id: u16,
    /// 24-bit PCI class/subclass/prog-if (class<<16|sub<<8|progif).
    pub class:     u32,
    /// Bound driver name, None when unbound.
    pub driver:    Spinlock<Option<&'static str>, DriverListClass>,
    /// Optional Linux `driver_override`: when set, only this driver name may
    /// match/bind the device, and normal ID-table matching is bypassed.
    pub driver_override: Spinlock<Option<String>, DriverListClass>,
    // --- /dev-node (devtmpfs) fields --------------------------------------
    // Populated by devices brought up via `device_add`. `class` (PCI class,
    // above) is distinct from `dev_class` (the devtmpfs class string), hence
    // the different name.
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
    /// Bus resources, e.g. PCI BAR windows.
    pub resources: Vec<Resource>,
}

impl Device {
    /// Construct an unbound device with no `/dev` node. # C: O(1)
    pub fn new(bus: &'static str, addr: String, vendor_id: u16, device_id: u16, class: u32) -> Self {
        Self {
            bus, addr, parent_bus: None, parent_addr: None, vendor_id, device_id, class,
            driver: Spinlock::new(None), driver_override: Spinlock::new(None),
            dev_class: "", devname: None, dev_t: None, node_factory: None,
            resources: Vec::new(),
        }
    }
    /// Currently-bound driver name, if any. # C: O(1)
    pub fn bound(&self) -> Option<&'static str> { *self.driver.lock() }
    /// Current driver override, if any. # C: O(n)
    pub fn driver_override(&self) -> Option<String> { self.driver_override.lock().clone() }
    /// Set or clear the driver override. Empty strings clear the override. # C: O(n)
    pub fn set_driver_override(&self, value: Option<String>) {
        *self.driver_override.lock() = value.filter(|v| !v.is_empty());
    }
    /// Parent device identity, if this is a child on a bus layered over
    /// another transport. # C: O(1)
    pub fn parent(&self) -> Option<(&'static str, &str)> {
        Some((self.parent_bus?, self.parent_addr.as_deref()?))
    }
    /// Builder: attach a parent device identity. # C: O(1)
    pub fn with_parent(mut self, bus: &'static str, addr: String) -> Self {
        self.parent_bus = Some(bus);
        self.parent_addr = Some(addr);
        self
    }
    /// Builder: declare a `/dev` node of `class` at `/dev/<name>` addressing
    /// `dev_t` (`None` ⇒ supply a [`Self::with_node_factory`] instead). # C: O(1)
    pub fn with_devnode(mut self, class: &'static str, name: String, dev_t: Option<(u32, u32)>) -> Self {
        self.dev_class = class; self.devname = Some(name); self.dev_t = dev_t; self
    }
    /// Builder: attach a bespoke `/dev` node factory (custom `FileOps`). # C: O(1)
    pub fn with_node_factory(mut self, f: NodeFactory) -> Self { self.node_factory = Some(f); self }
    /// Builder: attach bus resources to the device. # C: O(n)
    pub fn with_resources(mut self, resources: Vec<Resource>) -> Self {
        self.resources = resources;
        self
    }
}

/// The driver contract (drivers-plan: Driver/DriverInstance/Device +
/// probe/remove/shutdown symmetry). Object-safe (`&'static dyn Driver`).
/// `matches` decides whether this driver claims `dev`; `probe` performs
/// device bring-up and must leave no published partial state on failure;
/// `remove`/`shutdown` are the teardown symmetry.
pub trait Driver: Sync {
    /// Bus this driver registers on. PCI is the default because the current
    /// hardware model drivers mostly bind PCI functions; platform and future
    /// virtio child drivers override this.
    fn bus(&self) -> &'static str { "pci" }
    /// Driver name (appears at `/sys/bus/<bus>/drivers/<name>`).
    fn name(&self) -> &'static str;
    /// True iff this driver claims `dev`.
    fn matches(&self, dev: &Device) -> bool;
    /// Bind `dev`. Default Ok for passive/pseudo drivers. # C: driver-defined
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
/// Driver-binding transition reported after model state has changed.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BindEvent {
    Bound,
    Unbound,
}

/// Hook for publishing a driver-binding transition: (bus, addr, driver, event).
type BindHook = fn(&str, &str, &'static str, BindEvent);
/// Hook for publishing a registered driver: (bus, name).
type DriverHook = fn(&str, &'static str);
/// Hook that mints a devtmpfs `/dev` node: (class, name, dev_t, factory).
/// Wired to `devfs::add_device_node` at boot — the indirection keeps drv free
/// of a devfs dependency (the SYSFS_HOOK pattern, applied to `/dev`).
type DevtmpfsHook = fn(&str, &str, Option<(u32, u32)>, Option<NodeFactory>);
/// Hook that removes a devtmpfs `/dev` node by name (`device_del` symmetry).
type DevtmpfsDelHook = fn(&str);

static SYSFS_HOOK:  Spinlock<Option<SysfsHook>,  DriverListClass> = Spinlock::new(None);
static SYSFS_REMOVE_HOOK: Spinlock<Option<SysfsHook>, DriverListClass> = Spinlock::new(None);
static BIND_HOOK:   Spinlock<Option<BindHook>,   DriverListClass> = Spinlock::new(None);
static DRIVER_HOOK: Spinlock<Option<DriverHook>, DriverListClass> = Spinlock::new(None);
static DEVTMPFS_HOOK:     Spinlock<Option<DevtmpfsHook>,    DriverListClass> = Spinlock::new(None);
static DEVTMPFS_DEL_HOOK: Spinlock<Option<DevtmpfsDelHook>, DriverListClass> = Spinlock::new(None);

/// Install the device-publish hook (kernel wires `sysfs::publish_device_cb`).
/// # C: O(1)
pub fn set_sysfs_hook(f: SysfsHook) { *SYSFS_HOOK.lock() = Some(f); }
/// Install the device-remove hook (kernel wires `sysfs::remove_device_cb`).
/// # C: O(1)
pub fn set_sysfs_remove_hook(f: SysfsHook) { *SYSFS_REMOVE_HOOK.lock() = Some(f); }
/// Install the bind-transition hook (kernel wires `sysfs::bind_device_cb`).
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

/// Push an enumerated device into the authoritative registry.
/// # C: O(1) amortised
fn push_device(d: Arc<Device>) -> Arc<Device> {
    DEVICES.lock().push(Arc::clone(&d));
    DEV_COUNT.fetch_add(1, Ordering::Release);
    d
}

/// Snapshot of all registered devices. # C: O(N_devices)
pub fn devices() -> Vec<Arc<Device>> { DEVICES.lock().clone() }

/// Number of registered devices. # C: O(1)
pub fn device_count() -> usize { DEV_COUNT.load(Ordering::Acquire) }

/// Unified device registration (Linux `device_add`). ONE call publishes a
/// device to BOTH `/sys` and `/dev` from a single registration:
///   1. push to the registry so sysfs can resolve the object;
///   2. if the device declares a `/dev` node (`devname.is_some()`), fire
///      `DEVTMPFS_HOOK` so devtmpfs mints `/dev/<devname>`;
///   3. fire `SYSFS_HOOK`, which emits the Linux `add` uevent only after the
///      devtmpfs node is visible.
///
/// Deliberate oxide design (do NOT "fix" into Linux kset/kobject trees): `/sys`
/// directories are SYNTHESISED on demand from this registry by the sysfs crate
/// (`sysfs::bus`), so there is no eager kobject/kset dir tree or refcounting to
/// build here — registration is the single source of truth, dirs are a view.
/// # C: O(1) amortised
pub fn device_add(d: Arc<Device>) -> Arc<Device> {
    let d = push_device(d);
    if let Some(name) = d.devname.clone() {
        if let Some(h) = *DEVTMPFS_HOOK.lock() { h(d.dev_class, &name, d.dev_t, d.node_factory.clone()); }
    }
    if let Some(h) = *SYSFS_HOOK.lock() { h(&d); }
    d
}

/// Symmetric teardown (Linux `device_del`): first detach any bound driver so
/// the driver's `remove` owns hardware teardown, then emit `remove` while the
/// object is still visible, remove any owned `/dev` node, and finally drop the
/// device from the registry so `/sys` synthesis stops listing it.
/// # C: O(N_devices + remove)
pub fn device_del(d: &Arc<Device>) {
    if !DEVICES.lock().iter().any(|x| Arc::ptr_eq(x, d)) {
        return;
    }
    if d.bound().is_some() {
        let _ = unbind(d);
    }
    if let Some(h) = *SYSFS_REMOVE_HOOK.lock() { h(d); }
    if let Some(name) = d.devname.clone() {
        if let Some(h) = *DEVTMPFS_DEL_HOOK.lock() { h(&name); }
    }
    let removed = {
        let mut devices = DEVICES.lock();
        let before = devices.len();
        devices.retain(|x| !Arc::ptr_eq(x, d));
        devices.len() != before
    };
    if removed {
        DEV_COUNT.fetch_sub(1, Ordering::Release);
    }
}

/// Register a model driver. Fires the driver-publish hook so
/// `/sys/bus/<bus>/drivers/<name>` appears on the bus the driver actually
/// belongs to.
/// # C: O(1)
pub fn register_driver(d: &'static dyn Driver) {
    {
        let mut l = MODEL_DRIVERS.lock();
        if l.iter().any(|x| x.bus() == d.bus() && x.name() == d.name()) { return; }
        l.push(d);
    }
    DRV_COUNT.fetch_add(1, Ordering::Release);
    if let Some(h) = *DRIVER_HOOK.lock() { h(d.bus(), d.name()); }
}

/// Snapshot of registered model-driver names. # C: O(N_drivers)
pub fn driver_names() -> Vec<&'static str> {
    MODEL_DRIVERS.lock().iter().map(|d| d.name()).collect()
}

/// Snapshot of registered model-driver names for one bus. # C: O(N_drivers)
pub fn driver_names_for_bus(bus: &str) -> Vec<&'static str> {
    MODEL_DRIVERS.lock().iter()
        .filter(|d| d.bus() == bus)
        .map(|d| d.name())
        .collect()
}

/// Number of registered model drivers. # C: O(1)
pub fn driver_count() -> usize { DRV_COUNT.load(Ordering::Acquire) }

/// First registered driver whose `matches(dev)` is true. # C: O(N_drivers)
pub fn match_driver(dev: &Device) -> Option<&'static str> {
    let drivers = MODEL_DRIVERS.lock();
    if let Some(override_name) = dev.driver_override() {
        return drivers.iter()
            .find(|d| d.bus() == dev.bus && d.name() == override_name.as_str())
            .map(|d| d.name());
    }
    drivers.iter()
        .find(|d| d.bus() == dev.bus && d.matches(dev))
        .map(|d| d.name())
}

fn find_driver_on_bus(bus: &str, driver_name: &str) -> Option<&'static dyn Driver> {
    MODEL_DRIVERS.lock()
        .iter()
        .find(|d| d.bus() == bus && d.name() == driver_name)
        .copied()
}

fn driver_matches_device(driver: &dyn Driver, dev: &Device) -> bool {
    if driver.bus() != dev.bus {
        return false;
    }
    match dev.driver_override() {
        Some(name) => driver.name() == name.as_str(),
        None => driver.matches(dev),
    }
}

/// Bind `dev` to `driver_name`: validate the registered driver, reject
/// duplicate or non-matching binds, call `Driver::probe`, then stamp
/// `dev.driver` and fire the bind-publish hook. Probe failure leaves the
/// device unbound. # C: O(N_drivers + probe)
pub fn bind(dev: &Arc<Device>, driver_name: &'static str) -> KResult<()> {
    if dev.bound().is_some() { return Err(crate::Error::AlreadyBound); }
    let driver = find_driver_on_bus(dev.bus, driver_name).ok_or(crate::Error::NotFound)?;
    if !driver_matches_device(driver, dev) { return Err(crate::Error::NoMatch); }
    driver.probe(dev)?;
    *dev.driver.lock() = Some(driver_name);
    if let Some(h) = *BIND_HOOK.lock() { h(dev.bus, &dev.addr, driver_name, BindEvent::Bound); }
    Ok(())
}

/// Try every registered driver that matches `dev`, binding the first one
/// whose `probe` succeeds. If no driver matches, returns `NoMatch`; if one or
/// more match but all probes fail, returns the last probe error and leaves the
/// device unbound. # C: O(N_drivers × probe)
pub fn auto_bind(dev: &Arc<Device>) -> KResult<()> {
    if dev.bound().is_some() { return Err(crate::Error::AlreadyBound); }
    let drivers: Vec<&'static dyn Driver> = MODEL_DRIVERS.lock().clone();
    let mut matched = false;
    let mut last_err = crate::Error::NoMatch;
    for driver in drivers {
        if !driver_matches_device(driver, dev) { continue; }
        matched = true;
        match bind(dev, driver.name()) {
            Ok(()) => return Ok(()),
            Err(crate::Error::AlreadyBound) => return Err(crate::Error::AlreadyBound),
            Err(e) => last_err = e,
        }
    }
    if matched { Err(last_err) } else { Err(crate::Error::NoMatch) }
}

/// Unbind a device from its current driver. Calls `Driver::remove`, clears
/// model state, then emits the same change hook used for bind so sysfs/udev
/// observes a driver-link transition. # C: O(N_drivers + remove)
pub fn unbind(dev: &Arc<Device>) -> KResult<()> {
    let driver_name = dev.bound().ok_or(crate::Error::NoMatch)?;
    let driver = find_driver_on_bus(dev.bus, driver_name).ok_or(crate::Error::NotFound)?;
    driver.remove(dev);
    *dev.driver.lock() = None;
    if let Some(h) = *BIND_HOOK.lock() { h(dev.bus, &dev.addr, driver_name, BindEvent::Unbound); }
    Ok(())
}

/// Find the registered `Arc<Device>` at `(bus, addr)` and `bind` it to
/// `driver_name`. Convenience for bring-up sites that hold a bus addr
/// (not the Arc).
/// # C: O(N_devices)
pub fn bind_addr(bus: &str, addr: &str, driver_name: &'static str) -> KResult<()> {
    let d = DEVICES.lock().iter()
        .find(|d| d.bus == bus && d.addr == addr)
        .cloned()
        .ok_or(crate::Error::NotFound)?;
    bind(&d, driver_name)
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

    static AUTO_FAIL_PROBES: AtomicU32 = AtomicU32::new(0);
    struct AutoFailingProbeDrv;
    impl Driver for AutoFailingProbeDrv {
        fn name(&self) -> &'static str { "auto-failing-probe" }
        fn matches(&self, dev: &Device) -> bool { dev.device_id == 0xf00e }
        fn probe(&self, _dev: &Arc<Device>) -> KResult<()> {
            AUTO_FAIL_PROBES.fetch_add(1, Ordering::Release);
            Err(crate::Error::ProbeFailed)
        }
    }
    static AUTO_FAILING_PROBE_DRV: AutoFailingProbeDrv = AutoFailingProbeDrv;

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
        assert!(d.bound().is_none());
        assert_eq!(bind(&d, "fake-virtio-blk"), Ok(()));
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
        let d = device_add(Arc::new(Device::new(
            "pci", alloc::string::String::from("0000:00:0e.0"), 0x1AF4, 0x1042, 0)));
        d.set_driver_override(Some(String::from("override-only")));
        assert_eq!(match_driver(&d), Some("override-only"));
        assert_eq!(bind(&d, "fake-virtio-blk"), Err(crate::Error::NoMatch));
        assert_eq!(bind(&d, "override-only"), Ok(()));
        assert_eq!(d.bound(), Some("override-only"));
    }

    #[test]
    fn auto_bind_uses_matching_registered_driver() {
        register_driver(&FAKE);
        let d = device_add(Arc::new(Device::new(
            "pci", alloc::string::String::from("0000:00:0d.0"), 0x1AF4, 0x1042, 0)));
        assert_eq!(auto_bind(&d), Ok(()));
        assert_eq!(d.bound(), Some("fake-virtio-blk"));
    }

    #[test]
    fn failed_probe_leaves_device_unbound_and_retriable() {
        FAIL_PROBES.store(0, Ordering::Release);
        register_driver(&FAILING_PROBE_DRV);
        let d = device_add(Arc::new(Device::new(
            "pci", String::from("0000:00:13.0"), 0x1234, 0xf00d, 0)));

        assert_eq!(bind(&d, "failing-probe"), Err(crate::Error::ProbeFailed));
        assert!(d.bound().is_none());
        assert_eq!(FAIL_PROBES.load(Ordering::Acquire), 1);

        assert_eq!(bind(&d, "failing-probe"), Err(crate::Error::ProbeFailed));
        assert!(d.bound().is_none());
        assert_eq!(FAIL_PROBES.load(Ordering::Acquire), 2);
    }

    #[test]
    fn auto_bind_failed_probe_leaves_device_unbound() {
        AUTO_FAIL_PROBES.store(0, Ordering::Release);
        register_driver(&AUTO_FAILING_PROBE_DRV);
        let d = device_add(Arc::new(Device::new(
            "pci", String::from("0000:00:14.0"), 0x1234, 0xf00e, 0)));

        assert_eq!(auto_bind(&d), Err(crate::Error::ProbeFailed));
        assert!(d.bound().is_none());
        assert_eq!(AUTO_FAIL_PROBES.load(Ordering::Acquire), 1);
    }

    #[test]
    fn device_del_unbinds_bound_driver_once() {
        REMOVE_HITS.store(0, Ordering::Release);
        register_driver(&REMOVE_DRV);
        let d = device_add(Arc::new(Device::new(
            "pci", String::from("0000:00:11.0"), 0x1234, 0x7777, 0)));
        assert_eq!(bind(&d, "remove-test"), Ok(()));

        device_del(&d);
        assert_eq!(REMOVE_HITS.load(Ordering::Acquire), 1);
        assert!(d.bound().is_none());
        assert!(!devices().iter().any(|x| Arc::ptr_eq(x, &d)));

        device_del(&d);
        assert_eq!(REMOVE_HITS.load(Ordering::Acquire), 1);
    }

    #[test]
    fn bind_hook_reports_bound_and_unbound_after_state_change() {
        use sync::Spinlock as TestLock;
        static EVENTS: TestLock<Vec<BindEvent>, DriverListClass> = TestLock::new(Vec::new());
        fn hook(_bus: &str, _addr: &str, _driver: &'static str, event: BindEvent) {
            EVENTS.lock().push(event);
        }

        EVENTS.lock().clear();
        set_bind_hook(hook);
        register_driver(&REMOVE_DRV);
        let d = device_add(Arc::new(Device::new(
            "pci", String::from("0000:00:12.0"), 0x1234, 0x7777, 0)));

        assert_eq!(bind(&d, "remove-test"), Ok(()));
        assert_eq!(d.bound(), Some("remove-test"));
        assert_eq!(unbind(&d), Ok(()));
        assert_eq!(d.bound(), None);
        assert_eq!(&*EVENTS.lock(), &[BindEvent::Bound, BindEvent::Unbound]);
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
        assert_eq!(bind(&platform, "platform-test"), Ok(()));
        assert_eq!(platform.bound(), Some("platform-test"));
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

    #[test]
    fn device_add_fires_devtmpfs_hook_and_registers() {
        use sync::Spinlock as TestLock;
        // Record what the devtmpfs hook receives (mimics devfs::add_device_node).
        static SEEN: TestLock<Option<(&'static str, String, Option<(u32, u32)>)>, DriverListClass>
            = TestLock::new(None);
        static ORDER: AtomicU32 = AtomicU32::new(0);
        static SYSFS_AFTER_DEV: AtomicU32 = AtomicU32::new(0);
        fn cb(class: &str, name: &str, dev_t: Option<(u32, u32)>, _f: Option<NodeFactory>) {
            // class is &'static in practice (dev_class); store via a match for the test.
            let c: &'static str = if class == "block" { "block" } else { "other" };
            *SEEN.lock() = Some((c, String::from(name), dev_t));
            ORDER.store(1, Ordering::Release);
        }
        fn sysfs_cb(_d: &Device) {
            if ORDER.load(Ordering::Acquire) == 1 {
                SYSFS_AFTER_DEV.store(1, Ordering::Release);
            }
        }
        ORDER.store(0, Ordering::Release);
        SYSFS_AFTER_DEV.store(0, Ordering::Release);
        set_devtmpfs_hook(cb);
        set_sysfs_hook(sysfs_cb);
        let dev = device_add(Arc::new(
            Device::new("virtio", String::from("virtio9"), 0x1AF4, 0x1042, 0)
                .with_devnode("block", String::from("vdz"), Some((254, 9)))));
        // /dev node minted via the hook with the right class/name/dev_t.
        let seen = SEEN.lock().clone();
        assert_eq!(seen, Some(("block", String::from("vdz"), Some((254, 9)))));
        // and the device appears in the drv registry.
        assert!(devices().iter().any(|x| x.addr == "virtio9"));
        assert_eq!(dev.dev_class, "block");
        assert_eq!(SYSFS_AFTER_DEV.load(Ordering::Acquire), 1);
    }

    #[test]
    fn sysfs_hook_fires_on_device_add() {
        static HITS: AtomicU32 = AtomicU32::new(0);
        fn cb(_d: &Device) { HITS.fetch_add(1, Ordering::Release); }
        set_sysfs_hook(cb);
        let before = HITS.load(Ordering::Acquire);
        device_add(Arc::new(Device::new(
            "pci", alloc::string::String::from("0000:00:0c.0"), 0x1234, 0x5678, 0)));
        assert!(HITS.load(Ordering::Acquire) > before);
    }
}
