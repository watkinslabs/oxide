// Real driver model (drivers-plan D1a): Device / Driver registries +
// bus/driver binding, plus the sysfs-publish + bind hooks the kernel
// wires to the sysfs crate (this crate is no_std with no devfs dep,
// so it reaches sysfs through indirect `fn` hooks, not a direct dep).
//
// This is the authoritative driver path. Buses register devices, drivers
// register `Driver` objects, and binding calls `Driver::probe` before model
// state is published as bound. A future distributed driver slice can replace
// explicit boot-time `register_driver` calls without changing this contract.
//
// Module manifest:
// - `tests`: hosted driver-model lifecycle, binding, hook-order, and devtmpfs/sysfs tests.

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
    /// PCI BAR index when this is a PCI BAR resource. Non-PCI buses may leave
    /// this as zero until they grow indexed resources of their own.
    pub bar:   u8,
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
    // Populated by devices brought up via `try_device_add`. `class` (PCI class,
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

/// Fallible unified device registration (Linux `device_add`). ONE call
/// publishes a device to BOTH `/sys` and `/dev` from a single registration:
///   1. reject duplicate `(bus, addr)` identities before publishing anything;
///   2. push to the registry so sysfs can resolve the object;
///   3. if the device declares a `/dev` node (`devname.is_some()`), fire
///      `DEVTMPFS_HOOK` so devtmpfs mints `/dev/<devname>`;
///   4. attach any already-registered matching driver while the device is in
///      the registry but before the add uevent, matching Linux `device_add`
///      probing before `KOBJ_ADD`;
///   5. fire `SYSFS_HOOK`, which emits the Linux `add` uevent only after the
///      devtmpfs node is visible and initial driver probe had a chance to
///      publish child devices.
///
/// Deliberate oxide design (do NOT "fix" into Linux kset/kobject trees): `/sys`
/// directories are SYNTHESISED on demand from this registry by the sysfs crate
/// (`sysfs::bus`), so there is no eager kobject/kset dir tree or refcounting to
/// build here — registration is the single source of truth, dirs are a view.
/// # C: O(N_devices)
pub fn try_device_add(d: Arc<Device>) -> KResult<Arc<Device>> {
    if DEVICES.lock().iter().any(|x| x.bus == d.bus && x.addr == d.addr) {
        return Err(crate::Error::Busy);
    }
    let d = push_device(d);
    if let Some(name) = d.devname.clone() {
        if let Some(h) = *DEVTMPFS_HOOK.lock() { h(d.dev_class, &name, d.dev_t, d.node_factory.clone()); }
    }
    attach_device_to_registered_drivers(&d, false);
    if let Some(h) = *SYSFS_HOOK.lock() { h(&d); }
    Ok(d)
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
/// # C: O(N_devices + probe)
pub fn register_driver(d: &'static dyn Driver) {
    {
        let mut l = MODEL_DRIVERS.lock();
        if l.iter().any(|x| x.bus() == d.bus() && x.name() == d.name()) { return; }
        l.push(d);
    }
    DRV_COUNT.fetch_add(1, Ordering::Release);
    if let Some(h) = *DRIVER_HOOK.lock() { h(d.bus(), d.name()); }
    attach_driver_to_existing_devices(d);
}

/// Unregister a model driver. Bound devices are detached while the driver is
/// still present in the registry, then the driver disappears from
/// `/sys/bus/<bus>/drivers` because sysfs enumerates this registry dynamically.
/// # C: O(N_devices * N_drivers + remove + N_drivers)
pub fn unregister_driver(d: &'static dyn Driver) -> KResult<()> {
    if !MODEL_DRIVERS.lock().iter().any(|x| x.bus() == d.bus() && x.name() == d.name()) {
        return Err(crate::Error::NotFound);
    }

    for dev in devices() {
        if dev.bus == d.bus() && dev.bound() == Some(d.name()) {
            unbind(&dev)?;
        }
    }

    let removed = {
        let mut drivers = MODEL_DRIVERS.lock();
        let before = drivers.len();
        drivers.retain(|x| !(x.bus() == d.bus() && x.name() == d.name()));
        drivers.len() != before
    };
    if removed {
        DRV_COUNT.fetch_sub(1, Ordering::Release);
        Ok(())
    } else {
        Err(crate::Error::NotFound)
    }
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

fn attach_driver_to_existing_devices(driver: &'static dyn Driver) {
    for dev in devices() {
        if dev.bound().is_some() || !driver_matches_device(driver, &dev) {
            continue;
        }
        let _ = bind_inner(&dev, driver.name(), true);
    }
}

fn attach_device_to_registered_drivers(dev: &Arc<Device>, emit_bind_event: bool) {
    let drivers: Vec<&'static dyn Driver> = MODEL_DRIVERS.lock().clone();
    for driver in drivers {
        if dev.bound().is_some() || !driver_matches_device(driver, dev) {
            continue;
        }
        let _ = bind_inner(dev, driver.name(), emit_bind_event);
    }
}

/// Bind `dev` to `driver_name`: validate the registered driver, reject
/// duplicate or non-matching binds, call `Driver::probe`, then stamp
/// `dev.driver` and fire the bind-publish hook. Probe failure leaves the
/// device unbound. # C: O(N_drivers + probe)
pub fn bind(dev: &Arc<Device>, driver_name: &'static str) -> KResult<()> {
    bind_inner(dev, driver_name, true)
}

fn bind_inner(dev: &Arc<Device>, driver_name: &'static str, emit_bind_event: bool) -> KResult<()> {
    if dev.bound().is_some() { return Err(crate::Error::AlreadyBound); }
    let driver = find_driver_on_bus(dev.bus, driver_name).ok_or(crate::Error::NotFound)?;
    if !driver_matches_device(driver, dev) { return Err(crate::Error::NoMatch); }
    driver.probe(dev)?;
    *dev.driver.lock() = Some(driver_name);
    if emit_bind_event {
        if let Some(h) = *BIND_HOOK.lock() { h(dev.bus, &dev.addr, driver_name, BindEvent::Bound); }
    }
    Ok(())
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

/// Quiesce every currently-bound device for reboot/poweroff. This is not
/// hot-unplug: bindings, sysfs state, and devtmpfs nodes remain published
/// because the machine is entering a terminal power transition. Devices are
/// walked in reverse registration order so child/later devices quiet before
/// earlier parent transports.
/// # C: O(N_devices * N_drivers + shutdown)
pub fn shutdown_all() {
    let mut snapshot = devices();
    snapshot.reverse();
    for dev in snapshot {
        let Some(driver_name) = dev.bound() else { continue; };
        if let Some(driver) = find_driver_on_bus(dev.bus, driver_name) {
            driver.shutdown(&dev);
        }
    }
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
mod tests;
