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

/// One BAR region as the sysfs `resource` file reports it (DVR-0009):
/// inclusive `[start,end]` in bytes + the Linux `IORESOURCE_*` flag set.
/// Empty BAR (and 64-bit high half) = all zero.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Resource { pub start: u64, pub end: u64, pub flags: u64 }

/// PCI config-space snapshot captured at enumeration, backing the sysfs
/// attribute files udev/libpci read (DVR-0009..0011). Only the pci-bus
/// `Device` carries one; virtio/synthetic devices leave it `None`.
#[derive(Clone)]
pub struct PciCfg {
    /// Config-space revision id (offset 0x08 low byte).
    pub revision:         u8,
    /// Subsystem vendor id (offset 0x2C).
    pub subsystem_vendor: u16,
    /// Subsystem device id (offset 0x2E).
    pub subsystem_device: u16,
    /// Interrupt line (offset 0x3C low byte) — the `irq` attribute.
    pub irq:              u8,
    /// Decoded + sized BAR regions for `resource`/`resourceN`.
    pub bars:             [Resource; 6],
}

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
    /// PCI config snapshot (pci bus only) for sysfs attrs. # DVR-0009..0011
    pub pci:       Option<PciCfg>,
    /// `driver_override` sysfs attr (DVR-0011): admin-forced driver match.
    pub driver_override: Spinlock<Option<String>, DriverListClass>,
    /// Bound driver name, None when unbound.
    pub driver:    Spinlock<Option<&'static str>, DriverListClass>,
}

impl Device {
    /// Construct an unbound device (no PCI snapshot). # C: O(1)
    pub fn new(bus: &'static str, addr: String, vendor_id: u16, device_id: u16, class: u32) -> Self {
        Self { bus, addr, vendor_id, device_id, class, pci: None,
               driver_override: Spinlock::new(None), driver: Spinlock::new(None) }
    }
    /// Attach a PCI config snapshot (builder). # C: O(1)
    pub fn with_pci(mut self, cfg: PciCfg) -> Self { self.pci = Some(cfg); self }
    /// Currently-bound driver name, if any. # C: O(1)
    pub fn bound(&self) -> Option<&'static str> { *self.driver.lock() }
    /// Read the `driver_override` string (Linux empty = `"\n"`). # C: O(1)
    pub fn driver_override(&self) -> Option<String> { self.driver_override.lock().clone() }
    /// Set/clear `driver_override`; empty/`"(null)"` clears it. # C: O(1)
    pub fn set_driver_override(&self, s: &str) {
        let t = s.trim_matches(|c| c == '\n' || c == '\0');
        *self.driver_override.lock() = if t.is_empty() || t == "(null)" { None } else { Some(String::from(t)) };
    }
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

static SYSFS_HOOK:  Spinlock<Option<SysfsHook>,  DriverListClass> = Spinlock::new(None);
static BIND_HOOK:   Spinlock<Option<BindHook>,   DriverListClass> = Spinlock::new(None);
static DRIVER_HOOK: Spinlock<Option<DriverHook>, DriverListClass> = Spinlock::new(None);

/// Install the device-publish hook (kernel wires `sysfs::publish_device_cb`).
/// # C: O(1)
pub fn set_sysfs_hook(f: SysfsHook) { *SYSFS_HOOK.lock() = Some(f); }
/// Install the bind-publish hook (kernel wires `sysfs::bind_device_cb`).
/// # C: O(1)
pub fn set_bind_hook(f: BindHook) { *BIND_HOOK.lock() = Some(f); }
/// Install the driver-publish hook (kernel wires `sysfs::publish_driver_cb`).
/// # C: O(1)
pub fn set_driver_hook(f: DriverHook) { *DRIVER_HOOK.lock() = Some(f); }

/// Register an enumerated device. Pushes to the registry, fires the
/// sysfs-publish hook so `/sys/bus/<bus>/devices/<addr>` appears, and
/// returns the shared `Arc` (so the caller can later `bind` it).
/// # C: O(1) amortised
pub fn register_device(d: Arc<Device>) -> Arc<Device> {
    DEVICES.lock().push(Arc::clone(&d));
    DEV_COUNT.fetch_add(1, Ordering::Release);
    if let Some(h) = *SYSFS_HOOK.lock() { h(&d); }
    d
}

/// Snapshot of all registered devices. # C: O(N_devices)
pub fn devices() -> Vec<Arc<Device>> { DEVICES.lock().clone() }

/// Number of registered devices. # C: O(1)
pub fn device_count() -> usize { DEV_COUNT.load(Ordering::Acquire) }

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
    fn pci_snapshot_and_driver_override() {
        let cfg = PciCfg { revision: 0x01, subsystem_vendor: 0x1AF4, subsystem_device: 0x0001,
            irq: 11, bars: [Resource::default(); 6] };
        let d = Device::new("pci", alloc::string::String::from("0000:00:0d.0"), 0x1AF4, 0x1041, 0x020000)
            .with_pci(cfg);
        let p = d.pci.as_ref().expect("snapshot present");
        assert_eq!(p.revision, 0x01);
        assert_eq!(p.subsystem_vendor, 0x1AF4);
        assert_eq!(p.irq, 11);
        // driver_override: starts None, set, then cleared by empty/(null).
        assert!(d.driver_override().is_none());
        d.set_driver_override("vfio-pci\n");
        assert_eq!(d.driver_override().as_deref(), Some("vfio-pci"));
        d.set_driver_override("(null)\n");
        assert!(d.driver_override().is_none());
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
}
