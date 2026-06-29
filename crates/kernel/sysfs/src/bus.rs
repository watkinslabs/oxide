// sysfs device-tree publication (drivers-plan D1a + DVR-0009..0013).
// Synthesises the Linux-visible `/sys/bus/*` + `/sys/devices/*` tree from
// the live `drv` device/driver registries. Everything is dynamic: dir inodes
// readdir/lookup the registry on each access, so a device that
// `drv::register_device`'d after boot still appears.
//
// Tree (canonical real dirs under /sys/devices; the bus entries are
// Linux-style symlinks into them):
//   /sys/devices/pci0000:00/<addr>/{vendor,device,class,revision,
//     subsystem_vendor,subsystem_device,irq,enable,numa_node,modalias,
//     resource,resource0..5,driver_override,uevent}
//   /sys/devices/pci0000:00/<addr>/subsystem -> ../../../bus/pci       (DVR-0012)
//   /sys/devices/pci0000:00/<addr>/driver -> ../../../bus/pci/drivers/<name> (bound)
//   /sys/bus/pci/devices/<addr>     -> ../../../devices/pci0000:00/<addr>
//   /sys/bus/pci/drivers/<name>/<addr> -> ../../../../devices/pci0000:00/<addr> (DVR-0013)

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{default_inode_ops, mk_mode, FileOps, FileType, Ino, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError};

use crate::{make_body_inode, make_symlink_inode_ino, read_window, DIR_PERM, RO_PERM, RW_PERM};

const INO_BUS_PCI_DEV:   Ino = 0x5102_0001;
const INO_BUS_PCI_DRV:   Ino = 0x5102_0002;
const INO_BUS_VIRT_DEV:  Ino = 0x5102_0003;
const INO_BUS_VIRT_DRV:  Ino = 0x5102_0004;
const INO_DEV_PCI_ROOT:  Ino = 0x5102_0005;
const INO_DEV_VIRT_ROOT: Ino = 0x5102_0006;
const INO_SYMLINK:       Ino = 0x5102_0080;
const INO_DEVICE_DIR:    Ino = 0x5102_1000;
const INO_DRIVER_DIR:    Ino = 0x5102_1100;
const INO_ATTR:          Ino = 0x5102_2000;
const INO_RESN:          Ino = 0x5102_2100;
const INO_OVERRIDE:      Ino = 0x5102_2200;
const INO_ENABLE:        Ino = 0x5102_2300;

/// Split the 24-bit packed class into (base class, subclass, prog-if).
fn class_bytes(class24: u32) -> (u8, u8, u8) {
    (((class24 >> 16) & 0xff) as u8, ((class24 >> 8) & 0xff) as u8, (class24 & 0xff) as u8)
}

/// Bodies for the simple read-only attribute files (everything except the
/// writable `enable`/`driver_override` and the symlinks). `None` = not an
/// attribute of this device. # C: O(1)
fn attr_body(dev: &drv::Device, leaf: &str) -> Option<Vec<u8>> {
    match leaf {
        "vendor" => Some(alloc::format!("0x{:04x}\n", dev.vendor_id).into_bytes()),
        "device" => Some(alloc::format!("0x{:04x}\n", dev.device_id).into_bytes()),
        "class"  => Some(alloc::format!("0x{:06x}\n", dev.class).into_bytes()),
        "uevent" => Some(uevent_body(dev)),
        _ => pci_attr(dev, leaf),
    }
}

/// `uevent` attribute body (Linux device uevent env, one var per line).
fn uevent_body(dev: &drv::Device) -> Vec<u8> {
    let mut s = String::new();
    if dev.bus == "pci" {
        let (cls, sub, pif) = class_bytes(dev.class);
        if let Some(drvname) = dev.bound() { s.push_str(&alloc::format!("DRIVER={}\n", drvname)); }
        s.push_str(&alloc::format!("PCI_CLASS={:06X}\nPCI_ID={:04X}:{:04X}\n",
            dev.class, dev.vendor_id, dev.device_id));
        if let Some(cfg) = dev.pci.as_ref() {
            s.push_str(&alloc::format!("PCI_SUBSYS_ID={:04X}:{:04X}\n",
                cfg.subsystem_vendor, cfg.subsystem_device));
            s.push_str("MODALIAS=");
            s.push_str(&pci::sysfmt::modalias(dev.vendor_id, dev.device_id,
                cfg.subsystem_vendor, cfg.subsystem_device, cls, sub, pif));
        }
        s.push_str(&alloc::format!("PCI_SLOT_NAME={}\n", dev.addr));
    } else {
        s.push_str(&alloc::format!("MODALIAS=virtio:d{:08x}\n", dev.device_id as u32));
        if let Some(drvname) = dev.bound() { s.push_str(&alloc::format!("DRIVER={}\n", drvname)); }
    }
    s.into_bytes()
}

/// PCI-config-derived attribute bodies (DVR-0009..0011). `None` for a
/// non-pci device or a non-pci attribute. # C: O(1)
fn pci_attr(dev: &drv::Device, leaf: &str) -> Option<Vec<u8>> {
    let cfg = dev.pci.as_ref()?;
    let (cls, sub, pif) = class_bytes(dev.class);
    let b = match leaf {
        "revision"         => alloc::format!("0x{:02x}\n", cfg.revision).into_bytes(),
        "subsystem_vendor" => alloc::format!("0x{:04x}\n", cfg.subsystem_vendor).into_bytes(),
        "subsystem_device" => alloc::format!("0x{:04x}\n", cfg.subsystem_device).into_bytes(),
        "irq"              => alloc::format!("{}\n", cfg.irq).into_bytes(),
        "numa_node"        => b"-1\n".to_vec(),
        "modalias"         => pci::sysfmt::modalias(
            dev.vendor_id, dev.device_id, cfg.subsystem_vendor, cfg.subsystem_device,
            cls, sub, pif).into_bytes(),
        "resource"         => resource_text(cfg).into_bytes(),
        _ => return None,
    };
    Some(b)
}

/// Render the `resource` file body from the snapshot's sized BARs via the
/// hosted-tested `pci::sysfmt::resource_text`. # C: O(1)
fn resource_text(cfg: &drv::PciCfg) -> String {
    let mut regs = [pci::sysfmt::BarRegion::default(); 6];
    for (i, r) in cfg.bars.iter().enumerate() {
        let size = if r.flags != 0 && r.end >= r.start { r.end - r.start + 1 } else { 0 };
        regs[i] = pci::sysfmt::BarRegion { start: r.start, size, flags: r.flags };
    }
    pci::sysfmt::resource_text(&regs)
}

/// Ordered (name, type) list of a device's sysfs children. Drives both
/// `lookup` and `iterate` so they never disagree. # C: O(1)
fn entries(dev: &drv::Device) -> Vec<(String, FileType)> {
    let mut v: Vec<(String, FileType)> = Vec::new();
    if let (true, Some(cfg)) = (dev.bus == "pci", dev.pci.as_ref()) {
        for n in ["vendor","device","subsystem_vendor","subsystem_device","class","revision",
                  "irq","enable","numa_node","modalias","resource","driver_override","uevent"] {
            v.push((String::from(n), FileType::Regular));
        }
        for (i, r) in cfg.bars.iter().enumerate() {
            if r.flags != 0 { v.push((alloc::format!("resource{i}"), FileType::Regular)); }
        }
    } else {
        for n in ["device", "uevent"] { v.push((String::from(n), FileType::Regular)); }
    }
    v.push((String::from("subsystem"), FileType::Symlink));
    if dev.bound().is_some() { v.push((String::from("driver"), FileType::Symlink)); }
    v
}

/// A symlink inode (under the bus tree) whose readlink target is a fixed
/// byte string. # C: O(1)
fn make_link_inode(target: Vec<u8>) -> InodeRef { make_symlink_inode_ino(target, INO_SYMLINK) }

/// Real per-device directory under `/sys/devices/<root>/<addr>`.
struct DeviceDirData { addr: String, bus: &'static str }

struct DeviceDirOps;
impl InodeOps for DeviceDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let data = inode.private::<DeviceDirData>().ok_or(VfsError::Einval)?;
        let dev = find_dev(data.bus, &data.addr).ok_or(VfsError::Enoent)?;
        match name {
            "subsystem" => {
                let t = alloc::format!("../../../bus/{}", data.bus);
                return Ok(make_link_inode(t.into_bytes()));
            }
            "driver" => {
                let drvname = dev.bound().ok_or(VfsError::Enoent)?;
                let t = alloc::format!("../../../bus/{}/drivers/{}", data.bus, drvname);
                return Ok(make_link_inode(t.into_bytes()));
            }
            "driver_override" => return Ok(make_override_inode(data.bus, data.addr.clone())),
            "enable" => return Ok(make_enable_inode()),
            _ => {}
        }
        if let Some(idx) = name.strip_prefix("resource").and_then(|s| s.parse::<usize>().ok()) {
            let cfg = dev.pci.as_ref().ok_or(VfsError::Enoent)?;
            let r = cfg.bars.get(idx).filter(|r| r.flags != 0).ok_or(VfsError::Enoent)?;
            let size = if r.end >= r.start { r.end - r.start + 1 } else { 0 };
            return Ok(make_resn_inode(size));
        }
        let body = attr_body(&dev, name).ok_or(VfsError::Enoent)?;
        Ok(make_body_inode(body, INO_ATTR))
    }
}
impl FileOps for DeviceDirOps {
    fn iterate(&self, inode: &Inode, off: u64, f: &mut dyn FnMut(u64, u64, &str, FileType) -> bool) -> KResult<u64> {
        let data = inode.private::<DeviceDirData>().ok_or(VfsError::Einval)?;
        let dev = match find_dev(data.bus, &data.addr) { Some(d) => d, None => return Ok(off) };
        let list = entries(&dev);
        let mut idx = off as usize;
        while idx < list.len() {
            let (n, ft) = &list[idx];
            let next = idx as u64 + 1;
            let ino = inode.lookup(n).map(|i| i.ino()).unwrap_or(0);
            if !f(ino, next, n, *ft) { return Ok(next); }
            idx += 1;
        }
        Ok(idx as u64)
    }
}
fn make_device_dir_inode(addr: String, bus: &'static str) -> InodeRef {
    InodeBuilder::new(INO_DEVICE_DIR, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(DeviceDirOps), Arc::new(DeviceDirOps))
        .private(Arc::new(DeviceDirData { addr, bus }))
        .build()
}

// ---- writable / sized attribute inodes -----------------------------------

/// `enable` (DVR-0011): reads "1\n" (devices are enabled at boot), accepts
/// writes as a no-op (Linux toggles the enable refcount). # C: O(1)
struct EnableOps;
impl FileOps for EnableOps {
    fn read(&self, _i: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> { Ok(read_window(b"1\n", off, buf)) }
    fn write(&self, _i: &Inode, _o: u64, b: &[u8]) -> KResult<usize> { Ok(b.len()) }
}
fn make_enable_inode() -> InodeRef {
    InodeBuilder::new(INO_ENABLE, mk_mode(FileType::Regular, RW_PERM), default_inode_ops(), Arc::new(EnableOps)).build()
}

/// `driver_override` (DVR-0011): admin writes a driver name to force a match;
/// read returns the override (or "\n" when unset). Backed by the live Device.
struct OverrideData { bus: &'static str, addr: String }
struct OverrideOps;
impl FileOps for OverrideOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<OverrideData>().ok_or(VfsError::Einval)?;
        let body = match find_dev(d.bus, &d.addr).and_then(|dev| dev.driver_override()) {
            Some(s) => alloc::format!("{}\n", s).into_bytes(),
            None => b"\n".to_vec(),
        };
        Ok(read_window(&body, off, buf))
    }
    fn write(&self, inode: &Inode, _o: u64, b: &[u8]) -> KResult<usize> {
        let d = inode.private::<OverrideData>().ok_or(VfsError::Einval)?;
        if let Some(dev) = find_dev(d.bus, &d.addr) {
            dev.set_driver_override(core::str::from_utf8(b).unwrap_or(""));
        }
        Ok(b.len())
    }
}
fn make_override_inode(bus: &'static str, addr: String) -> InodeRef {
    InodeBuilder::new(INO_OVERRIDE, mk_mode(FileType::Regular, RW_PERM), default_inode_ops(), Arc::new(OverrideOps))
        .private(Arc::new(OverrideData { bus, addr })).build()
}

/// `resourceN` (DVR-0009): the raw BAR region. Exposed with the BAR's byte
/// size as `st_size` (so mmap/udev see the right extent); content is the
/// MMIO window which sysfs does not back here, so reads return EOF.
struct ResnOps;
impl FileOps for ResnOps {
    fn read(&self, _i: &Inode, _o: u64, _b: &mut [u8]) -> KResult<usize> { Ok(0) }
}
fn make_resn_inode(size: u64) -> InodeRef {
    InodeBuilder::new(INO_RESN, mk_mode(FileType::Regular, RO_PERM), default_inode_ops(), Arc::new(ResnOps))
        .size(size).build()
}

fn find_dev(bus: &str, addr: &str) -> Option<Arc<drv::Device>> {
    drv::devices().into_iter().find(|d| d.bus == bus && d.addr == addr)
}

fn dev_root_canon(bus: &str) -> &'static str {
    if bus == "pci" { "devices/pci0000:00" } else { "devices/virtio" }
}

/// Per-inode bus tag for the bus/devices-root dir inodes. # C: n/a
struct BusData { bus: &'static str }

/// `/sys/devices/pci0000:00` or `/sys/devices/virtio` — real device dirs.
struct DevicesRootOps;
impl InodeOps for DevicesRootOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let bus = inode.private::<BusData>().ok_or(VfsError::Einval)?.bus;
        if find_dev(bus, name).is_some() {
            return Ok(make_device_dir_inode(String::from(name), bus));
        }
        Err(VfsError::Enoent)
    }
}
impl FileOps for DevicesRootOps {
    fn iterate(&self, inode: &Inode, off: u64, f: &mut dyn FnMut(u64, u64, &str, FileType) -> bool) -> KResult<u64> {
        let bus = match inode.private::<BusData>() { Some(d) => d.bus, None => return Err(VfsError::Einval) };
        let devs = drv::devices();
        let list: Vec<&str> = devs.iter().filter(|d| d.bus == bus).map(|d| d.addr.as_str()).collect();
        let mut idx = off as usize;
        while idx < list.len() {
            let next = idx as u64 + 1;
            let ino = inode.lookup(list[idx]).map(|i| i.ino()).unwrap_or(0);
            if !f(ino, next, list[idx], FileType::Directory) { return Ok(next); }
            idx += 1;
        }
        Ok(idx as u64)
    }
}
fn make_devices_root_inode(bus: &'static str) -> InodeRef {
    let ino = if bus == "pci" { INO_DEV_PCI_ROOT } else { INO_DEV_VIRT_ROOT };
    InodeBuilder::new(ino, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(DevicesRootOps), Arc::new(DevicesRootOps))
        .private(Arc::new(BusData { bus }))
        .build()
}

/// `/sys/bus/<bus>/devices` — symlinks into the canonical /sys/devices dir.
struct BusDevicesOps;
impl InodeOps for BusDevicesOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let bus = inode.private::<BusData>().ok_or(VfsError::Einval)?.bus;
        if find_dev(bus, name).is_some() {
            let t = alloc::format!("../../../{}/{}", dev_root_canon(bus), name);
            return Ok(make_link_inode(t.into_bytes()));
        }
        Err(VfsError::Enoent)
    }
}
impl FileOps for BusDevicesOps {
    fn iterate(&self, inode: &Inode, off: u64, f: &mut dyn FnMut(u64, u64, &str, FileType) -> bool) -> KResult<u64> {
        let bus = match inode.private::<BusData>() { Some(d) => d.bus, None => return Err(VfsError::Einval) };
        let devs = drv::devices();
        let list: Vec<&str> = devs.iter().filter(|d| d.bus == bus).map(|d| d.addr.as_str()).collect();
        let mut idx = off as usize;
        while idx < list.len() {
            let next = idx as u64 + 1;
            let ino = inode.lookup(list[idx]).map(|i| i.ino()).unwrap_or(0);
            if !f(ino, next, list[idx], FileType::Symlink) { return Ok(next); }
            idx += 1;
        }
        Ok(idx as u64)
    }
}
fn make_bus_devices_inode(bus: &'static str) -> InodeRef {
    let ino = if bus == "pci" { INO_BUS_PCI_DEV } else { INO_BUS_VIRT_DEV };
    InodeBuilder::new(ino, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(BusDevicesOps), Arc::new(BusDevicesOps))
        .private(Arc::new(BusData { bus }))
        .build()
}

/// `/sys/bus/<bus>/drivers` — one dir per registered model driver.
struct BusDriversOps;
impl InodeOps for BusDriversOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let bus = inode.private::<BusData>().ok_or(VfsError::Einval)?.bus;
        if drv::driver_names().iter().any(|n| *n == name) {
            return Ok(make_driver_dir_inode(bus, String::from(name)));
        }
        Err(VfsError::Enoent)
    }
}
impl FileOps for BusDriversOps {
    fn iterate(&self, inode: &Inode, off: u64, f: &mut dyn FnMut(u64, u64, &str, FileType) -> bool) -> KResult<u64> {
        let names = drv::driver_names();
        let mut idx = off as usize;
        while idx < names.len() {
            let next = idx as u64 + 1;
            let ino = inode.lookup(names[idx]).map(|i| i.ino()).unwrap_or(0);
            if !f(ino, next, names[idx], FileType::Directory) { return Ok(next); }
            idx += 1;
        }
        Ok(idx as u64)
    }
}
fn make_bus_drivers_inode(bus: &'static str) -> InodeRef {
    let ino = if bus == "pci" { INO_BUS_PCI_DRV } else { INO_BUS_VIRT_DRV };
    InodeBuilder::new(ino, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(BusDriversOps), Arc::new(BusDriversOps))
        .private(Arc::new(BusData { bus }))
        .build()
}

/// `/sys/bus/<bus>/drivers/<name>` — driver dir holding a back-ref symlink to
/// every device bound to this driver (DVR-0013). `lookup(<addr>)` resolves the
/// symlink `<addr> -> ../../../../devices/<root>/<addr>`.
struct DriverDirData { bus: &'static str, name: String }
struct DriverDirOps;
impl DriverDirOps {
    /// Devices currently bound to `data.name` on `data.bus`. # C: O(N_devices)
    fn bound_addrs(data: &DriverDirData) -> Vec<String> {
        drv::devices().into_iter()
            .filter(|d| d.bus == data.bus && d.bound() == Some(data.name_static()))
            .map(|d| d.addr.clone()).collect()
    }
}
impl DriverDirData {
    /// The driver name as the `&'static str` the registry stores (so the
    /// `bound() == Some(name)` compare matches by value). # C: O(N_drivers)
    fn name_static(&self) -> &'static str {
        drv::driver_names().into_iter().find(|n| *n == self.name).unwrap_or("")
    }
}
impl InodeOps for DriverDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let data = inode.private::<DriverDirData>().ok_or(VfsError::Einval)?;
        if DriverDirOps::bound_addrs(data).iter().any(|a| a == name) {
            let t = alloc::format!("../../../../{}/{}", dev_root_canon(data.bus), name);
            return Ok(make_link_inode(t.into_bytes()));
        }
        Err(VfsError::Enoent)
    }
}
impl FileOps for DriverDirOps {
    fn iterate(&self, inode: &Inode, off: u64, f: &mut dyn FnMut(u64, u64, &str, FileType) -> bool) -> KResult<u64> {
        let data = inode.private::<DriverDirData>().ok_or(VfsError::Einval)?;
        let list = DriverDirOps::bound_addrs(data);
        let mut idx = off as usize;
        while idx < list.len() {
            let next = idx as u64 + 1;
            let ino = inode.lookup(&list[idx]).map(|i| i.ino()).unwrap_or(0);
            if !f(ino, next, &list[idx], FileType::Symlink) { return Ok(next); }
            idx += 1;
        }
        Ok(idx as u64)
    }
}
fn make_driver_dir_inode(bus: &'static str, name: String) -> InodeRef {
    InodeBuilder::new(INO_DRIVER_DIR, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(DriverDirOps), Arc::new(DriverDirOps))
        .private(Arc::new(DriverDirData { bus, name })).build()
}

/// Register the dynamic bus/devices dir inodes in sysfs's own tree.
/// Called from `sysfs::init` BEFORE pci enumeration. # C: O(1)
pub fn init() {
    crate::register("/sys/bus/pci/devices",    make_bus_devices_inode("pci"));
    crate::register("/sys/bus/pci/drivers",    make_bus_drivers_inode("pci"));
    crate::register("/sys/bus/virtio/devices", make_bus_devices_inode("virtio"));
    crate::register("/sys/bus/virtio/drivers", make_bus_drivers_inode("virtio"));
    crate::register("/sys/devices/pci0000:00", make_devices_root_inode("pci"));
    crate::register("/sys/devices/virtio",     make_devices_root_inode("virtio"));
    crate::devnum::init();
}

// --- drv-hook callbacks the kernel wires via drv::set_*_hook --------------

/// drv `set_sysfs_hook` target: a device was registered. # C: O(1)
pub fn publish_device_cb(dev: &drv::Device) {
    let devpath = alloc::format!("/{}/{}", dev_root_canon(dev.bus), dev.addr);
    ::netlink::emit_uevent("add", &devpath, dev.bus);
}

/// drv `set_driver_hook` target: a driver was registered. # C: O(1)
pub fn publish_driver_cb(_bus: &str, _name: &'static str) {}

/// drv `set_bind_hook` target: a device was bound. # C: O(1)
pub fn bind_device_cb(bus: &str, addr: &str, _driver: &'static str) {
    let devpath = alloc::format!("/{}/{}", dev_root_canon(bus), addr);
    ::netlink::emit_uevent("change", &devpath, bus);
}
