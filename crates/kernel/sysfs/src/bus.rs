// sysfs device-tree publication (drivers-plan D1a). Synthesises the
// Linux-visible `/sys/bus/*` + `/sys/devices/*` tree from the live
// `drv` device/driver registries. Everything is dynamic: dir inodes
// readdir/lookup the registry on each access, so a device that
// `drv::register_device`'d after boot still appears (no eager devfs
// key writes per device). Mirrors the `/sys/class/net` pattern.
//
// Tree (canonical real dirs under /sys/devices; the bus entries are
// Linux-style symlinks into them):
//   /sys/devices/pci0000:00/<addr>/{vendor,device,class,uevent}
//   /sys/devices/pci0000:00/<addr>/driver -> ../../../bus/pci/drivers/<name>  (bound)
//   /sys/bus/pci/devices/<addr>     -> ../../../devices/pci0000:00/<addr>
//   /sys/bus/pci/drivers/<name>/
//   /sys/devices/virtio/<addr>/{device,uevent} (+ driver symlink when bound)
//   /sys/bus/virtio/devices/<addr> -> ../../../devices/virtio/<addr>
//   /sys/bus/virtio/drivers/<name>/

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

use crate::BodyInode;

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

fn dev_attr(dev: &drv::Device, leaf: &str) -> Option<Vec<u8>> {
    match leaf {
        "vendor" => Some(alloc::format!("0x{:04x}\n", dev.vendor_id).into_bytes()),
        "device" => Some(alloc::format!("0x{:04x}\n", dev.device_id).into_bytes()),
        "class"  => Some(alloc::format!("0x{:06x}\n", dev.class).into_bytes()),
        "uevent" => {
            let mut s = String::new();
            if dev.bus == "pci" {
                s.push_str(&alloc::format!(
                    "PCI_ID={:04X}:{:04X}\nPCI_SLOT_NAME={}\n",
                    dev.vendor_id, dev.device_id, dev.addr));
            } else {
                s.push_str(&alloc::format!("MODALIAS=virtio:d{:08x}\n", dev.device_id as u32));
            }
            if let Some(drvname) = dev.bound() {
                s.push_str(&alloc::format!("DRIVER={}\n", drvname));
            }
            Some(s.into_bytes())
        }
        _ => None,
    }
}

fn dev_entries(bus: &str) -> &'static [&'static str] {
    if bus == "pci" { &["vendor", "device", "class", "uevent"] }
    else { &["device", "uevent"] }
}

/// A symlink inode whose readlink target is a fixed byte string.
struct LinkInode { target: Vec<u8> }
impl Inode for LinkInode {
    fn ino(&self) -> Ino { INO_SYMLINK }
    fn file_type(&self) -> FileType { FileType::Symlink }
    fn size(&self) -> u64 { self.target.len() as u64 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn readlink(&self) -> KResult<Vec<u8>> { Ok(self.target.clone()) }
}

/// Real per-device directory under `/sys/devices/<root>/<addr>`. Holds
/// attribute files + a `driver` symlink when bound.
struct DeviceDirInode { addr: String, bus: &'static str }
impl Inode for DeviceDirInode {
    fn ino(&self) -> Ino { INO_DEVICE_DIR }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        let dev = find_dev(self.bus, &self.addr).ok_or(VfsError::Enoent)?;
        if name == "driver" {
            let drvname = dev.bound().ok_or(VfsError::Enoent)?;
            // ../../../bus/<bus>/drivers/<name>  (from /sys/devices/<root>/<addr>)
            let t = alloc::format!("../../../bus/{}/drivers/{}", self.bus, drvname);
            return Ok(Arc::new(LinkInode { target: t.into_bytes() }) as InodeRef);
        }
        let body = dev_attr(&dev, name).ok_or(VfsError::Enoent)?;
        Ok(Arc::new(BodyInode::new(body, INO_ATTR)) as InodeRef)
    }
    fn readdir(&self, off: u64, f: &mut dyn FnMut(u64, &str, FileType) -> bool) -> KResult<u64> {
        let attrs = dev_entries(self.bus);
        let bound = find_dev(self.bus, &self.addr).map(|d| d.bound().is_some()).unwrap_or(false);
        let mut idx = off as usize;
        while idx < attrs.len() {
            let next = idx as u64 + 1;
            if !f(next, attrs[idx], FileType::Regular) { return Ok(next); }
            idx += 1;
        }
        if bound && idx == attrs.len() {
            let next = idx as u64 + 1;
            if !f(next, "driver", FileType::Symlink) { return Ok(next); }
            idx += 1;
        }
        Ok(idx as u64)
    }
}

fn find_dev(bus: &str, addr: &str) -> Option<Arc<drv::Device>> {
    drv::devices().into_iter().find(|d| d.bus == bus && d.addr == addr)
}

fn dev_root_canon(bus: &str) -> &'static str {
    if bus == "pci" { "devices/pci0000:00" } else { "devices/virtio" }
}

/// `/sys/devices/pci0000:00` or `/sys/devices/virtio` — real device dirs.
pub struct DevicesRootInode { pub bus: &'static str }
impl Inode for DevicesRootInode {
    fn ino(&self) -> Ino { if self.bus == "pci" { INO_DEV_PCI_ROOT } else { INO_DEV_VIRT_ROOT } }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        if find_dev(self.bus, name).is_some() {
            return Ok(Arc::new(DeviceDirInode { addr: String::from(name), bus: self.bus }) as InodeRef);
        }
        Err(VfsError::Enoent)
    }
    fn readdir(&self, off: u64, f: &mut dyn FnMut(u64, &str, FileType) -> bool) -> KResult<u64> {
        let devs = drv::devices();
        let list: Vec<&str> = devs.iter().filter(|d| d.bus == self.bus).map(|d| d.addr.as_str()).collect();
        let mut idx = off as usize;
        while idx < list.len() {
            let next = idx as u64 + 1;
            if !f(next, list[idx], FileType::Directory) { return Ok(next); }
            idx += 1;
        }
        Ok(idx as u64)
    }
}

/// `/sys/bus/<bus>/devices` — symlinks into the canonical /sys/devices dir.
pub struct BusDevicesInode { pub bus: &'static str }
impl Inode for BusDevicesInode {
    fn ino(&self) -> Ino { if self.bus == "pci" { INO_BUS_PCI_DEV } else { INO_BUS_VIRT_DEV } }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        if find_dev(self.bus, name).is_some() {
            // from /sys/bus/<bus>/devices/<addr> -> /sys/devices/<root>/<addr>
            let t = alloc::format!("../../../{}/{}", dev_root_canon(self.bus), name);
            return Ok(Arc::new(LinkInode { target: t.into_bytes() }) as InodeRef);
        }
        Err(VfsError::Enoent)
    }
    fn readdir(&self, off: u64, f: &mut dyn FnMut(u64, &str, FileType) -> bool) -> KResult<u64> {
        let devs = drv::devices();
        let list: Vec<&str> = devs.iter().filter(|d| d.bus == self.bus).map(|d| d.addr.as_str()).collect();
        let mut idx = off as usize;
        while idx < list.len() {
            let next = idx as u64 + 1;
            if !f(next, list[idx], FileType::Symlink) { return Ok(next); }
            idx += 1;
        }
        Ok(idx as u64)
    }
}

/// `/sys/bus/<bus>/drivers` — one dir per registered model driver.
pub struct BusDriversInode { pub bus: &'static str }
impl Inode for BusDriversInode {
    fn ino(&self) -> Ino { if self.bus == "pci" { INO_BUS_PCI_DRV } else { INO_BUS_VIRT_DRV } }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        if drv::driver_names().iter().any(|n| *n == name) {
            return Ok(Arc::new(DriverDirInode) as InodeRef);
        }
        Err(VfsError::Enoent)
    }
    fn readdir(&self, off: u64, f: &mut dyn FnMut(u64, &str, FileType) -> bool) -> KResult<u64> {
        let names = drv::driver_names();
        let mut idx = off as usize;
        while idx < names.len() {
            let next = idx as u64 + 1;
            if !f(next, names[idx], FileType::Directory) { return Ok(next); }
            idx += 1;
        }
        Ok(idx as u64)
    }
}

/// `/sys/bus/<bus>/drivers/<name>` — driver dir. Empty in D1a (bind/
/// unbind write-attrs ride D1b probe-driven binding).
struct DriverDirInode;
impl Inode for DriverDirInode {
    fn ino(&self) -> Ino { INO_DRIVER_DIR }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
    fn readdir(&self, _o: u64, _f: &mut dyn FnMut(u64, &str, FileType) -> bool) -> KResult<u64> { Ok(0) }
}

/// Register the dynamic bus/devices dir inodes in the devfs key
/// registry. Called from `sysfs::init` (procfs static-files init),
/// BEFORE pci enumeration — so devices published during enumeration
/// resolve through these dynamic inodes immediately.
/// # C: O(1)
pub fn init() {
    devfs::register("/sys/bus/pci/devices",    Arc::new(BusDevicesInode { bus: "pci" }) as InodeRef);
    devfs::register("/sys/bus/pci/drivers",    Arc::new(BusDriversInode { bus: "pci" }) as InodeRef);
    devfs::register("/sys/bus/virtio/devices", Arc::new(BusDevicesInode { bus: "virtio" }) as InodeRef);
    devfs::register("/sys/bus/virtio/drivers", Arc::new(BusDriversInode { bus: "virtio" }) as InodeRef);
    devfs::register("/sys/devices/pci0000:00", Arc::new(DevicesRootInode { bus: "pci" }) as InodeRef);
    devfs::register("/sys/devices/virtio",     Arc::new(DevicesRootInode { bus: "virtio" }) as InodeRef);
}

// --- drv-hook callbacks the kernel wires via drv::set_*_hook --------------
// The tree is dynamic (read from the drv registry on access), so these
// hooks need do no eager devfs work; they exist to satisfy the drv
// contract and to broadcast a kobject uevent so udev coldplug sees the
// device appear. Honest simplification: no per-device devfs key is
// written — the dir inodes synthesise children on demand.

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
