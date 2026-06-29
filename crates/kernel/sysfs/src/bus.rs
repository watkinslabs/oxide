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

use vfs::{mk_mode, DirContext, FileOps, FileType, Ino, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError};

use crate::{make_body_inode, make_symlink_inode_ino, DIR_PERM};

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

/// A symlink inode (under the bus tree) whose readlink target is a fixed
/// byte string. # C: O(1)
fn make_link_inode(target: Vec<u8>) -> InodeRef {
    make_symlink_inode_ino(target, INO_SYMLINK)
}

/// Real per-device directory under `/sys/devices/<root>/<addr>`. Holds
/// attribute files + a `driver` symlink when bound.
struct DeviceDirData { addr: String, bus: &'static str }

struct DeviceDirOps;
impl InodeOps for DeviceDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let data = inode.private::<DeviceDirData>().ok_or(VfsError::Einval)?;
        let dev = find_dev(data.bus, &data.addr).ok_or(VfsError::Enoent)?;
        if name == "driver" {
            let drvname = dev.bound().ok_or(VfsError::Enoent)?;
            // ../../../bus/<bus>/drivers/<name>  (from /sys/devices/<root>/<addr>)
            let t = alloc::format!("../../../bus/{}/drivers/{}", data.bus, drvname);
            return Ok(make_link_inode(t.into_bytes()));
        }
        let body = dev_attr(&dev, name).ok_or(VfsError::Enoent)?;
        Ok(make_body_inode(body, INO_ATTR))
    }
}
impl FileOps for DeviceDirOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let data = match inode.private::<DeviceDirData>() { Some(d) => d, None => return Err(VfsError::Einval) };
        let attrs = dev_entries(data.bus);
        let bound = find_dev(data.bus, &data.addr).map(|d| d.bound().is_some()).unwrap_or(false);
        let mut idx = ctx.pos as usize;
        while idx < attrs.len() {
            let next = idx as u64 + 1;
            let ino = inode.lookup(attrs[idx]).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(attrs[idx], ino, FileType::Regular, next) { return Ok(()); }
            idx += 1;
        }
        if bound && idx == attrs.len() {
            let next = idx as u64 + 1;
            let ino = inode.lookup("driver").map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit("driver", ino, FileType::Symlink, next) { return Ok(()); }
            idx += 1;
        }
        Ok(())
    }
}
fn make_device_dir_inode(addr: String, bus: &'static str) -> InodeRef {
    InodeBuilder::new(INO_DEVICE_DIR, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(DeviceDirOps), Arc::new(DeviceDirOps))
        .private(Arc::new(DeviceDirData { addr, bus }))
        .build()
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
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let bus = match inode.private::<BusData>() { Some(d) => d.bus, None => return Err(VfsError::Einval) };
        let devs = drv::devices();
        let list: Vec<&str> = devs.iter().filter(|d| d.bus == bus).map(|d| d.addr.as_str()).collect();
        let mut idx = ctx.pos as usize;
        while idx < list.len() {
            let next = idx as u64 + 1;
            let ino = inode.lookup(list[idx]).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(list[idx], ino, FileType::Directory, next) { return Ok(()); }
            idx += 1;
        }
        Ok(())
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
            // from /sys/bus/<bus>/devices/<addr> -> /sys/devices/<root>/<addr>
            let t = alloc::format!("../../../{}/{}", dev_root_canon(bus), name);
            return Ok(make_link_inode(t.into_bytes()));
        }
        Err(VfsError::Enoent)
    }
}
impl FileOps for BusDevicesOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let bus = match inode.private::<BusData>() { Some(d) => d.bus, None => return Err(VfsError::Einval) };
        let devs = drv::devices();
        let list: Vec<&str> = devs.iter().filter(|d| d.bus == bus).map(|d| d.addr.as_str()).collect();
        let mut idx = ctx.pos as usize;
        while idx < list.len() {
            let next = idx as u64 + 1;
            let ino = inode.lookup(list[idx]).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(list[idx], ino, FileType::Symlink, next) { return Ok(()); }
            idx += 1;
        }
        Ok(())
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
    fn lookup(&self, _inode: &Inode, name: &str) -> KResult<InodeRef> {
        if drv::driver_names().iter().any(|n| *n == name) {
            return Ok(make_driver_dir_inode());
        }
        Err(VfsError::Enoent)
    }
}
impl FileOps for BusDriversOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let names = drv::driver_names();
        let mut idx = ctx.pos as usize;
        while idx < names.len() {
            let next = idx as u64 + 1;
            let ino = inode.lookup(names[idx]).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(names[idx], ino, FileType::Directory, next) { return Ok(()); }
            idx += 1;
        }
        Ok(())
    }
}
fn make_bus_drivers_inode(bus: &'static str) -> InodeRef {
    let ino = if bus == "pci" { INO_BUS_PCI_DRV } else { INO_BUS_VIRT_DRV };
    InodeBuilder::new(ino, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(BusDriversOps), Arc::new(BusDriversOps))
        .private(Arc::new(BusData { bus }))
        .build()
}

/// `/sys/bus/<bus>/drivers/<name>` — driver dir. Empty in D1a (bind/
/// unbind write-attrs ride D1b probe-driven binding).
struct DriverDirOps;
impl InodeOps for DriverDirOps {
    fn lookup(&self, _inode: &Inode, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enoent) }
}
impl FileOps for DriverDirOps {
    fn iterate(&self, _inode: &Inode, _ctx: &mut DirContext) -> KResult<()> { Ok(()) }
}
fn make_driver_dir_inode() -> InodeRef {
    InodeBuilder::new(INO_DRIVER_DIR, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(DriverDirOps), Arc::new(DriverDirOps)).build()
}

/// Register the dynamic bus/devices dir inodes in sysfs's own tree.
/// Called from `sysfs::init` (procfs static-files init),
/// BEFORE pci enumeration — so devices published during enumeration
/// resolve through these dynamic inodes immediately.
/// # C: O(1)
pub fn init() {
    crate::register("/sys/bus/pci/devices",    make_bus_devices_inode("pci"));
    crate::register("/sys/bus/pci/drivers",    make_bus_drivers_inode("pci"));
    crate::register("/sys/bus/virtio/devices", make_bus_devices_inode("virtio"));
    crate::register("/sys/bus/virtio/drivers", make_bus_drivers_inode("virtio"));
    crate::register("/sys/devices/pci0000:00", make_devices_root_inode("pci"));
    crate::register("/sys/devices/virtio",     make_devices_root_inode("virtio"));
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
