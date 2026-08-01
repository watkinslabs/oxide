extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{mk_mode, DirContext, FileOps, FileType, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError};

use super::device::{
    dev_canon_exact, find_dev, make_device_dir_inode, make_device_link_inode,
};
use super::driver::make_driver_dir_inode;
use crate::DIR_PERM;
use super::ids::{bus_devices_ino, bus_drivers_ino, devices_root_ino};

struct BusData { bus: &'static str }

/// Only exact live parentless devices are anchored at a bus root. Parented
/// devices are reachable exclusively through their complete ancestry.
/// # C: O(N_devices + depth)
fn is_root_device(dev: &drv::Device) -> bool {
    dev.parent().is_none() && dev_canon_exact(dev).is_some()
}

/// `/sys/devices/pci0000:00` or `/sys/devices/virtio` — real device dirs.
struct DevicesRootOps;
impl InodeOps for DevicesRootOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let bus = inode.private::<BusData>().ok_or(VfsError::Einval)?.bus;
        match find_dev(bus, name) {
            Some(dev) if is_root_device(&dev) => {
                Ok(make_device_dir_inode(dev))
            }
            _ => Err(VfsError::Enoent),
        }
    }
}
impl FileOps for DevicesRootOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let bus = match inode.private::<BusData>() { Some(d) => d.bus, None => return Err(VfsError::Einval) };
        let devs = drv::devices();
        let list: Vec<&str> = devs.iter()
            .filter(|d| d.bus == bus && is_root_device(d))
            .map(|d| d.addr.as_str()).collect();
        crate::readdir::emit_names(inode, ctx, list.into_iter(), FileType::Directory)
    }
}
pub(super) fn make_devices_root_inode(bus: &'static str) -> InodeRef {
    let ino = devices_root_ino(bus);
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
        let dev = find_dev(bus, name).ok_or(VfsError::Enoent)?;
        let canon = dev_canon_exact(&dev).ok_or(VfsError::Enoent)?;
        let t = alloc::format!("../../../{canon}");
        Ok(make_device_link_inode(dev, t.into_bytes()))
    }
}
impl FileOps for BusDevicesOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let bus = match inode.private::<BusData>() { Some(d) => d.bus, None => return Err(VfsError::Einval) };
        let devs = drv::devices();
        let list: Vec<&str> = devs.iter()
            .filter(|d| d.bus == bus && dev_canon_exact(d).is_some())
            .map(|d| d.addr.as_str())
            .collect();
        crate::readdir::emit_names(inode, ctx, list.into_iter(), FileType::Symlink)
    }
}
pub(super) fn make_bus_devices_inode(bus: &'static str) -> InodeRef {
    let ino = bus_devices_ino(bus);
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
        if let Some(driver) = drv::driver_names_for_bus(bus).into_iter().find(|n| *n == name) {
            return Ok(make_driver_dir_inode(bus, driver));
        }
        Err(VfsError::Enoent)
    }
}
impl FileOps for BusDriversOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let bus = inode.private::<BusData>().ok_or(VfsError::Einval)?.bus;
        let names = drv::driver_names_for_bus(bus);
        crate::readdir::emit_names(inode, ctx, names.into_iter(), FileType::Directory)
    }
}
pub(super) fn make_bus_drivers_inode(bus: &'static str) -> InodeRef {
    let ino = bus_drivers_ino(bus);
    InodeBuilder::new(ino, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(BusDriversOps), Arc::new(BusDriversOps))
        .private(Arc::new(BusData { bus }))
        .build()
}
