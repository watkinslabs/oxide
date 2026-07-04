extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{mk_mode, DirContext, FileOps, FileType, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError};

use super::device::{find_dev, make_device_dir_inode, make_link_inode};
use super::driver::make_driver_dir_inode;
use crate::DIR_PERM;
use super::ids::{bus_devices_ino, bus_drivers_ino, dev_root_canon, devices_root_ino};

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
pub(super) fn make_bus_drivers_inode(bus: &'static str) -> InodeRef {
    let ino = bus_drivers_ino(bus);
    InodeBuilder::new(ino, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(BusDriversOps), Arc::new(BusDriversOps))
        .private(Arc::new(BusData { bus }))
        .build()
}
