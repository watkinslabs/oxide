extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{mk_mode, DirContext, FileOps, FileType, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError};

use super::device::make_link_inode;
use crate::{DIR_PERM, RW_PERM};
use super::ids::{dev_root_canon, INO_DRIVER_ATTR, INO_DRIVER_DIR};

struct DriverDirData { bus: &'static str, driver: &'static str }

/// `/sys/bus/<bus>/drivers/<name>` — driver dir with Linux bind/unbind attrs
/// and symlinks to devices currently bound to this driver.
struct DriverDirOps;
impl InodeOps for DriverDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let data = inode.private::<DriverDirData>().ok_or(VfsError::Einval)?;
        match name {
            "bind" => return Ok(make_driver_attr_inode(data.bus, data.driver, DriverAttr::Bind)),
            "unbind" => return Ok(make_driver_attr_inode(data.bus, data.driver, DriverAttr::Unbind)),
            _ => {}
        }
        let is_bound = drv::devices().into_iter().any(|d| {
            d.bus == data.bus && d.addr == name && d.bound() == Some(data.driver)
        });
        if !is_bound { return Err(VfsError::Enoent); }
        // from /sys/bus/<bus>/drivers/<driver>/<addr>
        // to /sys/devices/<root>/<addr>
        let t = alloc::format!("../../../../{}/{}", dev_root_canon(data.bus), name);
        Ok(make_link_inode(t.into_bytes()))
    }
}
impl FileOps for DriverDirOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let data = inode.private::<DriverDirData>().ok_or(VfsError::Einval)?;
        let devs = drv::devices();
        let bound: Vec<&str> = devs.iter()
            .filter(|d| d.bus == data.bus && d.bound() == Some(data.driver))
            .map(|d| d.addr.as_str())
            .collect();
        let mut idx = ctx.pos as usize;
        const ATTRS: &[&str] = &["bind", "unbind"];
        while idx < ATTRS.len() {
            let next = idx as u64 + 1;
            let ino = inode.lookup(ATTRS[idx]).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(ATTRS[idx], ino, FileType::Regular, next) { return Ok(()); }
            idx += 1;
        }
        while idx - ATTRS.len() < bound.len() {
            let next = idx as u64 + 1;
            let name = bound[idx - ATTRS.len()];
            let ino = inode.lookup(name).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(name, ino, FileType::Symlink, next) { return Ok(()); }
            idx += 1;
        }
        Ok(())
    }
}
pub(super) fn make_driver_dir_inode(bus: &'static str, driver: &'static str) -> InodeRef {
    InodeBuilder::new(INO_DRIVER_DIR, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(DriverDirOps), Arc::new(DriverDirOps))
        .private(Arc::new(DriverDirData { bus, driver }))
        .build()
}

#[derive(Copy, Clone)]
enum DriverAttr { Bind, Unbind }

struct DriverAttrData { bus: &'static str, driver: &'static str, attr: DriverAttr }

fn drv_error_to_vfs(e: drv::Error) -> VfsError {
    match e {
        drv::Error::AlreadyBound => VfsError::Ebusy,
        drv::Error::Busy => VfsError::Ebusy,
        drv::Error::NoMatch => VfsError::Enodev,
        drv::Error::NoMem => VfsError::Enomem,
        drv::Error::ProbeFailed => VfsError::Eio,
        drv::Error::Removed => VfsError::Enodev,
        drv::Error::NotFound => VfsError::Enoent,
    }
}

fn sysfs_write_token(buf: &[u8]) -> KResult<&str> {
    let s = core::str::from_utf8(buf).map_err(|_| VfsError::Einval)?;
    s.split_ascii_whitespace().next().ok_or(VfsError::Einval)
}

struct DriverAttrOps;
impl FileOps for DriverAttrOps {
    fn read(&self, _inode: &Inode, _off: u64, _buf: &mut [u8]) -> KResult<usize> { Ok(0) }
    fn write(&self, inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        let data = inode.private::<DriverAttrData>().ok_or(VfsError::Einval)?;
        let addr = sysfs_write_token(buf)?;
        match data.attr {
            DriverAttr::Bind => {
                drv::bind_addr(data.bus, addr, data.driver).map_err(drv_error_to_vfs)?;
            }
            DriverAttr::Unbind => {
                let dev = drv::devices().into_iter()
                    .find(|d| d.bus == data.bus && d.addr == addr && d.bound() == Some(data.driver))
                    .ok_or(VfsError::Enodev)?;
                drv::unbind(&dev).map_err(drv_error_to_vfs)?;
            }
        }
        Ok(buf.len())
    }
}

fn make_driver_attr_inode(bus: &'static str, driver: &'static str, attr: DriverAttr) -> InodeRef {
    let off = match attr { DriverAttr::Bind => 0, DriverAttr::Unbind => 1 };
    InodeBuilder::new(INO_DRIVER_ATTR + off, mk_mode(FileType::Regular, RW_PERM),
        vfs::default_inode_ops(), Arc::new(DriverAttrOps))
        .private(Arc::new(DriverAttrData { bus, driver, attr }))
        .build()
}
