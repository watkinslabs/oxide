use alloc::string::String;
use alloc::sync::Arc;

use vfs::{
    default_inode_ops, mk_mode, DirContext, FileOps, FileType, Ino, Inode, InodeBuilder, InodeOps,
    InodeRef, KResult, VfsError,
};

use crate::{make_body_inode, make_symlink_inode, read_window, uevent_action, DIR_PERM, RW_PERM};

#[cfg(target_arch = "aarch64")]
const SERIAL_TTY_MAJOR: u32 = 204;
#[cfg(not(target_arch = "aarch64"))]
const SERIAL_TTY_MAJOR: u32 = 4;

const TTY_DEVICES: &[(&str, u32, u32)] = &[
    ("console", 5, 1),
    ("tty",     5, 0),
    ("tty0",    4, 0),
    ("ttyS0",   SERIAL_TTY_MAJOR, 64),
];

fn tty_dev(name: &str) -> Option<(u32, u32)> {
    TTY_DEVICES.iter()
        .find(|(n, _, _)| *n == name)
        .map(|(_, maj, min)| (*maj, *min))
}

fn emit_tty_uevent(action: &str, name: &str, major: u32, minor: u32) {
    let devpath = alloc::format!("/devices/virtual/tty/{}", name);
    let devname = alloc::format!("DEVNAME={}", name);
    let maj = alloc::format!("MAJOR={}", major);
    let min = alloc::format!("MINOR={}", minor);
    ::netlink::emit_uevent_with_env(action, &devpath, "tty", &[&devname, &maj, &min]);
}

struct SysClassTtyOps;
impl InodeOps for SysClassTtyOps {
    fn lookup(&self, _inode: &Inode, name: &str) -> KResult<InodeRef> {
        if tty_dev(name).is_none() { return Err(VfsError::Enoent); }
        let mut target = String::from("../../devices/virtual/tty/");
        target.push_str(name);
        Ok(make_symlink_inode(target.into_bytes()))
    }
}
impl FileOps for SysClassTtyOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let mut idx = ctx.pos as usize;
        while idx < TTY_DEVICES.len() {
            let next = idx as u64 + 1;
            let name = TTY_DEVICES[idx].0;
            let ino = inode.lookup(name).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(name, ino, FileType::Symlink, next) { return Ok(()); }
            idx += 1;
        }
        Ok(())
    }
}

pub(crate) fn make_sys_class_tty_inode() -> InodeRef {
    InodeBuilder::new(0x5101_0001, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(SysClassTtyOps), Arc::new(SysClassTtyOps)).build()
}

struct SysDevicesVirtualTtyOps;
impl InodeOps for SysDevicesVirtualTtyOps {
    fn lookup(&self, _inode: &Inode, name: &str) -> KResult<InodeRef> {
        let (major, minor) = tty_dev(name).ok_or(VfsError::Enoent)?;
        Ok(make_tty_device_inode(String::from(name), major, minor))
    }
}
impl FileOps for SysDevicesVirtualTtyOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let mut idx = ctx.pos as usize;
        while idx < TTY_DEVICES.len() {
            let next = idx as u64 + 1;
            let name = TTY_DEVICES[idx].0;
            let ino = inode.lookup(name).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(name, ino, FileType::Directory, next) { return Ok(()); }
            idx += 1;
        }
        Ok(())
    }
}

pub(crate) fn make_sys_devices_virtual_tty_inode() -> InodeRef {
    InodeBuilder::new(0x5101_0002, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(SysDevicesVirtualTtyOps), Arc::new(SysDevicesVirtualTtyOps)).build()
}

struct TtyDeviceData { name: String, major: u32, minor: u32 }

struct TtyDeviceOps;
impl InodeOps for TtyDeviceOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<TtyDeviceData>().ok_or(VfsError::Einval)?;
        match name {
            "dev" => {
                let body = alloc::format!("{}:{}\n", d.major, d.minor).into_bytes();
                Ok(make_body_inode(body, 0x5101_2000 + d.minor as Ino))
            }
            "uevent" => Ok(make_tty_uevent_inode(d.name.clone(), d.major, d.minor)),
            _ => Err(VfsError::Enoent),
        }
    }
}
impl FileOps for TtyDeviceOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        const ENTRIES: &[&str] = &["dev", "uevent"];
        let mut idx = ctx.pos as usize;
        while idx < ENTRIES.len() {
            let next = idx as u64 + 1;
            let ino = inode.lookup(ENTRIES[idx]).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(ENTRIES[idx], ino, FileType::Regular, next) { return Ok(()); }
            idx += 1;
        }
        Ok(())
    }
}

fn make_tty_device_inode(name: String, major: u32, minor: u32) -> InodeRef {
    InodeBuilder::new(0x5101_1000 + minor as Ino, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(TtyDeviceOps), Arc::new(TtyDeviceOps))
        .private(Arc::new(TtyDeviceData { name, major, minor }))
        .build()
}

struct TtyUeventData { name: String, major: u32, minor: u32 }

struct TtyUeventFileOps;
impl FileOps for TtyUeventFileOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<TtyUeventData>().ok_or(VfsError::Einval)?;
        let body = alloc::format!(
            "MAJOR={}\nMINOR={}\nDEVNAME={}\n", d.major, d.minor, d.name).into_bytes();
        Ok(read_window(&body, off, buf))
    }
    fn write(&self, inode: &Inode, _o: u64, b: &[u8]) -> KResult<usize> {
        let d = inode.private::<TtyUeventData>().ok_or(VfsError::Einval)?;
        emit_tty_uevent(uevent_action(b), &d.name, d.major, d.minor);
        Ok(b.len())
    }
}

fn make_tty_uevent_inode(name: String, major: u32, minor: u32) -> InodeRef {
    InodeBuilder::new(0x5101_3000 + minor as Ino, mk_mode(FileType::Regular, RW_PERM),
        default_inode_ops(), Arc::new(TtyUeventFileOps))
        .private(Arc::new(TtyUeventData { name, major, minor }))
        .build()
}
