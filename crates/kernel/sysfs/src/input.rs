// `/sys/class/input` + `/sys/devices/virtual/input` device model for the
// virtio-input evdev devices (`/dev/input/event<n>`). Mirrors block.rs (60§6.3a):
// without a resolvable /sys tree the input uevent named a nonexistent path
// (`dev_root_canon("input")` fell through to devices/platform), so udevd could
// not process input devices and libinput/logind could not enumerate them for a
// seat. Sourced live from the `drv` model (devices whose bus == "input").

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{mk_mode, DirContext, FileOps, FileType, Ino, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError};

use crate::DIR_PERM;

const INO_VIRT_INPUT:  Ino = 0x5105_0001;
const INO_CLASS_INPUT: Ino = 0x5105_0002;
const INO_INPUT_DIR:   Ino = 0x5105_1000;
const INO_INPUT_ATTR:  Ino = 0x5105_2000;
const INO_INPUT_LINK:  Ino = 0x5105_3000;

/// `(addr, (major,minor), devname)` for each registered evdev device.
/// # C: O(N_devices)
fn input_devs() -> Vec<(String, (u32, u32), String)> {
    drv::devices().into_iter()
        .filter(|d| d.bus == "input")
        .filter_map(|d| {
            let dt = d.dev_t?;
            let dn = d.devname.clone().unwrap_or_else(|| alloc::format!("input/{}", d.addr));
            Some((d.addr.clone(), dt, dn))
        })
        .collect()
}

fn input_by_addr(addr: &str) -> Option<((u32, u32), String)> {
    input_devs().into_iter().find(|(a, _, _)| a == addr).map(|(_, dt, dn)| (dt, dn))
}

// ---- /sys/devices/virtual/input/<addr> (per-device dir) -------------------
struct InputDevDirData { addr: String }
struct InputDevDirOps;
impl InodeOps for InputDevDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<InputDevDirData>().ok_or(VfsError::Einval)?;
        let ((maj, min), devname) = input_by_addr(&d.addr).ok_or(VfsError::Enoent)?;
        match name {
            "uevent" => Ok(crate::make_body_inode(
                alloc::format!("MAJOR={}\nMINOR={}\nDEVNAME={}\n", maj, min, devname).into_bytes(),
                INO_INPUT_ATTR)),
            "dev" => Ok(crate::make_body_inode(
                alloc::format!("{}:{}\n", maj, min).into_bytes(), INO_INPUT_ATTR)),
            // sd-device reads SUBSYSTEM from the basename of this symlink.
            "subsystem" => Ok(crate::make_symlink_inode(b"../../../../class/input".to_vec())),
            _ => Err(VfsError::Enoent),
        }
    }
}
impl FileOps for InputDevDirOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        const ENTRIES: &[(&str, FileType)] = &[
            ("uevent", FileType::Regular), ("dev", FileType::Regular),
            ("subsystem", FileType::Symlink),
        ];
        let mut idx = ctx.pos as usize;
        while idx < ENTRIES.len() {
            let (name, ft) = ENTRIES[idx];
            let next = idx as u64 + 1;
            let ino = inode.lookup(name).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(name, ino, ft, next) { return Ok(()); }
            idx += 1;
        }
        Ok(())
    }
}
fn make_input_dev_dir(addr: String) -> InodeRef {
    InodeBuilder::new(INO_INPUT_DIR, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(InputDevDirOps), Arc::new(InputDevDirOps))
        .private(Arc::new(InputDevDirData { addr }))
        .build()
}

// ---- /sys/devices/virtual/input (dir of per-device dirs) ------------------
struct VirtInputOps;
impl InodeOps for VirtInputOps {
    fn lookup(&self, _inode: &Inode, name: &str) -> KResult<InodeRef> {
        if input_by_addr(name).is_some() { Ok(make_input_dev_dir(String::from(name))) }
        else { Err(VfsError::Enoent) }
    }
}
impl FileOps for VirtInputOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let devs = input_devs();
        let mut idx = ctx.pos as usize;
        while idx < devs.len() {
            let next = idx as u64 + 1;
            let ino = inode.lookup(&devs[idx].0).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(&devs[idx].0, ino, FileType::Directory, next) { return Ok(()); }
            idx += 1;
        }
        Ok(())
    }
}

// ---- /sys/class/input (dir of symlinks) -----------------------------------
struct ClassInputOps;
impl InodeOps for ClassInputOps {
    fn lookup(&self, _inode: &Inode, name: &str) -> KResult<InodeRef> {
        if input_by_addr(name).is_none() { return Err(VfsError::Enoent); }
        let mut target = String::from("../../devices/virtual/input/");
        target.push_str(name);
        Ok(crate::make_symlink_inode_ino(target.into_bytes(), INO_INPUT_LINK))
    }
}
impl FileOps for ClassInputOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let devs = input_devs();
        let mut idx = ctx.pos as usize;
        while idx < devs.len() {
            let next = idx as u64 + 1;
            let ino = inode.lookup(&devs[idx].0).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(&devs[idx].0, ino, FileType::Symlink, next) { return Ok(()); }
            idx += 1;
        }
        Ok(())
    }
}

/// Register the input class + virtual device trees. # C: O(1)
pub fn init() {
    crate::register("/sys/devices/virtual/input",
        InodeBuilder::new(INO_VIRT_INPUT, mk_mode(FileType::Directory, DIR_PERM),
            Arc::new(VirtInputOps), Arc::new(VirtInputOps)).build());
    crate::register("/sys/class/input",
        InodeBuilder::new(INO_CLASS_INPUT, mk_mode(FileType::Directory, DIR_PERM),
            Arc::new(ClassInputOps), Arc::new(ClassInputOps)).build());
}
