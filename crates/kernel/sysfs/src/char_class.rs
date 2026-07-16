// Model-backed virtual character classes for Linux character devices.
//
// These devices are published through drv::try_device_add, so sysfs must expose the
// matching class-device topology:
//   /sys/class/<class>/<name> -> ../../devices/virtual/<class>/<name>
//   /sys/devices/virtual/<class>/<name>/{dev,uevent,subsystem,device}
//
// Keeping this sourced from drv::devices() makes add/remove/readd behavior
// follow the driver model instead of a separate static sysfs table.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{
    mk_mode, DirContext, FileOps, FileType, Ino, Inode, InodeBuilder, InodeOps, InodeRef, KResult,
    VfsError,
};

use crate::{DIR_PERM, RW_PERM};

const INO_VIRT_MEM: Ino = crate::ids::CHAR_VIRT_MEM;
const INO_CLASS_MEM: Ino = crate::ids::CHAR_CLASS_MEM;
const INO_VIRT_MISC: Ino = crate::ids::CHAR_VIRT_MISC;
const INO_CLASS_MISC: Ino = crate::ids::CHAR_CLASS_MISC;
const INO_VIRT_SOUND: Ino = crate::ids::CHAR_VIRT_SOUND;
const INO_CLASS_SOUND: Ino = crate::ids::CHAR_CLASS_SOUND;
const INO_VIRT_GRAPHICS: Ino = crate::ids::CHAR_VIRT_GRAPHICS;
const INO_CLASS_GRAPHICS: Ino = crate::ids::CHAR_CLASS_GRAPHICS;
const INO_CHAR_DIR: Ino = crate::ids::CHAR_DIR;
const INO_CHAR_ATTR: Ino = crate::ids::CHAR_ATTR;
const INO_CHAR_LINK: Ino = crate::ids::CHAR_LINK;

#[derive(Clone)]
struct CharDevInfo {
    addr: String,
    devname: String,
    dev_t: (u32, u32),
    uevent_env: Vec<String>,
    parent_bus: Option<&'static str>,
    parent_addr: Option<String>,
}

fn char_devs(class: &'static str) -> Vec<CharDevInfo> {
    drv::devices()
        .into_iter()
        .filter(|d| d.bus == class)
        .filter_map(|d| {
            let dev_t = d.dev_t?;
            Some(CharDevInfo {
                addr: d.addr.clone(),
                devname: d.devname.clone().unwrap_or_else(|| d.addr.clone()),
                dev_t,
                uevent_env: d.uevent_env.clone(),
                parent_bus: d.parent_bus,
                parent_addr: d.parent_addr.clone(),
            })
        })
        .collect()
}

fn char_by_addr(class: &'static str, addr: &str) -> Option<CharDevInfo> {
    char_devs(class).into_iter().find(|d| d.addr == addr)
}

fn uevent_body(info: &CharDevInfo) -> Vec<u8> {
    let mut body = alloc::format!(
        "MAJOR={}\nMINOR={}\nDEVNAME={}\n",
        info.dev_t.0,
        info.dev_t.1,
        info.devname,
    );
    for entry in info.uevent_env.iter() {
        body.push_str(entry);
        body.push('\n');
    }
    body.into_bytes()
}

fn parent_root_leaf(bus: &str) -> &'static str {
    match bus {
        "pci" => "pci0000:00",
        "virtio" => "virtio",
        "platform" => "platform",
        "mem" => "virtual/mem",
        "misc" => "virtual/misc",
        "sound" => "virtual/sound",
        "graphics" => "virtual/graphics",
        "input" => "virtual/input",
        "drm" => "virtual/drm",
        _ => "platform",
    }
}

fn parent_device_target(info: &CharDevInfo) -> Option<Vec<u8>> {
    Some(alloc::format!(
        "../../../{}/{}",
        parent_root_leaf(info.parent_bus?),
        info.parent_addr.as_deref()?,
    )
    .into_bytes())
}

struct CharDevDirData {
    class: &'static str,
    addr: String,
}

struct CharUeventData {
    class: &'static str,
    info: CharDevInfo,
}

struct CharUeventOps;
impl FileOps for CharUeventOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<CharUeventData>().ok_or(VfsError::Einval)?;
        Ok(crate::read_window(&uevent_body(&d.info), off, buf))
    }
    fn write(&self, inode: &Inode, _o: u64, b: &[u8]) -> KResult<usize> {
        let d = inode.private::<CharUeventData>().ok_or(VfsError::Einval)?;
        let devpath = alloc::format!("/devices/virtual/{}/{}", d.class, d.info.addr);
        let devname = alloc::format!("DEVNAME={}", d.info.devname);
        let maj = alloc::format!("MAJOR={}", d.info.dev_t.0);
        let min = alloc::format!("MINOR={}", d.info.dev_t.1);
        let mut env = Vec::from([devname.as_str(), maj.as_str(), min.as_str()]);
        env.extend(d.info.uevent_env.iter().map(|entry| entry.as_str()));
        ::netlink::emit_uevent_with_env(
            crate::uevent_action(b), &devpath, d.class, &env);
        Ok(b.len())
    }
}

fn make_char_uevent_inode(class: &'static str, info: CharDevInfo) -> InodeRef {
    InodeBuilder::new(
        INO_CHAR_ATTR,
        mk_mode(FileType::Regular, RW_PERM),
        vfs::default_inode_ops(),
        Arc::new(CharUeventOps),
    )
    .private(Arc::new(CharUeventData { class, info }))
    .build()
}

struct CharDevDirOps;
impl InodeOps for CharDevDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<CharDevDirData>().ok_or(VfsError::Einval)?;
        let info = char_by_addr(d.class, &d.addr).ok_or(VfsError::Enoent)?;
        match name {
            "dev" => Ok(crate::make_body_inode(
                alloc::format!("{}:{}\n", info.dev_t.0, info.dev_t.1).into_bytes(),
                INO_CHAR_ATTR,
            )),
            "uevent" => Ok(make_char_uevent_inode(d.class, info)),
            "subsystem" => Ok(crate::make_symlink_inode(
                alloc::format!("../../../../class/{}", d.class).into_bytes(),
            )),
            "device" => Ok(crate::make_symlink_inode(
                parent_device_target(&info).ok_or(VfsError::Enoent)?,
            )),
            _ => Err(VfsError::Enoent),
        }
    }
}
impl FileOps for CharDevDirOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        const BASE_ENTRIES: &[(&str, FileType)] = &[
            ("dev", FileType::Regular),
            ("uevent", FileType::Regular),
            ("subsystem", FileType::Symlink),
        ];
        let d = inode.private::<CharDevDirData>().ok_or(VfsError::Einval)?;
        let info = char_by_addr(d.class, &d.addr).ok_or(VfsError::Enoent)?;
        let mut entries: Vec<(&str, FileType)> = BASE_ENTRIES.to_vec();
        if parent_device_target(&info).is_some() {
            entries.push(("device", FileType::Symlink));
        }
        let mut idx = ctx.pos as usize;
        while idx < entries.len() {
            let (name, ft) = entries[idx];
            let next = idx as u64 + 1;
            let ino = inode.lookup(name).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(name, ino, ft, next) {
                return Ok(());
            }
            idx += 1;
        }
        Ok(())
    }
}

fn make_char_dev_dir(class: &'static str, addr: String) -> InodeRef {
    InodeBuilder::new(
        INO_CHAR_DIR,
        mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(CharDevDirOps),
        Arc::new(CharDevDirOps),
    )
    .private(Arc::new(CharDevDirData { class, addr }))
    .build()
}

struct VirtualClassData {
    class: &'static str,
}

struct VirtualClassOps;
impl InodeOps for VirtualClassOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let class = inode
            .private::<VirtualClassData>()
            .ok_or(VfsError::Einval)?
            .class;
        if char_by_addr(class, name).is_some() {
            Ok(make_char_dev_dir(class, String::from(name)))
        } else {
            Err(VfsError::Enoent)
        }
    }
}
impl FileOps for VirtualClassOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let class = inode
            .private::<VirtualClassData>()
            .ok_or(VfsError::Einval)?
            .class;
        let devs = char_devs(class);
        let mut idx = ctx.pos as usize;
        while idx < devs.len() {
            let next = idx as u64 + 1;
            let ino = inode.lookup(&devs[idx].addr).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(&devs[idx].addr, ino, FileType::Directory, next) {
                return Ok(());
            }
            idx += 1;
        }
        Ok(())
    }
}

fn make_virtual_class_inode(class: &'static str, ino: Ino) -> InodeRef {
    InodeBuilder::new(
        ino,
        mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(VirtualClassOps),
        Arc::new(VirtualClassOps),
    )
    .private(Arc::new(VirtualClassData { class }))
    .build()
}

struct SysClassData {
    class: &'static str,
}

struct SysClassOps;
impl InodeOps for SysClassOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let class = inode.private::<SysClassData>().ok_or(VfsError::Einval)?.class;
        if char_by_addr(class, name).is_none() {
            return Err(VfsError::Enoent);
        }
        Ok(crate::make_symlink_inode_ino(
            alloc::format!("../../devices/virtual/{}/{}", class, name).into_bytes(),
            INO_CHAR_LINK,
        ))
    }
}
impl FileOps for SysClassOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let class = inode.private::<SysClassData>().ok_or(VfsError::Einval)?.class;
        let devs = char_devs(class);
        let mut idx = ctx.pos as usize;
        while idx < devs.len() {
            let next = idx as u64 + 1;
            let ino = inode.lookup(&devs[idx].addr).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(&devs[idx].addr, ino, FileType::Symlink, next) {
                return Ok(());
            }
            idx += 1;
        }
        Ok(())
    }
}

fn make_sys_class_inode(class: &'static str, ino: Ino) -> InodeRef {
    InodeBuilder::new(
        ino,
        mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(SysClassOps),
        Arc::new(SysClassOps),
    )
    .private(Arc::new(SysClassData { class }))
    .build()
}

/// Register model-backed virtual char class trees. # C: O(1)
pub fn init() {
    crate::register(
        "/sys/devices/virtual/mem",
        make_virtual_class_inode("mem", INO_VIRT_MEM),
    );
    crate::register("/sys/class/mem", make_sys_class_inode("mem", INO_CLASS_MEM));
    crate::register(
        "/sys/devices/virtual/misc",
        make_virtual_class_inode("misc", INO_VIRT_MISC),
    );
    crate::register(
        "/sys/class/misc",
        make_sys_class_inode("misc", INO_CLASS_MISC),
    );
    crate::register(
        "/sys/devices/virtual/sound",
        make_virtual_class_inode("sound", INO_VIRT_SOUND),
    );
    crate::register(
        "/sys/class/sound",
        make_sys_class_inode("sound", INO_CLASS_SOUND),
    );
    crate::register(
        "/sys/devices/virtual/graphics",
        make_virtual_class_inode("graphics", INO_VIRT_GRAPHICS),
    );
    crate::register(
        "/sys/class/graphics",
        make_sys_class_inode("graphics", INO_CLASS_GRAPHICS),
    );
}

#[cfg(test)]
mod tests;
