// Model-backed virtual character classes for Linux mem/misc devices.
//
// These devices are published through drv::device_add, so sysfs must expose the
// matching class-device topology:
//   /sys/class/<class>/<name> -> ../../devices/virtual/<class>/<name>
//   /sys/devices/virtual/<class>/<name>/{dev,uevent,subsystem}
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

use crate::DIR_PERM;

const INO_VIRT_MEM: Ino = 0x5106_0001;
const INO_CLASS_MEM: Ino = 0x5106_0002;
const INO_VIRT_MISC: Ino = 0x5106_0003;
const INO_CLASS_MISC: Ino = 0x5106_0004;
const INO_CHAR_DIR: Ino = 0x5106_1000;
const INO_CHAR_ATTR: Ino = 0x5106_2000;
const INO_CHAR_LINK: Ino = 0x5106_3000;

#[derive(Clone)]
struct CharDevInfo {
    addr: String,
    devname: String,
    dev_t: (u32, u32),
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
            })
        })
        .collect()
}

fn char_by_addr(class: &'static str, addr: &str) -> Option<CharDevInfo> {
    char_devs(class).into_iter().find(|d| d.addr == addr)
}

fn uevent_body(info: &CharDevInfo) -> Vec<u8> {
    alloc::format!(
        "MAJOR={}\nMINOR={}\nDEVNAME={}\n",
        info.dev_t.0,
        info.dev_t.1,
        info.devname,
    )
    .into_bytes()
}

struct CharDevDirData {
    class: &'static str,
    addr: String,
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
            "uevent" => Ok(crate::make_body_inode(uevent_body(&info), INO_CHAR_ATTR)),
            "subsystem" => Ok(crate::make_symlink_inode(
                alloc::format!("../../../../class/{}", d.class).into_bytes(),
            )),
            _ => Err(VfsError::Enoent),
        }
    }
}
impl FileOps for CharDevDirOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        const ENTRIES: &[(&str, FileType)] = &[
            ("dev", FileType::Regular),
            ("uevent", FileType::Regular),
            ("subsystem", FileType::Symlink),
        ];
        let mut idx = ctx.pos as usize;
        while idx < ENTRIES.len() {
            let (name, ft) = ENTRIES[idx];
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;

    fn add_char(class: &'static str, addr: &str, devname: &str, dt: (u32, u32)) -> Arc<drv::Device> {
        let dev = Arc::new(
            drv::Device::new(class, String::from(addr), 0, 0, 0)
                .with_devnode(class, String::from(devname), Some(dt)),
        );
        drv::device_add(Arc::clone(&dev));
        dev
    }

    #[test]
    fn mem_class_resolves_model_backed_char_device() {
        let dev = add_char("mem", "sysfs-null-test", "null-test", (1, 3));

        let class = make_sys_class_inode("mem", INO_CLASS_MEM);
        let link = class.lookup("sysfs-null-test").expect("class link");
        assert_eq!(
            link.readlink().expect("readlink"),
            b"../../devices/virtual/mem/sysfs-null-test".to_vec()
        );

        let root = make_virtual_class_inode("mem", INO_VIRT_MEM);
        let dir = root.lookup("sysfs-null-test").expect("device dir");
        let dev_attr = dir.lookup("dev").expect("dev attr");
        let mut buf = [0u8; 32];
        let n = dev_attr.read(0, &mut buf).expect("read dev attr");
        assert_eq!(&buf[..n], b"1:3\n");

        let subsystem = dir.lookup("subsystem").expect("subsystem link");
        assert_eq!(
            subsystem.readlink().expect("readlink"),
            b"../../../../class/mem".to_vec()
        );

        drv::device_del(&dev);
        assert_eq!(root.lookup("sysfs-null-test").err(), Some(VfsError::Enoent));
        assert_eq!(class.lookup("sysfs-null-test").err(), Some(VfsError::Enoent));
    }

    #[test]
    fn misc_class_uevent_uses_model_devname() {
        let dev = add_char("misc", "sysfs-hwrng-test", "hwrng-test", (10, 183));

        let root = make_virtual_class_inode("misc", INO_VIRT_MISC);
        let dir = root.lookup("sysfs-hwrng-test").expect("device dir");
        let uevent = dir.lookup("uevent").expect("uevent attr");
        let mut buf = [0u8; 64];
        let n = uevent.read(0, &mut buf).expect("read uevent");
        assert_eq!(
            &buf[..n],
            b"MAJOR=10\nMINOR=183\nDEVNAME=hwrng-test\n"
        );

        drv::device_del(&dev);
        assert_eq!(root.lookup("sysfs-hwrng-test").err(), Some(VfsError::Enoent));
    }
}
