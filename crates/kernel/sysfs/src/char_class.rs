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

const INO_VIRT_MEM: Ino = 0x5106_0001;
const INO_CLASS_MEM: Ino = 0x5106_0002;
const INO_VIRT_MISC: Ino = 0x5106_0003;
const INO_CLASS_MISC: Ino = 0x5106_0004;
const INO_VIRT_SOUND: Ino = 0x5106_0005;
const INO_CLASS_SOUND: Ino = 0x5106_0006;
const INO_VIRT_GRAPHICS: Ino = 0x5106_0007;
const INO_CLASS_GRAPHICS: Ino = 0x5106_0008;
const INO_CHAR_DIR: Ino = 0x5106_1000;
const INO_CHAR_ATTR: Ino = 0x5106_2000;
const INO_CHAR_LINK: Ino = 0x5106_3000;

#[derive(Clone)]
struct CharDevInfo {
    addr: String,
    devname: String,
    dev_t: (u32, u32),
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
    alloc::format!(
        "MAJOR={}\nMINOR={}\nDEVNAME={}\n",
        info.dev_t.0,
        info.dev_t.1,
        info.devname,
    )
    .into_bytes()
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
        ::netlink::emit_uevent_with_env(
            crate::uevent_action(b), &devpath, d.class, &[&devname, &maj, &min]);
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
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use netlink::{proto, NetlinkSocket};

    fn add_char(class: &'static str, addr: &str, devname: &str, dt: (u32, u32)) -> Arc<drv::Device> {
        let dev = Arc::new(
            drv::Device::new(class, String::from(addr), 0, 0, 0)
                .with_devnode(class, String::from(devname), Some(dt)),
        );
        drv::try_device_add(Arc::clone(&dev)).expect("test device registration");
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

    #[test]
    fn class_uevent_write_reemits_model_event() {
        let dev = add_char("sound", "controlC12", "snd/controlC12", (116, 322));
        let listener = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT));
        listener.set_group_mask(1);
        netlink::register_uevent_listener(&listener);

        let root = make_virtual_class_inode("sound", INO_VIRT_SOUND);
        let dir = root.lookup("controlC12").expect("sound device dir");
        let uevent = dir.lookup("uevent").expect("uevent attr");
        assert_eq!(uevent.write(0, b"change\n"), Ok("change\n".len()));
        let (msg, _src) = listener.dequeue().expect("uevent message");
        assert!(msg.windows(b"ACTION=change".len()).any(|w| w == b"ACTION=change"));
        assert!(msg.windows(b"DEVPATH=/devices/virtual/sound/controlC12".len()).any(|w| w == b"DEVPATH=/devices/virtual/sound/controlC12"));
        assert!(msg.windows(b"SUBSYSTEM=sound".len()).any(|w| w == b"SUBSYSTEM=sound"));
        assert!(msg.windows(b"DEVNAME=snd/controlC12".len()).any(|w| w == b"DEVNAME=snd/controlC12"));

        drv::device_del(&dev);
    }

    #[test]
    fn misc_class_autofs_is_model_backed_with_linux_dev_t() {
        let dev = add_char("misc", "autofs", "autofs", (10, 235));

        let class = make_sys_class_inode("misc", INO_CLASS_MISC);
        let link = class.lookup("autofs").expect("autofs class link");
        assert_eq!(
            link.readlink().expect("readlink"),
            b"../../devices/virtual/misc/autofs".to_vec()
        );

        let root = make_virtual_class_inode("misc", INO_VIRT_MISC);
        let dir = root.lookup("autofs").expect("autofs device dir");
        let dev_attr = dir.lookup("dev").expect("dev attr");
        let mut buf = [0u8; 32];
        let n = dev_attr.read(0, &mut buf).expect("read dev attr");
        assert_eq!(&buf[..n], b"10:235\n");

        drv::device_del(&dev);
        assert_eq!(class.lookup("autofs").err(), Some(VfsError::Enoent));
    }

    #[test]
    fn sound_class_separates_sysfs_leaf_from_devtmpfs_path() {
        let dev = add_char("sound", "controlC9", "snd/controlC9", (116, 288));

        let class = make_sys_class_inode("sound", INO_CLASS_SOUND);
        let link = class.lookup("controlC9").expect("sound class link");
        assert_eq!(
            link.readlink().expect("readlink"),
            b"../../devices/virtual/sound/controlC9".to_vec()
        );
        assert_eq!(class.lookup("snd").err(), Some(VfsError::Enoent));

        let root = make_virtual_class_inode("sound", INO_VIRT_SOUND);
        let dir = root.lookup("controlC9").expect("sound device dir");
        let uevent = dir.lookup("uevent").expect("uevent attr");
        let mut buf = [0u8; 64];
        let n = uevent.read(0, &mut buf).expect("read uevent");
        assert_eq!(
            &buf[..n],
            b"MAJOR=116\nMINOR=288\nDEVNAME=snd/controlC9\n"
        );

        drv::device_del(&dev);
        assert_eq!(root.lookup("controlC9").err(), Some(VfsError::Enoent));
    }

    #[test]
    fn graphics_class_resolves_fbdev_nodes() {
        let dev = add_char("graphics", "fb7", "fb7", (29, 7));

        let class = make_sys_class_inode("graphics", INO_CLASS_GRAPHICS);
        let link = class.lookup("fb7").expect("graphics class link");
        assert_eq!(
            link.readlink().expect("readlink"),
            b"../../devices/virtual/graphics/fb7".to_vec()
        );

        let root = make_virtual_class_inode("graphics", INO_VIRT_GRAPHICS);
        let dir = root.lookup("fb7").expect("graphics device dir");
        let subsystem = dir.lookup("subsystem").expect("subsystem link");
        assert_eq!(
            subsystem.readlink().expect("readlink"),
            b"../../../../class/graphics".to_vec()
        );

        drv::device_del(&dev);
        assert_eq!(class.lookup("fb7").err(), Some(VfsError::Enoent));
    }

    #[test]
    fn class_device_links_to_model_parent_when_present() {
        let parent = Arc::new(drv::Device::new(
            "virtio",
            String::from("virtio-snd-parent0"),
            0x1af4,
            25,
            0,
        ));
        drv::try_device_add(Arc::clone(&parent)).expect("test parent registration");
        let dev = Arc::new(
            drv::Device::new("sound", String::from("controlC10"), 0, 0, 0)
                .with_parent("virtio", String::from("virtio-snd-parent0"))
                .with_devnode("sound", String::from("snd/controlC10"), Some((116, 320))),
        );
        drv::try_device_add(Arc::clone(&dev)).expect("test sound registration");

        let root = make_virtual_class_inode("sound", INO_VIRT_SOUND);
        let dir = root.lookup("controlC10").expect("sound device dir");
        let device = dir.lookup("device").expect("parent device link");
        assert_eq!(
            device.readlink().expect("readlink"),
            b"../../../virtio/virtio-snd-parent0".to_vec()
        );

        drv::device_del(&dev);
        drv::device_del(&parent);
        assert_eq!(root.lookup("controlC10").err(), Some(VfsError::Enoent));
    }

    #[test]
    fn class_device_parent_link_tracks_remove_readd_model_state() {
        let parent = Arc::new(drv::Device::new(
            "virtio",
            String::from("virtio-snd-readd-parent0"),
            0x1af4,
            25,
            0,
        ));
        drv::try_device_add(Arc::clone(&parent)).expect("test parent registration");

        let root = make_virtual_class_inode("sound", INO_VIRT_SOUND);
        let class = make_sys_class_inode("sound", INO_CLASS_SOUND);
        let first = Arc::new(
            drv::Device::new("sound", String::from("controlC11"), 0, 0, 0)
                .with_parent("virtio", String::from("virtio-snd-readd-parent0"))
                .with_devnode("sound", String::from("snd/controlC11"), Some((116, 321))),
        );
        drv::try_device_add(Arc::clone(&first)).expect("first sound registration");

        let dir = root.lookup("controlC11").expect("first sound device dir");
        let device = dir.lookup("device").expect("first parent device link");
        assert_eq!(
            device.readlink().expect("readlink"),
            b"../../../virtio/virtio-snd-readd-parent0".to_vec()
        );
        assert!(class.lookup("controlC11").is_ok());

        drv::device_del(&first);
        assert_eq!(root.lookup("controlC11").err(), Some(VfsError::Enoent));
        assert_eq!(class.lookup("controlC11").err(), Some(VfsError::Enoent));

        let second = Arc::new(
            drv::Device::new("sound", String::from("controlC11"), 0, 0, 0)
                .with_parent("virtio", String::from("virtio-snd-readd-parent0"))
                .with_devnode("sound", String::from("snd/controlC11"), Some((116, 321))),
        );
        drv::try_device_add(Arc::clone(&second)).expect("second sound registration");

        let dir = root.lookup("controlC11").expect("readded sound device dir");
        let device = dir.lookup("device").expect("readded parent device link");
        assert_eq!(
            device.readlink().expect("readlink"),
            b"../../../virtio/virtio-snd-readd-parent0".to_vec()
        );
        let link = class.lookup("controlC11").expect("readded class link");
        assert_eq!(
            link.readlink().expect("readlink"),
            b"../../devices/virtual/sound/controlC11".to_vec()
        );

        drv::device_del(&second);
        drv::device_del(&parent);
        assert_eq!(root.lookup("controlC11").err(), Some(VfsError::Enoent));
    }
}
