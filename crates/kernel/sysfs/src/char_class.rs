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
const INO_VIRT_V4L: Ino = crate::ids::CHAR_VIRT_V4L;
const INO_CLASS_V4L: Ino = crate::ids::CHAR_CLASS_V4L;
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

fn sound_card_number(addr: &str) -> Option<u32> {
    let digits = if let Some(rest) = addr.strip_prefix("controlC") {
        rest
    } else if let Some(rest) = addr.strip_prefix("pcmC") {
        rest.split_once('D')?.0
    } else {
        return None;
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) { return None; }
    digits.parse().ok()
}

pub(crate) fn sound_device_devpath(addr: &str) -> Option<String> {
    Some(alloc::format!("devices/virtual/sound/card{}/{}", sound_card_number(addr)?, addr))
}

fn sound_card_devs(card: u32) -> Vec<CharDevInfo> {
    char_devs("sound").into_iter()
        .filter(|d| sound_card_number(&d.addr) == Some(card))
        .collect()
}

fn sound_cards() -> Vec<u32> {
    let mut cards = Vec::new();
    for dev in char_devs("sound") {
        let Some(card) = sound_card_number(&dev.addr) else { continue };
        if !cards.contains(&card) { cards.push(card); }
    }
    cards.sort_unstable();
    cards
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
        "video4linux" => "virtual/video4linux",
        "input" => "virtual/input",
        "drm" => "virtual/drm",
        _ => "platform",
    }
}

fn parent_device_target(info: &CharDevInfo) -> Option<Vec<u8>> {
    Some(alloc::format!(
        "{}{}/{}",
        if sound_card_number(&info.addr).is_some() { "../../../../" } else { "../../../" },
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
    /// kernfs / procfs attributes always install a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<CharUeventData>().ok_or(VfsError::Einval)?;
        Ok(crate::read_window(&uevent_body(&d.info), off, buf))
    }
    fn write(&self, inode: &Inode, _o: u64, b: &[u8]) -> KResult<usize> {
        let d = inode.private::<CharUeventData>().ok_or(VfsError::Einval)?;
        let devpath = if d.class == "sound" {
            match sound_card_number(&d.info.addr) {
                Some(card) => alloc::format!("/devices/virtual/sound/card{}/{}", card, d.info.addr),
                None => alloc::format!("/devices/virtual/sound/{}", d.info.addr),
            }
        } else {
            alloc::format!("/devices/virtual/{}/{}", d.class, d.info.addr)
        };
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
        crate::kobject::attr_inode_ops(),
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
                alloc::format!("{}class/{}",
                    if d.class == "sound" && sound_card_number(&d.addr).is_some() { "../../../../../" } else { "../../../../" },
                    d.class).into_bytes(),
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
        // `device` is a symlink only for a char dev with a model parent; the
        // lookup that resolves its ino enforces that.
        const ENTRIES: &[(&str, FileType)] = &[
            ("dev", FileType::Regular),
            ("uevent", FileType::Regular),
            ("subsystem", FileType::Symlink),
            ("device", FileType::Symlink),
        ];
        let d = inode.private::<CharDevDirData>().ok_or(VfsError::Einval)?;
        char_by_addr(d.class, &d.addr).ok_or(VfsError::Enoent)?;
        crate::readdir::emit_table(inode, ctx, ENTRIES)
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

struct SoundCardData { card: u32 }

struct SoundCardUeventOps;
impl FileOps for SoundCardUeventOps {
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn read(&self, _inode: &Inode, _off: u64, _buf: &mut [u8]) -> KResult<usize> { Ok(0) }
    fn write(&self, inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        let d = inode.private::<SoundCardData>().ok_or(VfsError::Einval)?;
        let devpath = alloc::format!("/devices/virtual/sound/card{}", d.card);
        ::netlink::emit_uevent(crate::uevent_action(buf), &devpath, "sound");
        Ok(buf.len())
    }
}

fn make_sound_card_uevent(card: u32) -> InodeRef {
    InodeBuilder::new(crate::ids::SOUND_CARD_ATTR, mk_mode(FileType::Regular, RW_PERM),
        crate::kobject::attr_inode_ops(), Arc::new(SoundCardUeventOps))
        .private(Arc::new(SoundCardData { card })).build()
}

struct SoundCardDirOps;
impl InodeOps for SoundCardDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<SoundCardData>().ok_or(VfsError::Einval)?;
        if sound_card_devs(d.card).is_empty() { return Err(VfsError::Enoent); }
        match name {
            "uevent" => Ok(make_sound_card_uevent(d.card)),
            "subsystem" => Ok(crate::make_symlink_inode(b"../../../../class/sound".to_vec())),
            _ => {
                let info = char_by_addr("sound", name).ok_or(VfsError::Enoent)?;
                if sound_card_number(&info.addr) != Some(d.card) { return Err(VfsError::Enoent); }
                Ok(make_char_dev_dir("sound", info.addr))
            }
        }
    }
}
impl FileOps for SoundCardDirOps {
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let d = inode.private::<SoundCardData>().ok_or(VfsError::Einval)?;
        let devs = sound_card_devs(d.card);
        let mut entries = crate::readdir::DirEntries::new(inode);
        entries.push("uevent", FileType::Regular);
        entries.push("subsystem", FileType::Symlink);
        for dev in devs.iter() { entries.push(&dev.addr, FileType::Directory); }
        entries.emit(ctx)
    }
}

fn make_sound_card_dir(card: u32) -> InodeRef {
    InodeBuilder::new(crate::ids::SOUND_CARD_DIR, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(SoundCardDirOps), Arc::new(SoundCardDirOps))
        .private(Arc::new(SoundCardData { card })).build()
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
        if class == "sound" {
            if let Some(card) = name.strip_prefix("card").and_then(|n| n.parse::<u32>().ok()) {
                if sound_cards().contains(&card) { return Ok(make_sound_card_dir(card)); }
            }
            if sound_card_number(name).is_some() { return Err(VfsError::Enoent); }
        }
        if char_by_addr(class, name).is_some() {
            Ok(make_char_dev_dir(class, String::from(name)))
        } else {
            Err(VfsError::Enoent)
        }
    }
}
impl FileOps for VirtualClassOps {
    /// kernfs / procfs attributes always install a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let class = inode
            .private::<VirtualClassData>()
            .ok_or(VfsError::Einval)?
            .class;
        let devs = char_devs(class);
        if class != "sound" {
            return crate::readdir::emit_names(inode, ctx, devs.iter().map(|d| d.addr.as_str()), FileType::Directory);
        }
        let cards = sound_cards();
        let mut entries = crate::readdir::DirEntries::new(inode);
        for card in cards { entries.push(&alloc::format!("card{}", card), FileType::Directory); }
        for dev in devs.iter().filter(|d| sound_card_number(&d.addr).is_none()) {
            entries.push(&dev.addr, FileType::Directory);
        }
        entries.emit(ctx)
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
        if class == "sound" {
            if let Some(card) = name.strip_prefix("card").and_then(|n| n.parse::<u32>().ok()) {
                if sound_cards().contains(&card) {
                    return Ok(crate::make_symlink_inode_ino(
                        alloc::format!("../../devices/virtual/sound/card{}", card).into_bytes(),
                        INO_CHAR_LINK));
                }
            }
        }
        if char_by_addr(class, name).is_none() {
            return Err(VfsError::Enoent);
        }
        let target = if class == "sound" {
            match sound_card_number(name) {
                Some(card) => alloc::format!("../../devices/virtual/sound/card{}/{}", card, name),
                None => alloc::format!("../../devices/virtual/sound/{}", name),
            }
        } else {
            alloc::format!("../../devices/virtual/{}/{}", class, name)
        };
        Ok(crate::make_symlink_inode_ino(
            target.into_bytes(),
            INO_CHAR_LINK,
        ))
    }
}
impl FileOps for SysClassOps {
    /// kernfs / procfs attributes always install a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let class = inode.private::<SysClassData>().ok_or(VfsError::Einval)?.class;
        let devs = char_devs(class);
        let mut entries = crate::readdir::DirEntries::new(inode);
        if class == "sound" {
            for card in sound_cards() { entries.push(&alloc::format!("card{}", card), FileType::Symlink); }
        }
        for dev in devs.iter() { entries.push(&dev.addr, FileType::Symlink); }
        entries.emit(ctx)
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
    crate::register(
        "/sys/devices/virtual/video4linux",
        make_virtual_class_inode("video4linux", INO_VIRT_V4L),
    );
    crate::register(
        "/sys/class/video4linux",
        make_sys_class_inode("video4linux", INO_CLASS_V4L),
    );
}

#[cfg(test)]
mod tests;
