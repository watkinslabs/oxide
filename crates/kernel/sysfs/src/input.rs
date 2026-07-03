// `/sys/class/input` sysfs tree. The evdev character devices are owned by the
// input driver through drv::device_add; this module only synthesizes the Linux
// class/device view from those live model devices.
//
// Tree:
//   /sys/class/input/
//     eventN -> ../../devices/virtual/input/eventN
//   /sys/devices/virtual/input/eventN/
//     dev        "13:<minor>\n"
//     uevent     MAJOR=/MINOR=/DEVNAME=
//     subsystem  -> ../../../class/input

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{
    mk_mode, DirContext, FileOps, FileType, Ino, Inode, InodeBuilder, InodeOps, InodeRef, KResult,
    VfsError,
};

use crate::{make_body_inode, make_symlink_inode, register, DIR_PERM, RW_PERM};

/// Linux input char major. Event nodes start at minor 64.
const INPUT_MAJOR: u32 = 13;
const EVENT_MINOR_BASE: u32 = 64;

struct InputEventMinor {
    name: String,
    minor: u32,
}

/// Snapshot live evdev class devices from the authoritative driver model.
/// # C: O(devices)
fn input_events() -> Vec<InputEventMinor> {
    let mut events = Vec::new();
    for dev in drv::devices() {
        if dev.dev_class != "input" {
            continue;
        }
        let Some((INPUT_MAJOR, minor)) = dev.dev_t else {
            continue;
        };
        let Some(devname) = dev.devname.as_deref() else {
            continue;
        };
        let Some(name) = devname.strip_prefix("input/") else {
            continue;
        };
        if !name.starts_with("event") || minor < EVENT_MINOR_BASE {
            continue;
        }
        events.push(InputEventMinor { name: String::from(name), minor });
    }
    events.sort_by(|a, b| a.minor.cmp(&b.minor));
    events
}

fn event_minor(name: &str) -> Option<u32> {
    input_events()
        .into_iter()
        .find(|event| event.name == name)
        .map(|event| event.minor)
}

// ---- /sys/class/input ------------------------------------------------------

struct SysClassInputOps;
impl InodeOps for SysClassInputOps {
    fn lookup(&self, _inode: &Inode, name: &str) -> KResult<InodeRef> {
        if event_minor(name).is_none() {
            return Err(VfsError::Enoent);
        }
        let mut target = String::from("../../devices/virtual/input/");
        target.push_str(name);
        Ok(make_symlink_inode(target.into_bytes()))
    }
}
impl FileOps for SysClassInputOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let events = input_events();
        let mut idx = ctx.pos as usize;
        while idx < events.len() {
            let next = idx as u64 + 1;
            let name = events[idx].name.as_str();
            let ino = inode.lookup(name).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(name, ino, FileType::Symlink, next) {
                return Ok(());
            }
            idx += 1;
        }
        Ok(())
    }
}

fn make_sys_class_input_inode() -> InodeRef {
    InodeBuilder::new(
        0x5105_0001,
        mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(SysClassInputOps),
        Arc::new(SysClassInputOps),
    )
    .build()
}

// ---- /sys/devices/virtual/input ------------------------------------------

struct SysDevicesVirtualInputOps;
impl InodeOps for SysDevicesVirtualInputOps {
    fn lookup(&self, _inode: &Inode, name: &str) -> KResult<InodeRef> {
        let minor = event_minor(name).ok_or(VfsError::Enoent)?;
        Ok(make_input_event_inode(String::from(name), minor))
    }
}
impl FileOps for SysDevicesVirtualInputOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let events = input_events();
        let mut idx = ctx.pos as usize;
        while idx < events.len() {
            let next = idx as u64 + 1;
            let name = events[idx].name.as_str();
            let ino = inode.lookup(name).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(name, ino, FileType::Directory, next) {
                return Ok(());
            }
            idx += 1;
        }
        Ok(())
    }
}

fn make_sys_devices_virtual_input_inode() -> InodeRef {
    InodeBuilder::new(
        0x5105_0002,
        mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(SysDevicesVirtualInputOps),
        Arc::new(SysDevicesVirtualInputOps),
    )
    .build()
}

// ---- /sys/devices/virtual/input/eventN ------------------------------------

struct InputEventData {
    name: String,
    minor: u32,
}

struct InputEventOps;
impl InodeOps for InputEventOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<InputEventData>().ok_or(VfsError::Einval)?;
        match name {
            "dev" => {
                let body = alloc::format!("{}:{}\n", INPUT_MAJOR, d.minor).into_bytes();
                Ok(make_body_inode(body, 0x5105_2000 + d.minor as Ino))
            }
            "uevent" => Ok(make_input_uevent_inode(d.name.clone(), d.minor)),
            "subsystem" => Ok(make_symlink_inode(b"../../../class/input".to_vec())),
            _ => Err(VfsError::Enoent),
        }
    }
}
impl FileOps for InputEventOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        const ENTRIES: &[(&str, FileType)] = &[
            ("dev", FileType::Regular),
            ("uevent", FileType::Regular),
            ("subsystem", FileType::Symlink),
        ];
        let mut idx = ctx.pos as usize;
        while idx < ENTRIES.len() {
            let next = idx as u64 + 1;
            let (name, ty) = ENTRIES[idx];
            let ino = inode.lookup(name).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(name, ino, ty, next) {
                return Ok(());
            }
            idx += 1;
        }
        Ok(())
    }
}

fn make_input_event_inode(name: String, minor: u32) -> InodeRef {
    InodeBuilder::new(
        0x5105_1000 + minor as Ino,
        mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(InputEventOps),
        Arc::new(InputEventOps),
    )
    .private(Arc::new(InputEventData { name, minor }))
    .build()
}

// ---- /sys/devices/virtual/input/eventN/uevent -----------------------------

struct InputUeventData {
    name: String,
    minor: u32,
}

struct InputUeventFileOps;
impl FileOps for InputUeventFileOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<InputUeventData>().ok_or(VfsError::Einval)?;
        let body = alloc::format!(
            "MAJOR={}\nMINOR={}\nDEVNAME=input/{}\n",
            INPUT_MAJOR,
            d.minor,
            d.name
        )
        .into_bytes();
        Ok(crate::read_window(&body, off, buf))
    }

    fn write(&self, inode: &Inode, _o: u64, b: &[u8]) -> KResult<usize> {
        let d = inode.private::<InputUeventData>().ok_or(VfsError::Einval)?;
        let devpath = alloc::format!("/devices/virtual/input/{}", d.name);
        let devname = alloc::format!("DEVNAME=input/{}", d.name);
        let maj = alloc::format!("MAJOR={}", INPUT_MAJOR);
        let min = alloc::format!("MINOR={}", d.minor);
        ::netlink::emit_uevent_with_env(
            crate::uevent_action(b),
            &devpath,
            "input",
            &[&devname, &maj, &min],
        );
        Ok(b.len())
    }
}

fn make_input_uevent_inode(name: String, minor: u32) -> InodeRef {
    InodeBuilder::new(
        0x5105_3000 + minor as Ino,
        mk_mode(FileType::Regular, RW_PERM),
        vfs::default_inode_ops(),
        Arc::new(InputUeventFileOps),
    )
    .private(Arc::new(InputUeventData { name, minor }))
    .build()
}

/// Register `/sys/class/input` and `/sys/devices/virtual/input`.
/// # C: O(1)
pub fn init() {
    register("/sys/class/input", make_sys_class_input_inode());
    register("/sys/devices/virtual/input", make_sys_devices_virtual_input_inode());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_events_follow_model_devices() {
        let event0 = drv::device_add(Arc::new(
            drv::Device::new("input", String::from("event0"), 0, 0, 0)
                .with_devnode("input", String::from("input/event0"), Some((13, 64))),
        ));
        let event2 = drv::device_add(Arc::new(
            drv::Device::new("input", String::from("event2"), 0, 0, 2)
                .with_devnode("input", String::from("input/event2"), Some((13, 66))),
        ));

        let events = input_events();
        assert!(events.iter().any(|event| event.name == "event0" && event.minor == 64));
        assert!(events.iter().any(|event| event.name == "event2" && event.minor == 66));
        assert_eq!(event_minor("event0"), Some(64));
        assert_eq!(event_minor("event2"), Some(66));

        drv::device_del(&event2);
        drv::device_del(&event0);
    }
}
