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

use crate::{DIR_PERM, RW_PERM};

const INO_VIRT_INPUT:  Ino = crate::ids::INPUT_VIRT;
const INO_CLASS_INPUT: Ino = crate::ids::INPUT_CLASS;
const INO_INPUT_DIR:   Ino = crate::ids::INPUT_DIR;
const INO_INPUT_ATTR:  Ino = crate::ids::INPUT_ATTR;
const INO_INPUT_LINK:  Ino = crate::ids::INPUT_LINK;

#[derive(Clone)]
struct InputDevInfo {
    addr: String,
    dev_t: (u32, u32),
    devname: String,
    uevent_env: Vec<String>,
    parent_bus: Option<&'static str>,
    parent_addr: Option<String>,
}

/// Model state for each registered evdev device.
/// # C: O(N_devices)
fn input_devs() -> Vec<InputDevInfo> {
    drv::devices().into_iter()
        .filter(|d| d.bus == "input")
        .filter_map(|d| {
            let dt = d.dev_t?;
            let dn = d.devname.clone().unwrap_or_else(|| alloc::format!("input/{}", d.addr));
            Some(InputDevInfo {
                addr: d.addr.clone(),
                dev_t: dt,
                devname: dn,
                uevent_env: d.uevent_env.clone(),
                parent_bus: d.parent_bus,
                parent_addr: d.parent_addr.clone(),
            })
        })
        .collect()
}

fn input_by_addr(addr: &str) -> Option<InputDevInfo> {
    input_devs().into_iter().find(|dev| dev.addr == addr)
}

fn parent_device_target(info: &InputDevInfo) -> Option<Vec<u8>> {
    let parent_bus = info.parent_bus?;
    let parent_addr = info.parent_addr.as_deref()?;
    // Input class devices live at /sys/devices/virtual/input/eventN.  Resolve
    // the parent through the model's canonical path, which preserves a
    // PCI-backed virtio device's nesting; the old flat virtio path did not
    // exist, leaving logind unable to resolve the evdev device it was asked to
    // take.
    let canon = crate::bus::dev_canon(parent_bus, parent_addr);
    Some(alloc::format!(
        "../../../../{}",
        canon,
    )
    .into_bytes())
}

// ---- /sys/devices/virtual/input/<addr> (per-device dir) -------------------
struct InputDevDirData { addr: String }

fn input_uevent_body(info: &InputDevInfo) -> Vec<u8> {
    let mut body = alloc::format!(
        "MAJOR={}\nMINOR={}\nDEVNAME={}\n",
        info.dev_t.0, info.dev_t.1, info.devname,
    );
    for entry in info.uevent_env.iter() {
        body.push_str(entry);
        body.push('\n');
    }
    body.into_bytes()
}

struct InputUeventData { info: InputDevInfo }
struct InputUeventOps;
impl FileOps for InputUeventOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<InputUeventData>().ok_or(VfsError::Einval)?;
        Ok(crate::read_window(&input_uevent_body(&d.info), off, buf))
    }
    fn write(&self, inode: &Inode, _o: u64, b: &[u8]) -> KResult<usize> {
        let d = inode.private::<InputUeventData>().ok_or(VfsError::Einval)?;
        let devpath = alloc::format!("/devices/virtual/input/{}", d.info.addr);
        let devname = alloc::format!("DEVNAME={}", d.info.devname);
        let maj = alloc::format!("MAJOR={}", d.info.dev_t.0);
        let min = alloc::format!("MINOR={}", d.info.dev_t.1);
        let mut env = Vec::from([devname.as_str(), maj.as_str(), min.as_str()]);
        env.extend(d.info.uevent_env.iter().map(|entry| entry.as_str()));
        ::netlink::emit_uevent_with_env(
            crate::uevent_action(b), &devpath, "input", &env);
        Ok(b.len())
    }
}

fn make_input_uevent_inode(info: InputDevInfo) -> InodeRef {
    InodeBuilder::new(INO_INPUT_ATTR, mk_mode(FileType::Regular, RW_PERM),
        vfs::default_inode_ops(), Arc::new(InputUeventOps))
        .private(Arc::new(InputUeventData { info }))
        .build()
}

struct InputDevDirOps;
impl InodeOps for InputDevDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<InputDevDirData>().ok_or(VfsError::Einval)?;
        let info = input_by_addr(&d.addr).ok_or(VfsError::Enoent)?;
        let (maj, min) = info.dev_t;
        match name {
            "uevent" => Ok(make_input_uevent_inode(info)),
            "dev" => Ok(crate::make_body_inode(
                alloc::format!("{}:{}\n", maj, min).into_bytes(), INO_INPUT_ATTR)),
            // sd-device reads SUBSYSTEM from the basename of this symlink.
            "subsystem" => Ok(crate::make_symlink_inode(b"../../../../class/input".to_vec())),
            "device" => Ok(crate::make_symlink_inode(
                parent_device_target(&info).ok_or(VfsError::Enoent)?,
            )),
            _ => Err(VfsError::Enoent),
        }
    }
}
impl FileOps for InputDevDirOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        const BASE_ENTRIES: &[(&str, FileType)] = &[
            ("uevent", FileType::Regular), ("dev", FileType::Regular),
            ("subsystem", FileType::Symlink),
        ];
        let d = inode.private::<InputDevDirData>().ok_or(VfsError::Einval)?;
        let info = input_by_addr(&d.addr).ok_or(VfsError::Enoent)?;
        let mut entries: Vec<(&str, FileType)> = BASE_ENTRIES.to_vec();
        if parent_device_target(&info).is_some() {
            entries.push(("device", FileType::Symlink));
        }
        let mut idx = ctx.pos as usize;
        while idx < entries.len() {
            let (name, ft) = entries[idx];
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
            let ino = inode.lookup(&devs[idx].addr).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(&devs[idx].addr, ino, FileType::Directory, next) { return Ok(()); }
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
            let ino = inode.lookup(&devs[idx].addr).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(&devs[idx].addr, ino, FileType::Symlink, next) { return Ok(()); }
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use netlink::{proto, NetlinkSocket};

    #[test]
    fn input_class_device_links_to_model_parent_when_present() {
        let parent = Arc::new(drv::Device::new(
            "virtio",
            String::from("virtio-input-parent0"),
            0x1af4,
            18,
            0,
        ));
        drv::try_device_add(Arc::clone(&parent)).expect("test parent registration");
        let input = Arc::new(
            drv::Device::new("input", String::from("event-parent0"), 0, 0, 0)
                .with_parent("virtio", String::from("virtio-input-parent0"))
                .with_devnode("input", String::from("input/event-parent0"), Some((13, 80))),
        );
        drv::try_device_add(Arc::clone(&input)).expect("test input registration");

        let root = InodeBuilder::new(
            INO_VIRT_INPUT,
            mk_mode(FileType::Directory, DIR_PERM),
            Arc::new(VirtInputOps),
            Arc::new(VirtInputOps),
        )
        .build();
        let dir = root.lookup("event-parent0").expect("input device dir");
        let device = dir.lookup("device").expect("parent device link");
        assert_eq!(
            device.readlink().expect("readlink"),
            b"../../../../devices/virtio/virtio-input-parent0".to_vec()
        );

        drv::device_del(&input);
        drv::device_del(&parent);
        assert_eq!(root.lookup("event-parent0").err(), Some(VfsError::Enoent));
    }

    #[test]
    fn input_class_device_without_parent_has_no_device_link() {
        let input = Arc::new(
            drv::Device::new("input", String::from("event-orphan0"), 0, 0, 0)
                .with_devnode("input", String::from("input/event-orphan0"), Some((13, 81))),
        );
        drv::try_device_add(Arc::clone(&input)).expect("test input registration");

        let root = InodeBuilder::new(
            INO_VIRT_INPUT,
            mk_mode(FileType::Directory, DIR_PERM),
            Arc::new(VirtInputOps),
            Arc::new(VirtInputOps),
        )
        .build();
        let dir = root.lookup("event-orphan0").expect("input device dir");
        assert_eq!(dir.lookup("device").err(), Some(VfsError::Enoent));

        drv::device_del(&input);
    }

    #[test]
    fn input_uevent_write_reemits_model_event() {
        let input = Arc::new(
            drv::Device::new("input", String::from("event-trigger0"), 0, 0, 0)
                .with_devnode("input", String::from("input/event-trigger0"), Some((13, 82)))
                .with_uevent_env(alloc::vec![
                    String::from("PRODUCT=3/1234/5678/9abc"),
                    String::from("NAME=\"oxide keyboard\""),
                    String::from("UNIQ=\"input-serial\""),
                ]),
        );
        drv::try_device_add(Arc::clone(&input)).expect("test input registration");
        let listener = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT, &network_namespace::initial()));
        listener.set_group_mask(1);
        netlink::register_uevent_listener(&listener);

        let root = InodeBuilder::new(
            INO_VIRT_INPUT,
            mk_mode(FileType::Directory, DIR_PERM),
            Arc::new(VirtInputOps),
            Arc::new(VirtInputOps),
        )
        .build();
        let dir = root.lookup("event-trigger0").expect("input device dir");
        let uevent = dir.lookup("uevent").expect("uevent attr");
        let mut buf = [0u8; 160];
        let n = uevent.read(0, &mut buf).expect("read uevent");
        assert!(buf[..n].windows(b"PRODUCT=3/1234/5678/9abc".len())
            .any(|w| w == b"PRODUCT=3/1234/5678/9abc"));
        assert!(buf[..n].windows(b"NAME=\"oxide keyboard\"".len())
            .any(|w| w == b"NAME=\"oxide keyboard\""));
        assert!(buf[..n].windows(b"UNIQ=\"input-serial\"".len())
            .any(|w| w == b"UNIQ=\"input-serial\""));
        assert_eq!(uevent.write(0, b"change\n"), Ok("change\n".len()));
        let (msg, _src) = listener.dequeue().expect("uevent message");
        assert!(msg.windows(b"ACTION=change".len()).any(|w| w == b"ACTION=change"));
        assert!(msg.windows(b"DEVPATH=/devices/virtual/input/event-trigger0".len()).any(|w| w == b"DEVPATH=/devices/virtual/input/event-trigger0"));
        assert!(msg.windows(b"SUBSYSTEM=input".len()).any(|w| w == b"SUBSYSTEM=input"));
        assert!(msg.windows(b"DEVNAME=input/event-trigger0".len()).any(|w| w == b"DEVNAME=input/event-trigger0"));
        assert!(msg.windows(b"PRODUCT=3/1234/5678/9abc".len()).any(|w| w == b"PRODUCT=3/1234/5678/9abc"));
        assert!(msg.windows(b"NAME=\"oxide keyboard\"".len()).any(|w| w == b"NAME=\"oxide keyboard\""));
        assert!(msg.windows(b"UNIQ=\"input-serial\"".len()).any(|w| w == b"UNIQ=\"input-serial\""));

        drv::device_del(&input);
    }
}
