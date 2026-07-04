// `/sys/class/drm` sysfs tree - the udev seat-discovery prerequisite for a
// graphical login. systemd-logind marks a seat `CanGraphical=yes` only when a
// DRM device on it carries udev's `master-of-seat` tag; udev's `71-seat.rules`
// applies that tag via `SUBSYSTEM=="drm", KERNEL=="card*"`. Without a
// `/sys/class/drm/card0` node whose `subsystem` symlink resolves to
// `/sys/class/drm`, udev never sees the GPU, seat0 stays non-graphical, and
// gdm never launches a greeter.
//
// Mirrors the `/sys/class/input` pattern: DRM minors are synthesised from live
// `drv::try_device_add` records whose devtmpfs class is "drm".
//
// Tree:
//   /sys/class/drm/                          (dir of symlinks)
//     cardN        -> ../../devices/virtual/drm/cardN
//     renderD128+N -> ../../devices/virtual/drm/renderD128+N
//                    (only when a DRM driver publishes a real render minor)
//   /sys/devices/virtual/drm/<name>/         (per-minor dir)
//     dev                                     "226:<minor>\n"
//     uevent                                  MAJOR=/MINOR=/DEVNAME=/DEVTYPE=
//     subsystem    -> ../../../class/drm      (so udev reads SUBSYSTEM=drm)

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{mk_mode, DirContext, FileOps, FileType, Ino, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError};

use crate::{make_body_inode, make_symlink_inode, register, DIR_PERM, RW_PERM};

/// DRM char-major (Linux `DRM_MAJOR`).
const DRM_MAJOR: u32 = 226;

#[derive(Clone)]
struct DrmMinor {
    name: String,
    minor: u32,
    devtype: &'static str,
    parent_bus: Option<&'static str>,
    parent_addr: Option<String>,
}

/// Snapshot DRM minors from the authoritative device model.
/// # C: O(devices log devices)
fn drm_minors() -> Vec<DrmMinor> {
    let mut minors = Vec::new();
    for dev in drv::devices() {
        if dev.dev_class != "drm" {
            continue;
        }
        let Some((DRM_MAJOR, minor)) = dev.dev_t else {
            continue;
        };
        let Some(devname) = dev.devname.as_deref() else {
            continue;
        };
        let leaf = devname.rsplit('/').next().unwrap_or(devname);
        minors.push(DrmMinor {
            name: String::from(leaf),
            minor,
            devtype: "drm_minor",
            parent_bus: dev.parent_bus,
            parent_addr: dev.parent_addr.clone(),
        });
    }
    minors.sort_by(|a, b| a.minor.cmp(&b.minor).then_with(|| a.name.cmp(&b.name)));
    minors
}

fn minor_of(name: &str) -> Option<DrmMinor> {
    drm_minors().into_iter().find(|m| m.name == name)
}

fn parent_root_leaf(bus: &str) -> &'static str {
    match bus {
        "pci" => "pci0000:00",
        "virtio" => "virtio",
        "platform" => "platform",
        "drm" => "virtual/drm",
        _ => "platform",
    }
}

fn parent_device_target(minor: &DrmMinor) -> Option<Vec<u8>> {
    Some(alloc::format!(
        "../../../{}/{}",
        parent_root_leaf(minor.parent_bus?),
        minor.parent_addr.as_deref()?,
    )
    .into_bytes())
}

// ---- /sys/class/drm (directory of symlinks) -------------------------------

struct SysClassDrmOps;
impl InodeOps for SysClassDrmOps {
    fn lookup(&self, _inode: &Inode, name: &str) -> KResult<InodeRef> {
        if minor_of(name).is_none() { return Err(VfsError::Enoent); }
        let mut target = String::from("../../devices/virtual/drm/");
        target.push_str(name);
        Ok(make_symlink_inode(target.into_bytes()))
    }
}
impl FileOps for SysClassDrmOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let minors = drm_minors();
        let mut idx = ctx.pos as usize;
        while idx < minors.len() {
            let next = idx as u64 + 1;
            let name = minors[idx].name.as_str();
            let ino = inode.lookup(name).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(name, ino, FileType::Symlink, next) { return Ok(()); }
            idx += 1;
        }
        Ok(())
    }
}
fn make_sys_class_drm_inode() -> InodeRef {
    InodeBuilder::new(0x5104_0001, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(SysClassDrmOps), Arc::new(SysClassDrmOps)).build()
}

// ---- /sys/devices/virtual/drm (directory of device dirs) ------------------

struct SysDevicesVirtualDrmOps;
impl InodeOps for SysDevicesVirtualDrmOps {
    fn lookup(&self, _inode: &Inode, name: &str) -> KResult<InodeRef> {
        let minor = minor_of(name).ok_or(VfsError::Enoent)?;
        Ok(make_drm_device_inode(minor))
    }
}
impl FileOps for SysDevicesVirtualDrmOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let minors = drm_minors();
        let mut idx = ctx.pos as usize;
        while idx < minors.len() {
            let next = idx as u64 + 1;
            let name = minors[idx].name.as_str();
            let ino = inode.lookup(name).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(name, ino, FileType::Directory, next) { return Ok(()); }
            idx += 1;
        }
        Ok(())
    }
}
fn make_sys_devices_virtual_drm_inode() -> InodeRef {
    InodeBuilder::new(0x5104_0002, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(SysDevicesVirtualDrmOps), Arc::new(SysDevicesVirtualDrmOps)).build()
}

// ---- /sys/devices/virtual/drm/<name> (per-minor dir) ----------------------

struct DrmDeviceData { minor: DrmMinor }

struct DrmDeviceOps;
impl InodeOps for DrmDeviceOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<DrmDeviceData>().ok_or(VfsError::Einval)?;
        match name {
            "dev" => {
                let body = alloc::format!("{}:{}\n", DRM_MAJOR, d.minor.minor).into_bytes();
                Ok(make_body_inode(body, 0x5104_2000 + d.minor.minor as Ino))
            }
            "uevent" => Ok(make_drm_uevent_inode(
                d.minor.name.clone(),
                d.minor.minor,
                d.minor.devtype,
            )),
            // `subsystem` symlink is what makes udev read SUBSYSTEM=="drm".
            "subsystem" => Ok(make_symlink_inode(b"../../../class/drm".to_vec())),
            "device" => Ok(make_symlink_inode(
                parent_device_target(&d.minor).ok_or(VfsError::Enoent)?,
            )),
            _ => Err(VfsError::Enoent),
        }
    }
}
impl FileOps for DrmDeviceOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        const BASE_ENTRIES: &[(&str, FileType)] = &[
            ("dev", FileType::Regular), ("uevent", FileType::Regular),
            ("subsystem", FileType::Symlink),
        ];
        let d = inode.private::<DrmDeviceData>().ok_or(VfsError::Einval)?;
        let mut entries: Vec<(&str, FileType)> = BASE_ENTRIES.to_vec();
        if parent_device_target(&d.minor).is_some() {
            entries.push(("device", FileType::Symlink));
        }
        let mut idx = ctx.pos as usize;
        while idx < entries.len() {
            let next = idx as u64 + 1;
            let (nm, ft) = entries[idx];
            let ino = inode.lookup(nm).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(nm, ino, ft, next) { return Ok(()); }
            idx += 1;
        }
        Ok(())
    }
}
fn make_drm_device_inode(minor: DrmMinor) -> InodeRef {
    InodeBuilder::new(0x5104_1000 + minor.minor as Ino, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(DrmDeviceOps), Arc::new(DrmDeviceOps))
        .private(Arc::new(DrmDeviceData { minor }))
        .build()
}

// ---- /sys/devices/virtual/drm/<name>/uevent (rw attr) ---------------------

struct DrmUeventData { name: String, minor: u32, devtype: &'static str }

struct DrmUeventFileOps;
impl FileOps for DrmUeventFileOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<DrmUeventData>().ok_or(VfsError::Einval)?;
        let body = alloc::format!(
            "MAJOR={}\nMINOR={}\nDEVNAME=dri/{}\nDEVTYPE={}\n",
            DRM_MAJOR, d.minor, d.name, d.devtype).into_bytes();
        Ok(crate::read_window(&body, off, buf))
    }
    fn write(&self, inode: &Inode, _o: u64, b: &[u8]) -> KResult<usize> {
        let d = inode.private::<DrmUeventData>().ok_or(VfsError::Einval)?;
        let devpath = alloc::format!("/devices/virtual/drm/{}", d.name);
        let devname = alloc::format!("DEVNAME=dri/{}", d.name);
        let maj = alloc::format!("MAJOR={}", DRM_MAJOR);
        let min = alloc::format!("MINOR={}", d.minor);
        let dtype = alloc::format!("DEVTYPE={}", d.devtype);
        ::netlink::emit_uevent_with_env(
            crate::uevent_action(b), &devpath, "drm", &[&devname, &maj, &min, &dtype]);
        Ok(b.len())
    }
}
fn make_drm_uevent_inode(name: String, minor: u32, devtype: &'static str) -> InodeRef {
    InodeBuilder::new(0x5104_3000 + minor as Ino, mk_mode(FileType::Regular, RW_PERM),
        vfs::default_inode_ops(), Arc::new(DrmUeventFileOps))
        .private(Arc::new(DrmUeventData { name, minor, devtype }))
        .build()
}

/// Register the `/sys/class/drm` + `/sys/devices/virtual/drm` trees.
/// # C: O(1)
pub fn init() {
    register("/sys/class/drm", make_sys_class_drm_inode());
    register("/sys/devices/virtual/drm", make_sys_devices_virtual_drm_inode());
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;

    fn drm_dev(addr: &str, name: &str, minor: u32) -> Arc<drv::Device> {
        drv::try_device_add(Arc::new(
            drv::Device::new("drm", String::from(addr), 0, 0, 0)
                .with_devnode("drm", String::from(name), Some((DRM_MAJOR, minor))),
        ))
        .expect("test device registration")
    }

    #[test]
    fn drm_class_enumerates_live_model_devices() {
        let card = drm_dev("sysfs-drm-card42", "dri/card42", 42);
        let render = drm_dev("sysfs-drm-render170", "dri/renderD170", 170);

        let minors = drm_minors();
        assert!(minors.iter().any(|m| m.name == "card42" && m.minor == 42));
        assert!(minors.iter().any(|m| m.name == "renderD170" && m.minor == 170));

        let class = make_sys_class_drm_inode();
        assert!(class.lookup("card42").is_ok());
        assert!(class.lookup("renderD170").is_ok());
        assert_eq!(class.lookup("card43").err(), Some(VfsError::Enoent));

        let devices = make_sys_devices_virtual_drm_inode();
        let card_dir = devices.lookup("card42").expect("card42 sysfs dir");
        let dev_attr = card_dir.lookup("dev").expect("card42 dev attr");
        let mut buf = [0u8; 16];
        let n = dev_attr.read(0, &mut buf).expect("read dev attr");
        assert_eq!(&buf[..n], b"226:42\n");

        drv::device_del(&render);
        drv::device_del(&card);
    }

    #[test]
    fn drm_class_device_links_to_model_parent_when_present() {
        let parent = Arc::new(drv::Device::new(
            "virtio",
            String::from("virtio-gpu-parent0"),
            0x1af4,
            16,
            0,
        ));
        drv::try_device_add(Arc::clone(&parent)).expect("test parent registration");
        let card = drv::try_device_add(Arc::new(
            drv::Device::new("drm", String::from("sysfs-drm-card43"), 0, 0, 0)
                .with_parent("virtio", String::from("virtio-gpu-parent0"))
                .with_devnode("drm", String::from("dri/card43"), Some((DRM_MAJOR, 43))),
        ))
        .expect("test drm registration");

        let devices = make_sys_devices_virtual_drm_inode();
        let card_dir = devices.lookup("card43").expect("card43 sysfs dir");
        let device = card_dir.lookup("device").expect("parent device link");
        assert_eq!(
            device.readlink().expect("readlink"),
            b"../../../virtio/virtio-gpu-parent0".to_vec()
        );

        drv::device_del(&card);
        drv::device_del(&parent);
        assert_eq!(devices.lookup("card43").err(), Some(VfsError::Enoent));
    }
}
