// `/sys/class/drm` sysfs tree — the udev seat-discovery prerequisite for a
// graphical login. systemd-logind marks a seat `CanGraphical=yes` only when a
// DRM device on it carries udev's `master-of-seat` tag; udev's `71-seat.rules`
// applies that tag via `SUBSYSTEM=="drm", KERNEL=="card*"`. Without a
// `/sys/class/drm/cardN` node whose `subsystem` symlink resolves to
// `/sys/class/drm`, udev never sees the GPU, seat0 stays non-graphical, and
// gdm never launches a greeter.
//
// Mirrors the `/sys/class/tty` symlink-dir pattern (lib.rs). The real KMS
// device nodes are /dev/dri/cardN (226:N), minted by drm::node::register.
//
// Tree:
//   /sys/class/drm/                          (dir of symlinks)
//     cardN        -> ../../devices/virtual/drm/cardN
//     renderD128+N -> ../../devices/virtual/drm/renderD128+N
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

struct DrmMinor {
    name: String,
    minor: u32,
    devtype: &'static str,
}

/// Snapshot DRM class devices from the authoritative driver model.
/// # C: O(devices)
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
        let Some(name) = devname.strip_prefix("dri/") else {
            continue;
        };
        if !(name.starts_with("card") || name.starts_with("renderD")) {
            continue;
        }
        minors.push(DrmMinor { name: String::from(name), minor, devtype: "drm_minor" });
    }
    minors.sort_by(|a, b| a.minor.cmp(&b.minor));
    minors
}

fn minor_of(name: &str) -> Option<(u32, &'static str)> {
    drm_minors()
        .into_iter()
        .find(|minor| minor.name == name)
        .map(|minor| (minor.minor, minor.devtype))
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
        let (minor, _t) = minor_of(name).ok_or(VfsError::Enoent)?;
        Ok(make_drm_device_inode(String::from(name), minor))
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

struct DrmDeviceData { name: String, minor: u32 }

struct DrmDeviceOps;
impl InodeOps for DrmDeviceOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<DrmDeviceData>().ok_or(VfsError::Einval)?;
        match name {
            "dev" => {
                let body = alloc::format!("{}:{}\n", DRM_MAJOR, d.minor).into_bytes();
                Ok(make_body_inode(body, 0x5104_2000 + d.minor as Ino))
            }
            "uevent" => Ok(make_drm_uevent_inode(d.name.clone(), d.minor)),
            // `subsystem` symlink is what makes udev read SUBSYSTEM=="drm".
            "subsystem" => Ok(make_symlink_inode(b"../../../class/drm".to_vec())),
            _ => Err(VfsError::Enoent),
        }
    }
}
impl FileOps for DrmDeviceOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        const ENTRIES: &[(&str, FileType)] = &[
            ("dev", FileType::Regular), ("uevent", FileType::Regular),
            ("subsystem", FileType::Symlink),
        ];
        let mut idx = ctx.pos as usize;
        while idx < ENTRIES.len() {
            let next = idx as u64 + 1;
            let (nm, ft) = ENTRIES[idx];
            let ino = inode.lookup(nm).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(nm, ino, ft, next) { return Ok(()); }
            idx += 1;
        }
        Ok(())
    }
}
fn make_drm_device_inode(name: String, minor: u32) -> InodeRef {
    InodeBuilder::new(0x5104_1000 + minor as Ino, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(DrmDeviceOps), Arc::new(DrmDeviceOps))
        .private(Arc::new(DrmDeviceData { name, minor }))
        .build()
}

// ---- /sys/devices/virtual/drm/<name>/uevent (rw attr) ---------------------

struct DrmUeventData { name: String, minor: u32 }

struct DrmUeventFileOps;
impl FileOps for DrmUeventFileOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<DrmUeventData>().ok_or(VfsError::Einval)?;
        let devtype = minor_of(&d.name).map(|(_, t)| t).unwrap_or("drm_minor");
        let body = alloc::format!(
            "MAJOR={}\nMINOR={}\nDEVNAME=dri/{}\nDEVTYPE={}\n",
            DRM_MAJOR, d.minor, d.name, devtype).into_bytes();
        Ok(crate::read_window(&body, off, buf))
    }
    fn write(&self, inode: &Inode, _o: u64, b: &[u8]) -> KResult<usize> {
        let d = inode.private::<DrmUeventData>().ok_or(VfsError::Einval)?;
        let devtype = minor_of(&d.name).map(|(_, t)| t).unwrap_or("drm_minor");
        let devpath = alloc::format!("/devices/virtual/drm/{}", d.name);
        let devname = alloc::format!("DEVNAME=dri/{}", d.name);
        let maj = alloc::format!("MAJOR={}", DRM_MAJOR);
        let min = alloc::format!("MINOR={}", d.minor);
        let dtype = alloc::format!("DEVTYPE={}", devtype);
        ::netlink::emit_uevent_with_env(
            crate::uevent_action(b), &devpath, "drm", &[&devname, &maj, &min, &dtype]);
        Ok(b.len())
    }
}
fn make_drm_uevent_inode(name: String, minor: u32) -> InodeRef {
    InodeBuilder::new(0x5104_3000 + minor as Ino, mk_mode(FileType::Regular, RW_PERM),
        vfs::default_inode_ops(), Arc::new(DrmUeventFileOps))
        .private(Arc::new(DrmUeventData { name, minor }))
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

    #[test]
    fn drm_minors_follow_model_devices() {
        let card = drv::device_add(Arc::new(
            drv::Device::new("drm", String::from("dri/card7"), 0, 0, 0)
                .with_devnode("drm", String::from("dri/card7"), Some((226, 7))),
        ));
        let render = drv::device_add(Arc::new(
            drv::Device::new("drm", String::from("dri/renderD135"), 0, 0, 0)
                .with_devnode("drm", String::from("dri/renderD135"), Some((226, 135))),
        ));

        let minors = drm_minors();
        assert!(minors.iter().any(|m| m.name == "card7" && m.minor == 7));
        assert!(minors.iter().any(|m| m.name == "renderD135" && m.minor == 135));
        assert_eq!(minor_of("card7"), Some((7, "drm_minor")));
        assert_eq!(minor_of("renderD135"), Some((135, "drm_minor")));

        drv::device_del(&render);
        drv::device_del(&card);
    }
}
