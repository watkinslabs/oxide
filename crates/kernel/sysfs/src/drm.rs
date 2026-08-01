// `/sys/class/drm` sysfs tree - the udev seat-discovery prerequisite for a
// graphical login. systemd-logind marks a seat `CanGraphical=yes` only when a
// DRM device on it carries udev's `master-of-seat` tag. Without a
// `/sys/class/drm/card0` node whose `subsystem` symlink resolves to
// `/sys/class/drm`, udev never sees the GPU, seat0 stays non-graphical, and
// gdm never launches a greeter.
//
// Mirrors the `/sys/class/input` pattern: DRM minors are synthesised from live
// `drv::try_device_add` records whose devtmpfs class is "drm".
//
// Tree:
//   /sys/class/drm/                          (dir of symlinks)
//     cardN        -> ../../devices/<parent>/drm/cardN
//                  -> ../../devices/virtual/drm/cardN when parentless
//     renderD128+N -> ../../devices/<parent>/drm/renderD128+N
//   /sys/devices/virtual/drm/<name>/         (per-minor dir)
//     dev                                     "226:<minor>\n"
//     uevent                                  MAJOR=/MINOR=/DEVNAME=/DEVTYPE=
//     subsystem    -> <../ × dir-depth>class/drm  (so udev reads SUBSYSTEM=drm)
//   /sys/devices/<parent>/<addr>/drm/<name>/ (parented DRM minors)
//     dev, uevent, subsystem, device          Linux class-device layout

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{mk_mode, DirContext, FileOps, FileType, Ino, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError};

use crate::{make_body_inode, make_symlink_inode, register, DIR_PERM, RW_PERM};

#[derive(Clone)]
struct DrmMinor {
    name: String,
    devname: String,
    minor: u32,
    devtype: &'static str,
    device: Arc<drv::Device>,
}

/// Snapshot DRM minors from the authoritative device model.
/// # C: O(devices log devices)
fn drm_minors() -> Vec<DrmMinor> {
    let mut minors = Vec::new();
    for dev in drv::devices() {
        if dev.dev_class != "drm" {
            continue;
        }
        let Some((::drm::DRM_MAJOR, minor)) = dev.dev_t else {
            continue;
        };
        let Some(devname) = dev.devname.as_ref() else {
            continue;
        };
        let Some(canon) = drv::device_canon_exact(&dev) else {
            continue;
        };
        let Some(name) = canon.rsplit('/').next().filter(|name| !name.is_empty()) else {
            continue;
        };
        if devname.rsplit('/').next() != Some(name) { continue; }
        minors.push(DrmMinor {
            name: String::from(name),
            devname: devname.clone(),
            minor,
            devtype: "drm_minor",
            device: dev,
        });
    }
    minors.sort_unstable_by(|a, b| a.minor.cmp(&b.minor).then_with(|| a.name.cmp(&b.name)));
    minors
}

fn minor_of(name: &str) -> Option<DrmMinor> {
    drm_minors().into_iter().find(|m| m.name == name)
}

fn unparented_minors() -> Vec<DrmMinor> {
    drm_minors()
        .into_iter()
        .filter(|m| m.device.parent().is_none())
        .collect()
}

fn parented_minors(parent_bus: &str, parent_addr: &str) -> Vec<DrmMinor> {
    drm_minors()
        .into_iter()
        .filter(|m| m.device.parent() == Some((parent_bus, parent_addr)))
        .collect()
}

fn minor_of_parent(parent_bus: &str, parent_addr: &str, name: &str) -> Option<DrmMinor> {
    parented_minors(parent_bus, parent_addr)
        .into_iter()
        .find(|m| m.name == name)
}

fn drm_device_path(minor: &DrmMinor) -> Option<String> {
    drv::device_canon_exact(&minor.device)
}

/// The leading-slash `/sys` DEVPATH for a DRM card `drv::Device` (bus `drm`),
/// matching its synthesised sysfs directory so udevd reads the right `uevent`.
/// # C: O(devices)
pub(crate) fn card_devpath(dev: &drv::Device) -> Option<String> {
    if dev.dev_class != "drm" {
        return None;
    }
    let (major, minor_num) = dev.dev_t?;
    if major != ::drm::DRM_MAJOR {
        return None;
    }
    let minor = drm_minors().into_iter()
        .find(|m| m.minor == minor_num && core::ptr::eq(m.device.as_ref(), dev))?;
    Some(alloc::format!("/{}", drm_device_path(&minor)?))
}

pub(crate) fn dev_index_target(dev: &drv::Device) -> Option<Vec<u8>> {
    if dev.dev_class != "drm" {
        return None;
    }
    let Some((::drm::DRM_MAJOR, minor)) = dev.dev_t else {
        return None;
    };
    let minor = drm_minors().into_iter()
        .find(|m| m.minor == minor && core::ptr::eq(m.device.as_ref(), dev))?;
    Some(alloc::format!("../../{}", drm_device_path(&minor)?).into_bytes())
}

pub(crate) fn has_parented_minors(parent_bus: &str, parent_addr: &str) -> bool {
    !parented_minors(parent_bus, parent_addr).is_empty()
}

fn device_link_target(minor: &DrmMinor) -> Option<Vec<u8>> {
    if minor.device.parent().is_some() {
        Some(b"../..".to_vec())
    } else {
        None
    }
}

fn subsystem_target(minor: &DrmMinor) -> Option<Vec<u8>> {
    // The `subsystem` symlink lives inside the card's own directory, so it must
    // climb `depth(card dir)` levels to reach `/sys` before descending into
    // `class/drm`. A fixed `../` count breaks the moment the card nests deeper —
    // which the path_id fix did by parenting virtio-gpu under its PCI transport
    // (`devices/pci0000:00/<bdf>/virtioN/drm/cardN`, depth 6, not the old flat
    // depth 4). A non-resolving `subsystem` link makes udev/sd-device fail to
    // classify the device (`sd_device_get_subsystem`), so logind refuses
    // `TakeDevice` with ENODEV and mutter reports "No GPUs found". Compute the
    // depth dynamically, exactly as the generic bus device links do
    // (`bus::ups_prefix`). # C: O(depth)
    Some(alloc::format!(
        "{}class/drm",
        crate::bus::ups_prefix(&drm_device_path(minor)?),
    ).into_bytes())
}

// ---- /sys/class/drm (directory of symlinks) -------------------------------

struct SysClassDrmOps;
impl InodeOps for SysClassDrmOps {
    fn lookup(&self, _inode: &Inode, name: &str) -> KResult<InodeRef> {
        let minor = minor_of(name).ok_or(VfsError::Enoent)?;
        Ok(make_symlink_inode(
            alloc::format!("../../{}", drm_device_path(&minor).ok_or(VfsError::Enoent)?)
                .into_bytes(),
        ))
    }
}
impl FileOps for SysClassDrmOps {
    /// kernfs / procfs attributes always install a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let minors: Vec<DrmMinor> = drm_minors().into_iter()
            .filter(|minor| drm_device_path(minor).is_some())
            .collect();
        crate::readdir::emit_names(inode, ctx, minors.iter().map(|m| m.name.as_str()),
            FileType::Symlink)
    }
}
fn make_sys_class_drm_inode() -> InodeRef {
    InodeBuilder::new(crate::ids::DRM_VIRT, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(SysClassDrmOps), Arc::new(SysClassDrmOps)).build()
}

// ---- /sys/devices/virtual/drm (directory of device dirs) ------------------

struct SysDevicesVirtualDrmOps;
impl InodeOps for SysDevicesVirtualDrmOps {
    fn lookup(&self, _inode: &Inode, name: &str) -> KResult<InodeRef> {
        let minor = unparented_minors()
            .into_iter()
            .find(|m| m.name == name)
            .ok_or(VfsError::Enoent)?;
        Ok(make_drm_device_inode(minor))
    }
}
impl FileOps for SysDevicesVirtualDrmOps {
    /// kernfs / procfs attributes always install a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let minors = unparented_minors();
        crate::readdir::emit_names(inode, ctx, minors.iter().map(|m| m.name.as_str()),
            FileType::Directory)
    }
}
fn make_sys_devices_virtual_drm_inode() -> InodeRef {
    InodeBuilder::new(crate::ids::DRM_CLASS, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(SysDevicesVirtualDrmOps), Arc::new(SysDevicesVirtualDrmOps)).build()
}

// ---- /sys/devices/<parent>/<addr>/drm (parented DRM minor directory) -------

struct ParentDrmData {
    parent: Arc<drv::Device>,
}

struct ParentDrmOps;
impl InodeOps for ParentDrmOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<ParentDrmData>().ok_or(VfsError::Einval)?;
        drv::device_canon_exact(&d.parent).ok_or(VfsError::Enoent)?;
        let minor = minor_of_parent(d.parent.bus, &d.parent.addr, name)
            .ok_or(VfsError::Enoent)?;
        Ok(make_drm_device_inode(minor))
    }
}
impl FileOps for ParentDrmOps {
    /// kernfs / procfs attributes always install a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let d = inode.private::<ParentDrmData>().ok_or(VfsError::Einval)?;
        drv::device_canon_exact(&d.parent).ok_or(VfsError::Enoent)?;
        let minors = parented_minors(d.parent.bus, &d.parent.addr);
        crate::readdir::emit_names(inode, ctx, minors.iter().map(|m| m.name.as_str()),
            FileType::Directory)
    }
}

pub(crate) fn make_parent_drm_inode(parent: Arc<drv::Device>) -> InodeRef {
    InodeBuilder::new(crate::ids::DRM_ROOT, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(ParentDrmOps), Arc::new(ParentDrmOps))
        .private(Arc::new(ParentDrmData { parent }))
        .build()
}

// ---- /sys/devices/virtual/drm/<name> (per-minor dir) ----------------------

struct DrmDeviceData { minor: DrmMinor }

struct DrmDeviceOps;
impl InodeOps for DrmDeviceOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<DrmDeviceData>().ok_or(VfsError::Einval)?;
        drm_device_path(&d.minor).ok_or(VfsError::Enoent)?;
        match name {
            "dev" => {
                let body =
                    alloc::format!("{}:{}\n", ::drm::DRM_MAJOR, d.minor.minor).into_bytes();
                Ok(make_body_inode(body, crate::ids::DRM_ATTR + d.minor.minor as Ino))
            }
            "uevent" => Ok(make_drm_uevent_inode(d.minor.clone())),
            // `subsystem` symlink is what makes udev read SUBSYSTEM=="drm".
            "subsystem" => Ok(make_symlink_inode(
                subsystem_target(&d.minor).ok_or(VfsError::Enoent)?,
            )),
            "device" => Ok(make_symlink_inode(
                device_link_target(&d.minor).ok_or(VfsError::Enoent)?,
            )),
            _ => Err(VfsError::Enoent),
        }
    }
}
impl FileOps for DrmDeviceOps {
    /// kernfs / procfs attributes always install a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        // `device` is a symlink only when the minor has a model parent; the
        // lookup that resolves its ino enforces that.
        const ENTRIES: &[(&str, FileType)] = &[
            ("dev", FileType::Regular), ("uevent", FileType::Regular),
            ("subsystem", FileType::Symlink), ("device", FileType::Symlink),
        ];
        let d = inode.private::<DrmDeviceData>().ok_or(VfsError::Einval)?;
        drm_device_path(&d.minor).ok_or(VfsError::Enoent)?;
        crate::readdir::emit_table(inode, ctx, ENTRIES)
    }
}
fn make_drm_device_inode(minor: DrmMinor) -> InodeRef {
    InodeBuilder::new(crate::ids::DRM_DIR + minor.minor as Ino, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(DrmDeviceOps), Arc::new(DrmDeviceOps))
        .private(Arc::new(DrmDeviceData { minor }))
        .build()
}

// ---- /sys/devices/virtual/drm/<name>/uevent (rw attr) ---------------------

struct DrmUeventData { minor: DrmMinor }
impl DrmUeventData {
    fn devpath(&self) -> Option<String> {
        Some(alloc::format!("/{}", drm_device_path(&self.minor)?))
    }
}

struct DrmUeventFileOps;
impl FileOps for DrmUeventFileOps {
    /// kernfs / procfs attributes always install a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<DrmUeventData>().ok_or(VfsError::Einval)?;
        d.devpath().ok_or(VfsError::Enoent)?;
        let body = alloc::format!(
            "MAJOR={}\nMINOR={}\nDEVNAME={}\nDEVTYPE={}\n",
            ::drm::DRM_MAJOR, d.minor.minor, d.minor.devname, d.minor.devtype).into_bytes();
        Ok(crate::read_window(&body, off, buf))
    }
    fn write(&self, inode: &Inode, _o: u64, b: &[u8]) -> KResult<usize> {
        let d = inode.private::<DrmUeventData>().ok_or(VfsError::Einval)?;
        #[cfg(feature = "debug-udevdb")]
        {
            klog::write_raw(b"[DRM-UEVENT write name=");
            klog::write_raw(d.minor.name.as_bytes());
            klog::write_raw(b" minor=");
            klog::write_dec_u64(d.minor.minor as u64);
            klog::write_raw(b" bytes=");
            klog::write_dec_u64(b.len() as u64);
            klog::write_raw(b" action=");
            klog::write_raw(b);
            klog::write_raw(b"\\n");
        }
        let devpath = d.devpath().ok_or(VfsError::Enoent)?;
        let devname = alloc::format!("DEVNAME={}", d.minor.devname);
        let maj = alloc::format!("MAJOR={}", ::drm::DRM_MAJOR);
        let min = alloc::format!("MINOR={}", d.minor.minor);
        let dtype = alloc::format!("DEVTYPE={}", d.minor.devtype);
        ::netlink::emit_uevent_with_env(
            crate::uevent_action(b), &devpath, "drm", &[&devname, &maj, &min, &dtype]);
        Ok(b.len())
    }
}
fn make_drm_uevent_inode(minor: DrmMinor) -> InodeRef {
    InodeBuilder::new(crate::ids::DRM_RW_ATTR + minor.minor as Ino, mk_mode(FileType::Regular, RW_PERM),
        crate::kobject::attr_inode_ops(), Arc::new(DrmUeventFileOps))
        .private(Arc::new(DrmUeventData { minor }))
        .build()
}

/// Register the `/sys/class/drm` + `/sys/devices/virtual/drm` trees.
/// # C: O(1)
pub fn init() {
    register("/sys/class/drm", make_sys_class_drm_inode());
    register("/sys/devices/virtual/drm", make_sys_devices_virtual_drm_inode());
}

#[cfg(test)]
pub(crate) fn make_sys_class_drm_inode_for_test() -> InodeRef {
    make_sys_class_drm_inode()
}

#[cfg(test)]
mod tests;
