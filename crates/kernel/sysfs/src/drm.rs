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

fn unparented_minors() -> Vec<DrmMinor> {
    drm_minors()
        .into_iter()
        .filter(|m| m.parent_bus.is_none() || m.parent_addr.is_none())
        .collect()
}

fn parented_minors(parent_bus: &str, parent_addr: &str) -> Vec<DrmMinor> {
    drm_minors()
        .into_iter()
        .filter(|m| {
            m.parent_bus == Some(parent_bus)
                && m.parent_addr.as_deref() == Some(parent_addr)
        })
        .collect()
}

fn minor_of_parent(parent_bus: &str, parent_addr: &str, name: &str) -> Option<DrmMinor> {
    parented_minors(parent_bus, parent_addr)
        .into_iter()
        .find(|m| m.name == name)
}

fn drm_device_path(minor: &DrmMinor) -> String {
    if let (Some(parent_bus), Some(parent_addr)) =
        (minor.parent_bus, minor.parent_addr.as_deref())
    {
        // Nest the card under its parent's canonical sysfs directory, so a
        // PCI-backed virtio-gpu lands at `devices/pci0000:00/<bdf>/virtioN/drm/
        // cardN`. udev's `path_id` builtin walks the card's parent chain and
        // needs to reach the PCI transport (it sets `supported_parent`); a flat
        // `devices/virtio/virtioN` parent has no PCI ancestor and path_id fails
        // ENOENT (empty ID_PATH), which breaks `71-seat.rules`.
        alloc::format!("{}/drm/{}", crate::bus::dev_canon(parent_bus, parent_addr), minor.name)
    } else {
        alloc::format!("devices/virtual/drm/{}", minor.name)
    }
}

/// The leading-slash `/sys` DEVPATH for a DRM card `drv::Device` (bus `drm`),
/// matching its synthesised sysfs directory so udevd reads the right `uevent`.
/// # C: O(devices)
pub(crate) fn card_devpath(dev: &drv::Device) -> Option<String> {
    if dev.dev_class != "drm" {
        return None;
    }
    let (major, minor_num) = dev.dev_t?;
    if major != DRM_MAJOR {
        return None;
    }
    let minor = drm_minors().into_iter().find(|m| m.minor == minor_num)?;
    Some(alloc::format!("/{}", drm_device_path(&minor)))
}

pub(crate) fn dev_index_target(dev: &drv::Device) -> Option<Vec<u8>> {
    if dev.dev_class != "drm" {
        return None;
    }
    let Some((DRM_MAJOR, minor)) = dev.dev_t else {
        return None;
    };
    let minor = drm_minors().into_iter().find(|m| m.minor == minor)?;
    Some(alloc::format!("../../{}", drm_device_path(&minor)).into_bytes())
}

pub(crate) fn has_parented_minors(parent_bus: &str, parent_addr: &str) -> bool {
    !parented_minors(parent_bus, parent_addr).is_empty()
}

fn device_link_target(minor: &DrmMinor) -> Option<Vec<u8>> {
    if minor.parent_bus.is_some() && minor.parent_addr.is_some() {
        Some(b"../..".to_vec())
    } else {
        None
    }
}

fn subsystem_target(minor: &DrmMinor) -> Vec<u8> {
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
    alloc::format!("{}class/drm", crate::bus::ups_prefix(&drm_device_path(minor))).into_bytes()
}

// ---- /sys/class/drm (directory of symlinks) -------------------------------

struct SysClassDrmOps;
impl InodeOps for SysClassDrmOps {
    fn lookup(&self, _inode: &Inode, name: &str) -> KResult<InodeRef> {
        let minor = minor_of(name).ok_or(VfsError::Enoent)?;
        Ok(make_symlink_inode(
            alloc::format!("../../{}", drm_device_path(&minor)).into_bytes(),
        ))
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
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let minors = unparented_minors();
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
    InodeBuilder::new(crate::ids::DRM_CLASS, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(SysDevicesVirtualDrmOps), Arc::new(SysDevicesVirtualDrmOps)).build()
}

// ---- /sys/devices/<parent>/<addr>/drm (parented DRM minor directory) -------

struct ParentDrmData {
    parent_bus: &'static str,
    parent_addr: String,
}

struct ParentDrmOps;
impl InodeOps for ParentDrmOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<ParentDrmData>().ok_or(VfsError::Einval)?;
        let minor = minor_of_parent(d.parent_bus, &d.parent_addr, name).ok_or(VfsError::Enoent)?;
        Ok(make_drm_device_inode(minor))
    }
}
impl FileOps for ParentDrmOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let d = inode.private::<ParentDrmData>().ok_or(VfsError::Einval)?;
        let minors = parented_minors(d.parent_bus, &d.parent_addr);
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

pub(crate) fn make_parent_drm_inode(parent_bus: &'static str, parent_addr: String) -> InodeRef {
    InodeBuilder::new(crate::ids::DRM_ROOT, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(ParentDrmOps), Arc::new(ParentDrmOps))
        .private(Arc::new(ParentDrmData { parent_bus, parent_addr }))
        .build()
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
                Ok(make_body_inode(body, crate::ids::DRM_ATTR + d.minor.minor as Ino))
            }
            "uevent" => Ok(make_drm_uevent_inode(
                d.minor.name.clone(),
                d.minor.minor,
                d.minor.devtype,
            )),
            // `subsystem` symlink is what makes udev read SUBSYSTEM=="drm".
            "subsystem" => Ok(make_symlink_inode(subsystem_target(&d.minor))),
            "device" => Ok(make_symlink_inode(
                device_link_target(&d.minor).ok_or(VfsError::Enoent)?,
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
        if device_link_target(&d.minor).is_some() {
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
    InodeBuilder::new(crate::ids::DRM_DIR + minor.minor as Ino, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(DrmDeviceOps), Arc::new(DrmDeviceOps))
        .private(Arc::new(DrmDeviceData { minor }))
        .build()
}

// ---- /sys/devices/virtual/drm/<name>/uevent (rw attr) ---------------------

struct DrmUeventData { name: String, minor: u32, devtype: &'static str }
impl DrmUeventData {
    fn devpath(&self) -> String {
        let minor = drm_minors()
            .into_iter()
            .find(|m| m.name == self.name && m.minor == self.minor)
            .unwrap_or(DrmMinor {
                name: self.name.clone(),
                minor: self.minor,
                devtype: self.devtype,
                parent_bus: None,
                parent_addr: None,
            });
        alloc::format!("/{}", drm_device_path(&minor))
    }
}

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
        let devpath = d.devpath();
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
    InodeBuilder::new(crate::ids::DRM_RW_ATTR + minor as Ino, mk_mode(FileType::Regular, RW_PERM),
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
pub(crate) fn make_sys_class_drm_inode_for_test() -> InodeRef {
    make_sys_class_drm_inode()
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
        let render = drv::try_device_add(Arc::new(
            drv::Device::new("drm", String::from("sysfs-drm-render171"), 0, 0, 0)
                .with_parent("virtio", String::from("virtio-gpu-parent0"))
                .with_devnode("drm", String::from("dri/renderD171"), Some((DRM_MAJOR, 171))),
        ))
        .expect("test render registration");

        let class = make_sys_class_drm_inode();
        let class_link = class.lookup("card43").expect("card43 class link");
        assert_eq!(
            class_link.readlink().expect("readlink"),
            b"../../devices/virtio/virtio-gpu-parent0/drm/card43".to_vec()
        );
        assert_eq!(
            class.lookup("renderD171").expect("render class link").readlink().expect("readlink"),
            b"../../devices/virtio/virtio-gpu-parent0/drm/renderD171".to_vec()
        );

        let devices = make_sys_devices_virtual_drm_inode();
        assert_eq!(devices.lookup("card43").err(), Some(VfsError::Enoent));

        let parent_drm = make_parent_drm_inode("virtio", String::from("virtio-gpu-parent0"));
        let card_dir = parent_drm.lookup("card43").expect("card43 parented sysfs dir");
        assert!(parent_drm.lookup("renderD171").is_ok());
        let device = card_dir.lookup("device").expect("parent device link");
        assert_eq!(device.readlink().expect("readlink"), b"../..".to_vec());
        let subsystem = card_dir.lookup("subsystem").expect("subsystem link");
        // card43 dir = devices/virtio/virtio-gpu-parent0/drm/card43 (depth 5), so
        // the subsystem link climbs 5 levels to /sys then into class/drm.
        assert_eq!(
            subsystem.readlink().expect("readlink"),
            b"../../../../../class/drm".to_vec()
        );

        drv::device_del(&render);
        drv::device_del(&card);
        drv::device_del(&parent);
        assert_eq!(parent_drm.lookup("card43").err(), Some(VfsError::Enoent));
    }
}
