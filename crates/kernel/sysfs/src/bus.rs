// sysfs device-tree publication (drivers-plan D1a). Synthesises the
// Linux-visible `/sys/bus/*` + `/sys/devices/*` tree from the live
// `drv` device/driver registries. Everything is dynamic: dir inodes
// readdir/lookup the registry on each access, so a device added after boot
// still appears (no eager sysfs key writes per device). Mirrors the
// `/sys/class/net` pattern.
//
// Tree (canonical real dirs under /sys/devices; the bus entries are
// Linux-style symlinks into them):
//   /sys/devices/pci0000:00/<addr>/{vendor,device,class,resource,modalias,driver_override,uevent}
//   /sys/devices/pci0000:00/<addr>/driver -> ../../../bus/pci/drivers/<name>  (bound)
//   /sys/devices/pci0000:00/<addr>/subsystem -> ../../../bus/pci
//   /sys/devices/<root>/<addr>/parent -> ../../<parent-root>/<parent-addr> (children)
//   /sys/bus/pci/devices/<addr>     -> ../../../devices/pci0000:00/<addr>
//   /sys/bus/pci/drivers/<name>/
//   /sys/devices/virtio/<addr>/{device,modalias,driver_override,uevent}
//   /sys/devices/virtio/<addr>/subsystem -> ../../../bus/virtio
//   /sys/bus/virtio/devices/<addr> -> ../../../devices/virtio/<addr>
//   /sys/bus/virtio/drivers/<name>/
//   /sys/devices/platform/<addr>/{modalias,driver_override,uevent}
//   /sys/bus/platform/devices/<addr> -> ../../../devices/platform/<addr>
//   /sys/bus/platform/drivers/<name>/
//   /sys/dev/{char,block}/<major>:<minor> -> ../../devices/<root>/<addr>

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{mk_mode, DirContext, FileOps, FileType, Ino, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError};

use crate::kobject::{make_attr_inode, Attribute, AttrGroup, SysfsOps};
use crate::{make_symlink_inode_ino, DIR_PERM, RO_PERM, RW_PERM};

const INO_BUS_PCI_DEV:   Ino = 0x5102_0001;
const INO_BUS_PCI_DRV:   Ino = 0x5102_0002;
const INO_BUS_VIRT_DEV:  Ino = 0x5102_0003;
const INO_BUS_VIRT_DRV:  Ino = 0x5102_0004;
const INO_DEV_PCI_ROOT:  Ino = 0x5102_0005;
const INO_DEV_VIRT_ROOT: Ino = 0x5102_0006;
const INO_BUS_PLATFORM_DEV: Ino = 0x5102_0007;
const INO_BUS_PLATFORM_DRV: Ino = 0x5102_0008;
const INO_DEV_PLATFORM_ROOT: Ino = 0x5102_0009;
const INO_SYS_DEV_CHAR:  Ino = 0x5102_000a;
const INO_SYS_DEV_BLOCK: Ino = 0x5102_000b;
const INO_SYMLINK:       Ino = 0x5102_0080;
const INO_DEVICE_DIR:    Ino = 0x5102_1000;
const INO_DRIVER_DIR:    Ino = 0x5102_1100;
const INO_ATTR:          Ino = 0x5102_2000;
const INO_DRIVER_ATTR:   Ino = 0x5102_3000;

const DEV_ATTR: Attribute = Attribute { name: "dev", mode: RO_PERM };
const PCI_RESOURCE_ATTRS: [Attribute; 6] = [
    Attribute { name: "resource0", mode: RO_PERM },
    Attribute { name: "resource1", mode: RO_PERM },
    Attribute { name: "resource2", mode: RO_PERM },
    Attribute { name: "resource3", mode: RO_PERM },
    Attribute { name: "resource4", mode: RO_PERM },
    Attribute { name: "resource5", mode: RO_PERM },
];

fn modalias(dev: &drv::Device) -> String {
    if dev.bus == "pci" {
        let base = (dev.class >> 16) & 0xff;
        let sub = (dev.class >> 8) & 0xff;
        let pi = dev.class & 0xff;
        alloc::format!(
            "pci:v{:08X}d{:08X}sv*sd*bc{:02X}sc{:02X}i{:02X}",
            dev.vendor_id as u32, dev.device_id as u32, base, sub, pi)
    } else if dev.bus == "virtio" {
        alloc::format!("virtio:d{:08x}", dev.device_id as u32)
    } else {
        alloc::format!("platform:{}", dev.addr)
    }
}

fn dev_uevent_env(dev: &drv::Device) -> Vec<String> {
    let mut env = Vec::new();
    if dev.bus == "pci" {
        env.push(alloc::format!("PCI_ID={:04X}:{:04X}", dev.vendor_id, dev.device_id));
        env.push(alloc::format!("PCI_SLOT_NAME={}", dev.addr));
    }
    if let Some((major, minor)) = dev.dev_t {
        env.push(alloc::format!("MAJOR={}", major));
        env.push(alloc::format!("MINOR={}", minor));
    }
    if let Some(name) = dev.devname.as_ref() {
        env.push(alloc::format!("DEVNAME={}", name));
    }
    // Block disks: udev block rules key on DEVTYPE (60§6.3a). Whole-disk nodes
    // are DEVTYPE=disk (partitions would be =partition; v1 has no partitions).
    if dev.bus == "block" {
        env.push(String::from("DEVTYPE=disk"));
    }
    env.push(alloc::format!("MODALIAS={}", modalias(dev)));
    if let Some(drvname) = dev.bound() {
        env.push(alloc::format!("DRIVER={}", drvname));
    }
    env
}

fn pci_resource_index(leaf: &str) -> Option<u8> {
    let suffix = leaf.strip_prefix("resource")?;
    if suffix.len() != 1 {
        return None;
    }
    let b = suffix.as_bytes()[0];
    if !(b'0'..=b'5').contains(&b) {
        return None;
    }
    Some(b - b'0')
}

fn resource_body(r: &drv::Resource) -> Vec<u8> {
    alloc::format!(
        "0x{:016x} 0x{:016x} 0x{:016x}\n",
        r.start, r.end, r.flags,
    ).into_bytes()
}

fn dev_attr(dev: &drv::Device, leaf: &str) -> Option<Vec<u8>> {
    match leaf {
        "vendor" => Some(alloc::format!("0x{:04x}\n", dev.vendor_id).into_bytes()),
        "device" => Some(alloc::format!("0x{:04x}\n", dev.device_id).into_bytes()),
        "class"  => Some(alloc::format!("0x{:06x}\n", dev.class).into_bytes()),
        "resource" if dev.bus == "pci" => {
            let mut s = String::new();
            for r in dev.resources.iter() {
                s.push_str(&alloc::format!(
                    "0x{:016x} 0x{:016x} 0x{:016x}\n",
                    r.start, r.end, r.flags,
                ));
            }
            Some(s.into_bytes())
        }
        leaf if dev.bus == "pci" && pci_resource_index(leaf).is_some() => {
            let bar = pci_resource_index(leaf).expect("resource index checked");
            dev.resources
                .iter()
                .find(|r| r.bar == bar)
                .map(resource_body)
        }
        "modalias" => Some(alloc::format!("{}\n", modalias(dev)).into_bytes()),
        "driver_override" => {
            Some(match dev.driver_override() {
                Some(name) => alloc::format!("{}\n", name),
                None => String::from("(null)\n"),
            }.into_bytes())
        }
        "dev" => {
            let (major, minor) = dev.dev_t?;
            Some(alloc::format!("{}:{}\n", major, minor).into_bytes())
        }
        "uevent" => {
            let mut s = String::new();
            for entry in dev_uevent_env(dev) {
                s.push_str(&entry);
                s.push('\n');
            }
            Some(s.into_bytes())
        }
        _ => None,
    }
}

/// PCI device default attribute group (Linux `pci_dev_attrs`). # C: n/a
const PCI_DEV_ATTRS: &[Attribute] = &[
    Attribute { name: "vendor", mode: RO_PERM },
    Attribute { name: "device", mode: RO_PERM },
    Attribute { name: "class",  mode: RO_PERM },
    Attribute { name: "resource", mode: RO_PERM },
    Attribute { name: "modalias", mode: RO_PERM },
    Attribute { name: "driver_override", mode: RW_PERM },
    Attribute { name: "uevent", mode: RW_PERM },
];
static PCI_DEV_GROUP: AttrGroup = AttrGroup { attrs: PCI_DEV_ATTRS };

/// virtio device default attribute group. # C: n/a
const VIRTIO_DEV_ATTRS: &[Attribute] = &[
    Attribute { name: "device", mode: RO_PERM },
    Attribute { name: "modalias", mode: RO_PERM },
    Attribute { name: "driver_override", mode: RW_PERM },
    Attribute { name: "uevent", mode: RW_PERM },
];
static VIRTIO_DEV_GROUP: AttrGroup = AttrGroup { attrs: VIRTIO_DEV_ATTRS };

/// platform device default attribute group. # C: n/a
const PLATFORM_DEV_ATTRS: &[Attribute] = &[
    Attribute { name: "modalias", mode: RO_PERM },
    Attribute { name: "driver_override", mode: RW_PERM },
    Attribute { name: "uevent", mode: RW_PERM },
];
static PLATFORM_DEV_GROUP: AttrGroup = AttrGroup { attrs: PLATFORM_DEV_ATTRS };

/// The device attribute group for `bus`. # C: O(1)
fn dev_group(bus: &str) -> &'static AttrGroup {
    match bus {
        "pci" => &PCI_DEV_GROUP,
        "virtio" => &VIRTIO_DEV_GROUP,
        "platform" => &PLATFORM_DEV_GROUP,
        _ => &PLATFORM_DEV_GROUP,
    }
}

/// `sysfs_ops` for a `/sys/devices/.../<addr>` device kobject — `show` renders
/// each attribute fresh from the live `drv` registry. # C: O(1)
struct DeviceKobj { addr: String, bus: &'static str }
impl SysfsOps for DeviceKobj {
    fn show(&self, attr: &str) -> Option<Vec<u8>> {
        let dev = find_dev(self.bus, &self.addr)?;
        dev_attr(&dev, attr)
    }

    fn store(&self, attr: &str, buf: &[u8]) -> KResult<usize> {
        let dev = find_dev(self.bus, &self.addr).ok_or(VfsError::Enoent)?;
        match attr {
            "driver_override" => {
                let s = core::str::from_utf8(buf).map_err(|_| VfsError::Einval)?;
                let value = s.trim();
                if value.is_empty() || value == "(null)" {
                    dev.set_driver_override(None);
                } else {
                    dev.set_driver_override(Some(String::from(value)));
                }
                Ok(buf.len())
            }
            "uevent" => {
                let action = crate::uevent_action(buf);
                let devpath = alloc::format!("/{}/{}", dev_root_canon(dev.bus), dev.addr);
                let env = dev_uevent_env(&dev);
                let refs: Vec<&str> = env.iter().map(|s| s.as_str()).collect();
                ::netlink::emit_uevent_with_env(action, &devpath, dev.bus, &refs);
                Ok(buf.len())
            }
            _ => Err(VfsError::Erofs),
        }
    }
}

/// A symlink inode (under the bus tree) whose readlink target is a fixed
/// byte string. # C: O(1)
fn make_link_inode(target: Vec<u8>) -> InodeRef {
    make_symlink_inode_ino(target, INO_SYMLINK)
}

/// Real per-device directory under `/sys/devices/<root>/<addr>`. Holds
/// attribute files + a `driver` symlink when bound.
struct DeviceDirData { addr: String, bus: &'static str }

struct DeviceDirOps;
impl InodeOps for DeviceDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let data = inode.private::<DeviceDirData>().ok_or(VfsError::Einval)?;
        let dev = find_dev(data.bus, &data.addr).ok_or(VfsError::Enoent)?;
        if name == "driver" {
            let drvname = dev.bound().ok_or(VfsError::Enoent)?;
            // ../../../bus/<bus>/drivers/<name>  (from /sys/devices/<root>/<addr>)
            let t = alloc::format!("../../../bus/{}/drivers/{}", data.bus, drvname);
            return Ok(make_link_inode(t.into_bytes()));
        }
        if name == "subsystem" {
            // ../../../bus/<bus>  (from /sys/devices/<root>/<addr>)
            let t = alloc::format!("../../../bus/{}", data.bus);
            return Ok(make_link_inode(t.into_bytes()));
        }
        if name == "parent" {
            let (parent_bus, parent_addr) = dev.parent().ok_or(VfsError::Enoent)?;
            let t = alloc::format!("../../{}/{}", dev_root_leaf(parent_bus), parent_addr);
            return Ok(make_link_inode(t.into_bytes()));
        }
        if name == "drm" && crate::drm::has_parented_minors(data.bus, &data.addr) {
            return Ok(crate::drm::make_parent_drm_inode(data.bus, data.addr.clone()));
        }
        if name == "dev" {
            if dev.dev_t.is_none() { return Err(VfsError::Enoent); }
            let ops: Arc<dyn SysfsOps> = Arc::new(DeviceKobj { addr: data.addr.clone(), bus: data.bus });
            return Ok(make_attr_inode(&DEV_ATTR, ops, INO_ATTR));
        }
        if data.bus == "pci" {
            if let Some(bar) = pci_resource_index(name) {
                if !dev.resources.iter().any(|r| r.bar == bar) {
                    return Err(VfsError::Enoent);
                }
                let ops: Arc<dyn SysfsOps> = Arc::new(DeviceKobj { addr: data.addr.clone(), bus: data.bus });
                return Ok(make_attr_inode(&PCI_RESOURCE_ATTRS[bar as usize], ops, INO_ATTR));
            }
        }
        let attr = dev_group(data.bus).find(name).ok_or(VfsError::Enoent)?;
        let ops: Arc<dyn SysfsOps> = Arc::new(DeviceKobj { addr: data.addr.clone(), bus: data.bus });
        Ok(make_attr_inode(attr, ops, INO_ATTR))
    }
}
impl FileOps for DeviceDirOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let data = match inode.private::<DeviceDirData>() { Some(d) => d, None => return Err(VfsError::Einval) };
        let attrs = dev_group(data.bus).attrs;
        let dev = find_dev(data.bus, &data.addr);
        let bound = dev.as_ref().map(|d| d.bound().is_some()).unwrap_or(false);
        let has_parent = dev.as_ref().map(|d| d.parent().is_some()).unwrap_or(false);
        let has_dev = dev.as_ref().map(|d| d.dev_t.is_some()).unwrap_or(false);
        let mut entries: Vec<(&str, FileType)> = attrs.iter()
            .map(|a| (a.name, FileType::Regular))
            .collect();
        if has_dev {
            entries.push(("dev", FileType::Regular));
        }
        if data.bus == "pci" {
            if let Some(dev) = dev.as_ref() {
                for attr in PCI_RESOURCE_ATTRS.iter() {
                    if let Some(bar) = pci_resource_index(attr.name) {
                        if dev.resources.iter().any(|r| r.bar == bar) {
                            entries.push((attr.name, FileType::Regular));
                        }
                    }
                }
            }
        }
        entries.push(("subsystem", FileType::Symlink));
        if has_parent {
            entries.push(("parent", FileType::Symlink));
        }
        if crate::drm::has_parented_minors(data.bus, &data.addr) {
            entries.push(("drm", FileType::Directory));
        }
        if bound {
            entries.push(("driver", FileType::Symlink));
        }
        let mut idx = ctx.pos as usize;
        while idx < entries.len() {
            let next = idx as u64 + 1;
            let (name, file_type) = entries[idx];
            let ino = inode.lookup(name).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(name, ino, file_type, next) { return Ok(()); }
            idx += 1;
        }
        Ok(())
    }
}
fn make_device_dir_inode(addr: String, bus: &'static str) -> InodeRef {
    InodeBuilder::new(INO_DEVICE_DIR, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(DeviceDirOps), Arc::new(DeviceDirOps))
        .private(Arc::new(DeviceDirData { addr, bus }))
        .build()
}

fn find_dev(bus: &str, addr: &str) -> Option<Arc<drv::Device>> {
    drv::devices().into_iter().find(|d| d.bus == bus && d.addr == addr)
}

fn dev_root_canon(bus: &str) -> &'static str {
    match bus {
        "pci" => "devices/pci0000:00",
        "virtio" => "devices/virtio",
        "platform" => "devices/platform",
        // Block disks live under /sys/devices/virtual/block/<name> (60§6.3a):
        // the uevent DEVPATH MUST resolve to a real /sys dir or udevd reads
        // /sys<DEVPATH>/uevent → ENOENT and never processes the disk.
        "block" => "devices/virtual/block",
        "input" => "devices/virtual/input",
        "drm" => "devices/virtual/drm",
        "mem" => "devices/virtual/mem",
        "misc" => "devices/virtual/misc",
        "sound" => "devices/virtual/sound",
        "graphics" => "devices/virtual/graphics",
        _ => "devices/platform",
    }
}

fn dev_root_leaf(bus: &str) -> &'static str {
    match bus {
        "pci" => "pci0000:00",
        "virtio" => "virtio",
        "platform" => "platform",
        "block" => "virtual/block",
        "input" => "virtual/input",
        "drm" => "virtual/drm",
        "mem" => "virtual/mem",
        "misc" => "virtual/misc",
        "sound" => "virtual/sound",
        "graphics" => "virtual/graphics",
        _ => "platform",
    }
}

fn bus_devices_ino(bus: &str) -> Ino {
    match bus {
        "pci" => INO_BUS_PCI_DEV,
        "virtio" => INO_BUS_VIRT_DEV,
        "platform" => INO_BUS_PLATFORM_DEV,
        _ => INO_BUS_PLATFORM_DEV,
    }
}

fn bus_drivers_ino(bus: &str) -> Ino {
    match bus {
        "pci" => INO_BUS_PCI_DRV,
        "virtio" => INO_BUS_VIRT_DRV,
        "platform" => INO_BUS_PLATFORM_DRV,
        _ => INO_BUS_PLATFORM_DRV,
    }
}

fn devices_root_ino(bus: &str) -> Ino {
    match bus {
        "pci" => INO_DEV_PCI_ROOT,
        "virtio" => INO_DEV_VIRT_ROOT,
        "platform" => INO_DEV_PLATFORM_ROOT,
        _ => INO_DEV_PLATFORM_ROOT,
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum DevIndexKind { Char, Block }

fn dev_index_kind(dev: &drv::Device) -> DevIndexKind {
    if dev.dev_class == "block" { DevIndexKind::Block } else { DevIndexKind::Char }
}

fn dev_index_name(major: u32, minor: u32) -> String {
    alloc::format!("{}:{}", major, minor)
}

fn find_dev_by_index(kind: DevIndexKind, name: &str) -> Option<Arc<drv::Device>> {
    drv::devices().into_iter().find(|d| {
        let Some((major, minor)) = d.dev_t else { return false; };
        dev_index_kind(d) == kind && dev_index_name(major, minor) == name
    })
}

/// Canonical `/sys` DEVPATH for a device's uevent (Linux `add@<devpath>`).
/// udevd reads `/sys<DEVPATH>/uevent`, so this MUST match the real sysfs dir.
/// DRM cards live at `/devices/virtual/drm/<sysname>` (sysfs::drm), NOT the
/// `dev_root_canon("drm")` fallthrough `devices/platform/dri/card0`. # C: O(1)
fn dev_devpath(dev: &drv::Device) -> String {
    if dev.bus == "drm" {
        let sysname = dev.addr.rsplit('/').next().unwrap_or(dev.addr.as_str());
        return alloc::format!("/devices/virtual/drm/{}", sysname);
    }
    alloc::format!("/{}/{}", dev_root_canon(dev.bus), dev.addr)
}

fn dev_index_target(dev: &drv::Device) -> Vec<u8> {
    if let Some(target) = crate::drm::dev_index_target(dev) {
        return target;
    }
    alloc::format!("../../{}/{}", dev_root_canon(dev.bus), dev.addr).into_bytes()
}

/// `/sys/dev/char` and `/sys/dev/block` reverse dev_t indexes. Linux exposes
/// each `<major>:<minor>` as a symlink to the owning device kobject; deriving
/// this from `drv::devices()` keeps add/remove/readd behavior registry-owned.
struct SysDevIndexOps;
impl InodeOps for SysDevIndexOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let kind = inode.private::<DevIndexData>().ok_or(VfsError::Einval)?.kind;
        let dev = find_dev_by_index(kind, name).ok_or(VfsError::Enoent)?;
        Ok(make_link_inode(dev_index_target(&dev)))
    }
}
impl FileOps for SysDevIndexOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let kind = inode.private::<DevIndexData>().ok_or(VfsError::Einval)?.kind;
        let mut names: Vec<String> = Vec::new();
        for dev in drv::devices().iter() {
            let Some((major, minor)) = dev.dev_t else { continue; };
            if dev_index_kind(dev) != kind { continue; }
            let name = dev_index_name(major, minor);
            if !names.iter().any(|n| n == &name) {
                names.push(name);
            }
        }
        let mut idx = ctx.pos as usize;
        while idx < names.len() {
            let next = idx as u64 + 1;
            let ino = inode.lookup(&names[idx]).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(&names[idx], ino, FileType::Symlink, next) { return Ok(()); }
            idx += 1;
        }
        Ok(())
    }
}

struct DevIndexData { kind: DevIndexKind }

fn make_sys_dev_index_inode(kind: DevIndexKind) -> InodeRef {
    let ino = match kind {
        DevIndexKind::Char => INO_SYS_DEV_CHAR,
        DevIndexKind::Block => INO_SYS_DEV_BLOCK,
    };
    InodeBuilder::new(ino, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(SysDevIndexOps), Arc::new(SysDevIndexOps))
        .private(Arc::new(DevIndexData { kind }))
        .build()
}

/// Per-inode bus tag for the bus/devices-root dir inodes. # C: n/a
struct BusData { bus: &'static str }

/// `/sys/devices/pci0000:00` or `/sys/devices/virtio` — real device dirs.
struct DevicesRootOps;
impl InodeOps for DevicesRootOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let bus = inode.private::<BusData>().ok_or(VfsError::Einval)?.bus;
        if find_dev(bus, name).is_some() {
            return Ok(make_device_dir_inode(String::from(name), bus));
        }
        Err(VfsError::Enoent)
    }
}
impl FileOps for DevicesRootOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let bus = match inode.private::<BusData>() { Some(d) => d.bus, None => return Err(VfsError::Einval) };
        let devs = drv::devices();
        let list: Vec<&str> = devs.iter().filter(|d| d.bus == bus).map(|d| d.addr.as_str()).collect();
        let mut idx = ctx.pos as usize;
        while idx < list.len() {
            let next = idx as u64 + 1;
            let ino = inode.lookup(list[idx]).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(list[idx], ino, FileType::Directory, next) { return Ok(()); }
            idx += 1;
        }
        Ok(())
    }
}
fn make_devices_root_inode(bus: &'static str) -> InodeRef {
    let ino = devices_root_ino(bus);
    InodeBuilder::new(ino, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(DevicesRootOps), Arc::new(DevicesRootOps))
        .private(Arc::new(BusData { bus }))
        .build()
}

/// `/sys/bus/<bus>/devices` — symlinks into the canonical /sys/devices dir.
struct BusDevicesOps;
impl InodeOps for BusDevicesOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let bus = inode.private::<BusData>().ok_or(VfsError::Einval)?.bus;
        if find_dev(bus, name).is_some() {
            // from /sys/bus/<bus>/devices/<addr> -> /sys/devices/<root>/<addr>
            let t = alloc::format!("../../../{}/{}", dev_root_canon(bus), name);
            return Ok(make_link_inode(t.into_bytes()));
        }
        Err(VfsError::Enoent)
    }
}
impl FileOps for BusDevicesOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let bus = match inode.private::<BusData>() { Some(d) => d.bus, None => return Err(VfsError::Einval) };
        let devs = drv::devices();
        let list: Vec<&str> = devs.iter().filter(|d| d.bus == bus).map(|d| d.addr.as_str()).collect();
        let mut idx = ctx.pos as usize;
        while idx < list.len() {
            let next = idx as u64 + 1;
            let ino = inode.lookup(list[idx]).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(list[idx], ino, FileType::Symlink, next) { return Ok(()); }
            idx += 1;
        }
        Ok(())
    }
}
fn make_bus_devices_inode(bus: &'static str) -> InodeRef {
    let ino = bus_devices_ino(bus);
    InodeBuilder::new(ino, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(BusDevicesOps), Arc::new(BusDevicesOps))
        .private(Arc::new(BusData { bus }))
        .build()
}

/// `/sys/bus/<bus>/drivers` — one dir per registered model driver.
struct BusDriversOps;
impl InodeOps for BusDriversOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let bus = inode.private::<BusData>().ok_or(VfsError::Einval)?.bus;
        if let Some(driver) = drv::driver_names_for_bus(bus).into_iter().find(|n| *n == name) {
            return Ok(make_driver_dir_inode(bus, driver));
        }
        Err(VfsError::Enoent)
    }
}
impl FileOps for BusDriversOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let bus = inode.private::<BusData>().ok_or(VfsError::Einval)?.bus;
        let names = drv::driver_names_for_bus(bus);
        let mut idx = ctx.pos as usize;
        while idx < names.len() {
            let next = idx as u64 + 1;
            let ino = inode.lookup(names[idx]).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(names[idx], ino, FileType::Directory, next) { return Ok(()); }
            idx += 1;
        }
        Ok(())
    }
}
fn make_bus_drivers_inode(bus: &'static str) -> InodeRef {
    let ino = bus_drivers_ino(bus);
    InodeBuilder::new(ino, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(BusDriversOps), Arc::new(BusDriversOps))
        .private(Arc::new(BusData { bus }))
        .build()
}

struct DriverDirData { bus: &'static str, driver: &'static str }

/// `/sys/bus/<bus>/drivers/<name>` — driver dir with Linux bind/unbind attrs
/// and symlinks to devices currently bound to this driver.
struct DriverDirOps;
impl InodeOps for DriverDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let data = inode.private::<DriverDirData>().ok_or(VfsError::Einval)?;
        match name {
            "bind" => return Ok(make_driver_attr_inode(data.bus, data.driver, DriverAttr::Bind)),
            "unbind" => return Ok(make_driver_attr_inode(data.bus, data.driver, DriverAttr::Unbind)),
            _ => {}
        }
        let is_bound = drv::devices().into_iter().any(|d| {
            d.bus == data.bus && d.addr == name && d.bound() == Some(data.driver)
        });
        if !is_bound { return Err(VfsError::Enoent); }
        // from /sys/bus/<bus>/drivers/<driver>/<addr>
        // to /sys/devices/<root>/<addr>
        let t = alloc::format!("../../../../{}/{}", dev_root_canon(data.bus), name);
        Ok(make_link_inode(t.into_bytes()))
    }
}
impl FileOps for DriverDirOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let data = inode.private::<DriverDirData>().ok_or(VfsError::Einval)?;
        let devs = drv::devices();
        let bound: Vec<&str> = devs.iter()
            .filter(|d| d.bus == data.bus && d.bound() == Some(data.driver))
            .map(|d| d.addr.as_str())
            .collect();
        let mut idx = ctx.pos as usize;
        const ATTRS: &[&str] = &["bind", "unbind"];
        while idx < ATTRS.len() {
            let next = idx as u64 + 1;
            let ino = inode.lookup(ATTRS[idx]).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(ATTRS[idx], ino, FileType::Regular, next) { return Ok(()); }
            idx += 1;
        }
        while idx - ATTRS.len() < bound.len() {
            let next = idx as u64 + 1;
            let name = bound[idx - ATTRS.len()];
            let ino = inode.lookup(name).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(name, ino, FileType::Symlink, next) { return Ok(()); }
            idx += 1;
        }
        Ok(())
    }
}
fn make_driver_dir_inode(bus: &'static str, driver: &'static str) -> InodeRef {
    InodeBuilder::new(INO_DRIVER_DIR, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(DriverDirOps), Arc::new(DriverDirOps))
        .private(Arc::new(DriverDirData { bus, driver }))
        .build()
}

#[derive(Copy, Clone)]
enum DriverAttr { Bind, Unbind }

struct DriverAttrData { bus: &'static str, driver: &'static str, attr: DriverAttr }

fn drv_error_to_vfs(e: drv::Error) -> VfsError {
    match e {
        drv::Error::AlreadyBound => VfsError::Ebusy,
        drv::Error::Busy => VfsError::Ebusy,
        drv::Error::NoMatch => VfsError::Enodev,
        drv::Error::NoMem => VfsError::Enomem,
        drv::Error::ProbeFailed => VfsError::Eio,
        drv::Error::Removed => VfsError::Enodev,
        drv::Error::NotFound => VfsError::Enoent,
    }
}

fn sysfs_write_token(buf: &[u8]) -> KResult<&str> {
    let s = core::str::from_utf8(buf).map_err(|_| VfsError::Einval)?;
    s.split_ascii_whitespace().next().ok_or(VfsError::Einval)
}

struct DriverAttrOps;
impl FileOps for DriverAttrOps {
    fn read(&self, _inode: &Inode, _off: u64, _buf: &mut [u8]) -> KResult<usize> { Ok(0) }
    fn write(&self, inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        let data = inode.private::<DriverAttrData>().ok_or(VfsError::Einval)?;
        let addr = sysfs_write_token(buf)?;
        match data.attr {
            DriverAttr::Bind => {
                drv::bind_addr(data.bus, addr, data.driver).map_err(drv_error_to_vfs)?;
            }
            DriverAttr::Unbind => {
                let dev = drv::devices().into_iter()
                    .find(|d| d.bus == data.bus && d.addr == addr && d.bound() == Some(data.driver))
                    .ok_or(VfsError::Enodev)?;
                drv::unbind(&dev).map_err(drv_error_to_vfs)?;
            }
        }
        Ok(buf.len())
    }
}

fn make_driver_attr_inode(bus: &'static str, driver: &'static str, attr: DriverAttr) -> InodeRef {
    let off = match attr { DriverAttr::Bind => 0, DriverAttr::Unbind => 1 };
    InodeBuilder::new(INO_DRIVER_ATTR + off, mk_mode(FileType::Regular, RW_PERM),
        vfs::default_inode_ops(), Arc::new(DriverAttrOps))
        .private(Arc::new(DriverAttrData { bus, driver, attr }))
        .build()
}

/// Register the dynamic bus/devices dir inodes in sysfs's own tree.
/// Called from `sysfs::init` (procfs static-files init),
/// BEFORE pci enumeration — so devices published during enumeration
/// resolve through these dynamic inodes immediately.
/// # C: O(1)
pub fn init() {
    crate::register("/sys/bus/pci/devices",    make_bus_devices_inode("pci"));
    crate::register("/sys/bus/pci/drivers",    make_bus_drivers_inode("pci"));
    crate::register("/sys/bus/virtio/devices", make_bus_devices_inode("virtio"));
    crate::register("/sys/bus/virtio/drivers", make_bus_drivers_inode("virtio"));
    crate::register("/sys/bus/platform/devices", make_bus_devices_inode("platform"));
    crate::register("/sys/bus/platform/drivers", make_bus_drivers_inode("platform"));
    crate::register("/sys/devices/pci0000:00", make_devices_root_inode("pci"));
    crate::register("/sys/devices/virtio",     make_devices_root_inode("virtio"));
    crate::register("/sys/devices/platform",   make_devices_root_inode("platform"));
    crate::register("/sys/dev/char",           make_sys_dev_index_inode(DevIndexKind::Char));
    crate::register("/sys/dev/block",          make_sys_dev_index_inode(DevIndexKind::Block));
}

// --- drv-hook callbacks the kernel wires via drv::set_*_hook --------------
// The tree is dynamic (read from the drv registry on access), so these
// hooks need do no eager devfs work; they exist to satisfy the drv
// contract and to broadcast a kobject uevent so udev coldplug sees the
// device appear. Honest simplification: no per-device devfs key is
// written — the dir inodes synthesise children on demand.

/// drv `set_sysfs_hook` target: a device was registered. # C: O(1)
pub fn publish_device_cb(dev: &drv::Device) {
    let devpath = dev_devpath(dev);
    let env = dev_uevent_env(dev);
    let refs: Vec<&str> = env.iter().map(|s| s.as_str()).collect();
    ::netlink::emit_uevent_with_env("add", &devpath, dev.bus, &refs);
}

/// drv `set_sysfs_remove_hook` target: a device is being removed while it is
/// still visible in the model registry. # C: O(1)
pub fn remove_device_cb(dev: &drv::Device) {
    let devpath = dev_devpath(dev);
    let env = dev_uevent_env(dev);
    let refs: Vec<&str> = env.iter().map(|s| s.as_str()).collect();
    ::netlink::emit_uevent_with_env("remove", &devpath, dev.bus, &refs);
}

/// drv `set_driver_hook` target: a driver was registered. # C: O(1)
pub fn publish_driver_cb(_bus: &str, _name: &'static str) {}

/// drv `set_bind_hook` target: a device binding changed after model state was
/// updated. # C: O(N_devices)
pub fn bind_device_cb(bus: &str, addr: &str, _driver: &'static str, _event: drv::BindEvent) {
    let devpath = alloc::format!("/{}/{}", dev_root_canon(bus), addr);
    if let Some(dev) = find_dev(bus, addr) {
        let env = dev_uevent_env(&dev);
        let refs: Vec<&str> = env.iter().map(|s| s.as_str()).collect();
        ::netlink::emit_uevent_with_env("change", &devpath, bus, &refs);
    } else {
        ::netlink::emit_uevent("change", &devpath, bus);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};

    struct SysfsBindDriver;
    impl drv::Driver for SysfsBindDriver {
        fn bus(&self) -> &'static str { "platform" }
        fn name(&self) -> &'static str { "sysfs-bind-test" }
        fn matches(&self, dev: &drv::Device) -> bool { dev.addr == "sysfs-bind-dev0" }
        fn probe(&self, _dev: &Arc<drv::Device>) -> drv::KResult<()> {
            BIND_PROBES.fetch_add(1, Ordering::Release);
            Ok(())
        }
        fn remove(&self, _dev: &drv::Device) {
            BIND_REMOVES.fetch_add(1, Ordering::Release);
        }
    }

    static SYSFS_BIND_DRIVER: SysfsBindDriver = SysfsBindDriver;
    static BIND_PROBES: AtomicU32 = AtomicU32::new(0);
    static BIND_REMOVES: AtomicU32 = AtomicU32::new(0);

    struct SysfsBindUeventDriver;
    impl drv::Driver for SysfsBindUeventDriver {
        fn bus(&self) -> &'static str { "platform" }
        fn name(&self) -> &'static str { "sysfs-bind-uevent-test" }
        fn matches(&self, dev: &drv::Device) -> bool { dev.addr == "sysfs-bind-uevent0" }
    }
    static SYSFS_BIND_UEVENT_DRIVER: SysfsBindUeventDriver = SysfsBindUeventDriver;

    struct SysfsAddUeventDriver;
    impl drv::Driver for SysfsAddUeventDriver {
        fn bus(&self) -> &'static str { "platform" }
        fn name(&self) -> &'static str { "sysfs-add-uevent-test" }
        fn matches(&self, dev: &drv::Device) -> bool { dev.addr == "sysfs-add-uevent0" }
    }
    static SYSFS_ADD_UEVENT_DRIVER: SysfsAddUeventDriver = SysfsAddUeventDriver;

    struct RejectDriver;
    impl drv::Driver for RejectDriver {
        fn bus(&self) -> &'static str { "platform" }
        fn name(&self) -> &'static str { "sysfs-bind-reject" }
        fn matches(&self, dev: &drv::Device) -> bool { dev.addr == "sysfs-bind-reject0" }
        fn probe(&self, _dev: &Arc<drv::Device>) -> drv::KResult<()> {
            Err(drv::Error::ProbeFailed)
        }
    }
    static REJECT_DRIVER: RejectDriver = RejectDriver;

    struct SysfsUnregisterDriver;
    impl drv::Driver for SysfsUnregisterDriver {
        fn bus(&self) -> &'static str { "platform" }
        fn name(&self) -> &'static str { "sysfs-unregister-test" }
        fn matches(&self, dev: &drv::Device) -> bool { dev.addr == "sysfs-unregister0" }
        fn remove(&self, _dev: &drv::Device) {
            BIND_REMOVES.fetch_add(1, Ordering::Release);
        }
    }
    static SYSFS_UNREGISTER_DRIVER: SysfsUnregisterDriver = SysfsUnregisterDriver;

    fn platform_device(addr: &str) -> Arc<drv::Device> {
        let d = Arc::new(drv::Device::new("platform", String::from(addr), 0, 0, 0));
        drv::try_device_add(Arc::clone(&d)).expect("test device registration");
        d
    }

    fn uevent_has_entry(msg: &[u8], needle: &[u8]) -> bool {
        msg.split(|b| *b == 0).any(|entry| entry == needle)
    }

    #[test]
    fn driver_bind_unbind_attrs_drive_drv_model() {
        BIND_PROBES.store(0, Ordering::Release);
        BIND_REMOVES.store(0, Ordering::Release);
        drv::register_driver(&SYSFS_BIND_DRIVER);
        let dev = platform_device("sysfs-bind-dev0");

        let root = make_bus_drivers_inode("platform");
        let dir = root.lookup("sysfs-bind-test").expect("driver dir");
        let bind = dir.lookup("bind").expect("bind attr");
        assert_eq!(dev.bound(), Some("sysfs-bind-test"));
        assert_eq!(BIND_PROBES.load(Ordering::Acquire), 1);
        assert_eq!(bind.write(0, b"sysfs-bind-dev0\n").err(), Some(VfsError::Ebusy));
        let bound_link = dir.lookup("sysfs-bind-dev0").expect("driver dir bound device symlink");
        assert_eq!(
            bound_link.readlink().expect("readlink"),
            b"../../../../devices/platform/sysfs-bind-dev0".to_vec());

        let unbind = dir.lookup("unbind").expect("unbind attr");
        assert_eq!(unbind.write(0, b"sysfs-bind-dev0\n"), Ok("sysfs-bind-dev0\n".len()));
        assert_eq!(dev.bound(), None);
        assert_eq!(BIND_REMOVES.load(Ordering::Acquire), 1);
        assert_eq!(dir.lookup("sysfs-bind-dev0").err(), Some(VfsError::Enoent));

        assert_eq!(bind.write(0, b"sysfs-bind-dev0\n"), Ok("sysfs-bind-dev0\n".len()));
        assert_eq!(dev.bound(), Some("sysfs-bind-test"));
        assert_eq!(BIND_PROBES.load(Ordering::Acquire), 2);
        let rebound_link = dir.lookup("sysfs-bind-dev0").expect("driver dir rebound device symlink");
        assert_eq!(
            rebound_link.readlink().expect("readlink"),
            b"../../../../devices/platform/sysfs-bind-dev0".to_vec());
    }

    #[test]
    fn bind_unbind_emit_change_uevents_from_current_model_state() {
        use netlink::{proto, NetlinkSocket};

        let listener = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT));
        listener.set_group_mask(1);
        netlink::register_uevent_listener(&listener);
        drv::set_bind_hook(bind_device_cb);

        let dev = platform_device("sysfs-bind-uevent0");
        drv::register_driver(&SYSFS_BIND_UEVENT_DRIVER);

        let bound = listener.dequeue().expect("bind change uevent");
        assert!(uevent_has_entry(&bound, b"ACTION=change"));
        assert!(uevent_has_entry(&bound, b"DEVPATH=/devices/platform/sysfs-bind-uevent0"));
        assert!(uevent_has_entry(&bound, b"SUBSYSTEM=platform"));
        assert!(uevent_has_entry(&bound, b"DRIVER=sysfs-bind-uevent-test"));
        assert_eq!(dev.bound(), Some("sysfs-bind-uevent-test"));

        let root = make_bus_drivers_inode("platform");
        let dir = root.lookup("sysfs-bind-uevent-test").expect("driver dir");
        let unbind = dir.lookup("unbind").expect("unbind attr");
        assert_eq!(unbind.write(0, b"sysfs-bind-uevent0\n"), Ok("sysfs-bind-uevent0\n".len()));

        let unbound = listener.dequeue().expect("unbind change uevent");
        assert!(uevent_has_entry(&unbound, b"ACTION=change"));
        assert!(uevent_has_entry(&unbound, b"DEVPATH=/devices/platform/sysfs-bind-uevent0"));
        assert!(uevent_has_entry(&unbound, b"SUBSYSTEM=platform"));
        assert!(!uevent_has_entry(&unbound, b"DRIVER=sysfs-bind-uevent-test"));
        assert_eq!(dev.bound(), None);

        drv::device_del(&dev);
    }

    #[test]
    fn device_add_uevent_includes_initial_bound_driver_state() {
        use netlink::{proto, NetlinkSocket};

        drv::set_sysfs_hook(publish_device_cb);
        drv::register_driver(&SYSFS_ADD_UEVENT_DRIVER);
        let listener = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT));
        listener.set_group_mask(1);
        netlink::register_uevent_listener(&listener);

        let dev = platform_device("sysfs-add-uevent0");

        let added = listener.dequeue().expect("add uevent");
        assert!(uevent_has_entry(&added, b"ACTION=add"));
        assert!(uevent_has_entry(&added, b"DEVPATH=/devices/platform/sysfs-add-uevent0"));
        assert!(uevent_has_entry(&added, b"SUBSYSTEM=platform"));
        assert!(uevent_has_entry(&added, b"DRIVER=sysfs-add-uevent-test"));
        assert_eq!(dev.bound(), Some("sysfs-add-uevent-test"));

        drv::device_del(&dev);
    }

    #[test]
    fn device_del_emits_remove_uevent_before_model_disappears() {
        use netlink::{proto, NetlinkSocket};

        fn no_add_uevent(_dev: &drv::Device) {}

        let listener = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT));
        listener.set_group_mask(1);
        netlink::register_uevent_listener(&listener);
        drv::set_sysfs_hook(no_add_uevent);
        drv::set_sysfs_remove_hook(remove_device_cb);

        let dev = Arc::new(drv::Device::new(
            "platform",
            String::from("sysfs-remove-uevent0"),
            0,
            0,
            0,
        ));
        drv::try_device_add(Arc::clone(&dev)).expect("test device registration");

        drv::device_del(&dev);

        let removed = listener.dequeue().expect("remove uevent");
        assert!(uevent_has_entry(&removed, b"ACTION=remove"));
        assert!(uevent_has_entry(
            &removed,
            b"DEVPATH=/devices/platform/sysfs-remove-uevent0"
        ));
        assert!(uevent_has_entry(&removed, b"SUBSYSTEM=platform"));
        assert!(!drv::devices()
            .iter()
            .any(|registered| Arc::ptr_eq(registered, &dev)));
    }

    #[test]
    fn driver_unregister_removes_sysfs_driver_dir_and_unbinds_devices() {
        BIND_REMOVES.store(0, Ordering::Release);
        drv::register_driver(&SYSFS_UNREGISTER_DRIVER);
        let dev = platform_device("sysfs-unregister0");

        let root = make_bus_drivers_inode("platform");
        assert!(root.lookup("sysfs-unregister-test").is_ok());
        assert_eq!(dev.bound(), Some("sysfs-unregister-test"));

        assert_eq!(drv::unregister_driver(&SYSFS_UNREGISTER_DRIVER), Ok(()));
        assert_eq!(dev.bound(), None);
        assert_eq!(BIND_REMOVES.load(Ordering::Acquire), 1);
        assert_eq!(root.lookup("sysfs-unregister-test").err(), Some(VfsError::Enoent));

        drv::device_del(&dev);
    }

    #[test]
    fn driver_bind_attr_preserves_unbound_state_on_probe_failure() {
        drv::register_driver(&REJECT_DRIVER);
        let dev = platform_device("sysfs-bind-reject0");

        let root = make_bus_drivers_inode("platform");
        let dir = root.lookup("sysfs-bind-reject").expect("driver dir");
        let bind = dir.lookup("bind").expect("bind attr");
        assert_eq!(bind.write(0, b"sysfs-bind-reject0\n").err(), Some(VfsError::Eio));
        assert_eq!(dev.bound(), None);
        assert_eq!(dir.lookup("sysfs-bind-reject0").err(), Some(VfsError::Enoent));
    }

    #[test]
    fn model_device_with_dev_t_exposes_dev_attr_and_sys_dev_index() {
        let dev = Arc::new(
            drv::Device::new("virtio", String::from("sysfs-dev-index0"), 0, 2, 0)
                .with_devnode("block", String::from("vdt"), Some((254, 42))));
        drv::try_device_add(Arc::clone(&dev)).expect("test device registration");

        let devices = make_devices_root_inode("virtio");
        let dir = devices.lookup("sysfs-dev-index0").expect("device dir");
        let dev_attr = dir.lookup("dev").expect("dev attr");
        let mut buf = [0u8; 16];
        let n = dev_attr.read(0, &mut buf).expect("read dev attr");
        assert_eq!(&buf[..n], b"254:42\n");

        let index = make_sys_dev_index_inode(DevIndexKind::Block);
        let link = index.lookup("254:42").expect("block dev index link");
        assert_eq!(
            link.readlink().expect("readlink"),
            b"../../devices/virtio/sysfs-dev-index0".to_vec());

        drv::device_del(&dev);
        assert_eq!(devices.lookup("sysfs-dev-index0").err(), Some(VfsError::Enoent));
        assert_eq!(index.lookup("254:42").err(), Some(VfsError::Enoent));
    }

    #[test]
    fn pci_device_exposes_indexed_bar_resource_attrs() {
        let dev = Arc::new(
            drv::Device::new("pci", String::from("0000:00:1f.0"), 0x1234, 0x5678, 0x010601)
                .with_resources(Vec::from([
                    drv::Resource { bar: 2, start: 0x1000, end: 0x1fff, flags: 0x200 },
                    drv::Resource { bar: 5, start: 0xfebc_0000, end: 0xfebc_0fff, flags: 0x2200 },
                ])));
        drv::try_device_add(Arc::clone(&dev)).expect("test pci registration");

        let devices = make_devices_root_inode("pci");
        let dir = devices.lookup("0000:00:1f.0").expect("pci device dir");
        assert_eq!(dir.lookup("resource0").err(), Some(VfsError::Enoent));

        let res2 = dir.lookup("resource2").expect("resource2 attr");
        let mut buf = [0u8; 96];
        let n = res2.read(0, &mut buf).expect("read resource2");
        assert_eq!(
            &buf[..n],
            b"0x0000000000001000 0x0000000000001fff 0x0000000000000200\n");

        let res5 = dir.lookup("resource5").expect("resource5 attr");
        let n = res5.read(0, &mut buf).expect("read resource5");
        assert_eq!(
            &buf[..n],
            b"0x00000000febc0000 0x00000000febc0fff 0x0000000000002200\n");

        let modalias = dir.lookup("modalias").expect("modalias still works");
        let n = modalias.read(0, &mut buf).expect("read modalias");
        assert_eq!(&buf[..n], b"pci:v00001234d00005678sv*sd*bc01sc06i01\n");

        drv::device_del(&dev);
    }

    #[test]
    fn sys_dev_char_indexes_virtual_char_class_devices() {
        let mem = Arc::new(
            drv::Device::new("mem", String::from("sysfs-random-test"), 0, 0, 0)
                .with_devnode("mem", String::from("random-test"), Some((1, 8))));
        let misc = Arc::new(
            drv::Device::new("misc", String::from("sysfs-autofs-test"), 0, 0, 0)
                .with_devnode("misc", String::from("autofs-test"), Some((10, 235))));
        let sound = Arc::new(
            drv::Device::new("sound", String::from("controlC8"), 0, 0, 0)
                .with_devnode("sound", String::from("snd/controlC8"), Some((116, 256))));
        let graphics = Arc::new(
            drv::Device::new("graphics", String::from("fb8"), 0, 0, 0)
                .with_devnode("graphics", String::from("fb8"), Some((29, 8))));
        let input = Arc::new(
            drv::Device::new("input", String::from("event-sysdev8"), 0, 0, 0)
                .with_devnode("input", String::from("input/event-sysdev8"), Some((13, 88))));
        let drm = Arc::new(
            drv::Device::new("drm", String::from("card88"), 0, 0, 0)
                .with_devnode("drm", String::from("dri/card88"), Some((226, 88))));
        drv::try_device_add(Arc::clone(&mem)).expect("test mem registration");
        drv::try_device_add(Arc::clone(&misc)).expect("test misc registration");
        drv::try_device_add(Arc::clone(&sound)).expect("test sound registration");
        drv::try_device_add(Arc::clone(&graphics)).expect("test graphics registration");
        drv::try_device_add(Arc::clone(&input)).expect("test input registration");
        drv::try_device_add(Arc::clone(&drm)).expect("test drm registration");

        let index = make_sys_dev_index_inode(DevIndexKind::Char);
        let mem_link = index.lookup("1:8").expect("mem char index link");
        assert_eq!(
            mem_link.readlink().expect("readlink"),
            b"../../devices/virtual/mem/sysfs-random-test".to_vec());
        let misc_link = index.lookup("10:235").expect("misc char index link");
        assert_eq!(
            misc_link.readlink().expect("readlink"),
            b"../../devices/virtual/misc/sysfs-autofs-test".to_vec());
        let sound_link = index.lookup("116:256").expect("sound char index link");
        assert_eq!(
            sound_link.readlink().expect("readlink"),
            b"../../devices/virtual/sound/controlC8".to_vec());
        let graphics_link = index.lookup("29:8").expect("graphics char index link");
        assert_eq!(
            graphics_link.readlink().expect("readlink"),
            b"../../devices/virtual/graphics/fb8".to_vec());
        let input_link = index.lookup("13:88").expect("input char index link");
        assert_eq!(
            input_link.readlink().expect("readlink"),
            b"../../devices/virtual/input/event-sysdev8".to_vec());
        let drm_link = index.lookup("226:88").expect("drm char index link");
        assert_eq!(
            drm_link.readlink().expect("readlink"),
            b"../../devices/virtual/drm/card88".to_vec());

        drv::device_del(&mem);
        drv::device_del(&misc);
        drv::device_del(&sound);
        drv::device_del(&graphics);
        drv::device_del(&input);
        drv::device_del(&drm);
        assert_eq!(index.lookup("1:8").err(), Some(VfsError::Enoent));
        assert_eq!(index.lookup("10:235").err(), Some(VfsError::Enoent));
        assert_eq!(index.lookup("116:256").err(), Some(VfsError::Enoent));
        assert_eq!(index.lookup("29:8").err(), Some(VfsError::Enoent));
        assert_eq!(index.lookup("13:88").err(), Some(VfsError::Enoent));
        assert_eq!(index.lookup("226:88").err(), Some(VfsError::Enoent));
    }

    #[test]
    fn sys_dev_char_indexes_parented_drm_under_parent_device() {
        let parent = Arc::new(drv::Device::new(
            "virtio",
            String::from("sysfs-gpu-parent0"),
            0x1af4,
            16,
            0,
        ));
        let drm = Arc::new(
            drv::Device::new("drm", String::from("card89"), 0, 0, 0)
                .with_parent("virtio", String::from("sysfs-gpu-parent0"))
                .with_devnode("drm", String::from("dri/card89"), Some((226, 89))),
        );
        drv::try_device_add(Arc::clone(&parent)).expect("test parent registration");
        drv::try_device_add(Arc::clone(&drm)).expect("test drm registration");

        let parent_dir = make_devices_root_inode("virtio")
            .lookup("sysfs-gpu-parent0")
            .expect("parent device dir");
        let drm_dir = parent_dir.lookup("drm").expect("parent drm child dir");
        assert!(drm_dir.lookup("card89").is_ok());

        let index = make_sys_dev_index_inode(DevIndexKind::Char);
        let drm_link = index.lookup("226:89").expect("drm char index link");
        assert_eq!(
            drm_link.readlink().expect("readlink"),
            b"../../devices/virtio/sysfs-gpu-parent0/drm/card89".to_vec());

        drv::device_del(&drm);
        drv::device_del(&parent);
        assert_eq!(index.lookup("226:89").err(), Some(VfsError::Enoent));
    }

    #[test]
    fn sys_dev_char_index_tracks_remove_readd_same_devt() {
        let index = make_sys_dev_index_inode(DevIndexKind::Char);
        let first = Arc::new(
            drv::Device::new("sound", String::from("controlC12"), 0, 0, 0)
                .with_devnode("sound", String::from("snd/controlC12"), Some((116, 322))));
        drv::try_device_add(Arc::clone(&first)).expect("first sound registration");

        let link = index.lookup("116:322").expect("first sound char index");
        assert_eq!(
            link.readlink().expect("readlink"),
            b"../../devices/virtual/sound/controlC12".to_vec());

        drv::device_del(&first);
        assert_eq!(index.lookup("116:322").err(), Some(VfsError::Enoent));

        let second = Arc::new(
            drv::Device::new("sound", String::from("controlC12"), 0, 0, 0)
                .with_devnode("sound", String::from("snd/controlC12"), Some((116, 322))));
        drv::try_device_add(Arc::clone(&second)).expect("second sound registration");

        let link = index.lookup("116:322").expect("readded sound char index");
        assert_eq!(
            link.readlink().expect("readlink"),
            b"../../devices/virtual/sound/controlC12".to_vec());

        drv::device_del(&second);
        assert_eq!(index.lookup("116:322").err(), Some(VfsError::Enoent));
    }
}
