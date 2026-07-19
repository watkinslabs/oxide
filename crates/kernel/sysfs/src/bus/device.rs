extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{mk_mode, DirContext, FileOps, FileType, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError};

use crate::kobject::{make_attr_inode, Attribute, AttrGroup, SysfsOps};
use crate::{make_symlink_inode_ino, DIR_PERM, RO_PERM, RW_PERM};

use super::ids::{dev_root_canon, INO_ATTR, INO_DEVICE_DIR, INO_SYMLINK};
use super::index::dev_devpath;

const DEV_ATTR: Attribute = Attribute { name: "dev", mode: RO_PERM };
const PCI_RESOURCE_ATTRS: [Attribute; 6] = [
    Attribute { name: "resource0", mode: RO_PERM },
    Attribute { name: "resource1", mode: RO_PERM },
    Attribute { name: "resource2", mode: RO_PERM },
    Attribute { name: "resource3", mode: RO_PERM },
    Attribute { name: "resource4", mode: RO_PERM },
    Attribute { name: "resource5", mode: RO_PERM },
];

pub(super) fn modalias(dev: &drv::Device) -> String {
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

pub(super) fn dev_uevent_env(dev: &drv::Device) -> Vec<String> {
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
    env.extend(dev.uevent_env.iter().cloned());
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
    // Linux exposes both transport identity attributes on every virtio device.
    // libdrm follows `/sys/dev/char/<major>:<minor>/device` for a virtio-gpu
    // card and reads `vendor` before selecting a Mesa loader; omitting it
    // makes that discovery fail despite a valid DRM node and parent topology.
    Attribute { name: "vendor", mode: RO_PERM },
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
    fn show(&self, attr: &str) -> KResult<Vec<u8>> {
        let dev = find_dev(self.bus, &self.addr).ok_or(VfsError::Enodev)?;
        dev_attr(&dev, attr).ok_or(VfsError::Enoent)
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
                let devpath = dev_devpath(&dev);
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
pub(super) fn make_link_inode(target: Vec<u8>) -> InodeRef {
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
            let canon = dev_canon(data.bus, &data.addr);
            let t = alloc::format!("{}bus/{}/drivers/{}", ups_prefix(&canon), data.bus, drvname);
            return Ok(make_link_inode(t.into_bytes()));
        }
        if name == "subsystem" {
            let canon = dev_canon(data.bus, &data.addr);
            let t = alloc::format!("{}bus/{}", ups_prefix(&canon), data.bus);
            return Ok(make_link_inode(t.into_bytes()));
        }
        if name == "parent" {
            let (parent_bus, parent_addr) = dev.parent().ok_or(VfsError::Enoent)?;
            let canon = dev_canon(data.bus, &data.addr);
            let t = alloc::format!("{}{}", ups_prefix(&canon), dev_canon(parent_bus, parent_addr));
            return Ok(make_link_inode(t.into_bytes()));
        }
        if name == "drm" && crate::drm::has_parented_minors(data.bus, &data.addr) {
            return Ok(crate::drm::make_parent_drm_inode(data.bus, data.addr.clone()));
        }
        // Nested child-device directory: a device whose model parent is this
        // one lives *under* it (Linux sysfs topology), e.g. `virtioN` under its
        // PCI function. Only nesting-bus children are placed here; class devices
        // keep their `/sys/devices/virtual/<class>` home.
        if let Some(child) = drv::devices().into_iter().find(|c| {
            c.addr == name
                && is_nesting_bus(c.bus)
                && c.parent() == Some((data.bus, data.addr.as_str()))
        }) {
            return Ok(make_device_dir_inode(child.addr.clone(), child.bus));
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
        // Nested child-device dirs (owned names; e.g. `virtioN` under a PCI fn).
        let child_names: Vec<String> = drv::devices().into_iter()
            .filter(|c| is_nesting_bus(c.bus)
                && c.parent() == Some((data.bus, data.addr.as_str())))
            .map(|c| c.addr.clone())
            .collect();
        let total = entries.len() + child_names.len();
        let mut idx = ctx.pos as usize;
        while idx < total {
            let next = idx as u64 + 1;
            let (name, file_type): (&str, FileType) = if idx < entries.len() {
                entries[idx]
            } else {
                (child_names[idx - entries.len()].as_str(), FileType::Directory)
            };
            let ino = inode.lookup(name).map(|i| i.ino()).unwrap_or(0);
            if !ctx.emit(name, ino, file_type, next) { return Ok(()); }
            idx += 1;
        }
        Ok(())
    }
}
pub(super) fn make_device_dir_inode(addr: String, bus: &'static str) -> InodeRef {
    InodeBuilder::new(INO_DEVICE_DIR, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(DeviceDirOps), Arc::new(DeviceDirOps))
        .private(Arc::new(DeviceDirData { addr, bus }))
        .build()
}

pub(super) fn find_dev(bus: &str, addr: &str) -> Option<Arc<drv::Device>> {
    drv::devices().into_iter().find(|d| d.bus == bus && d.addr == addr)
}

/// Buses whose devices live in the dynamic `/sys/devices/{pci0000:00,virtio,
/// platform}` tree (as opposed to `/sys/devices/virtual/<class>`). Only these
/// participate in parent nesting: a PCI-backed virtio function is placed under
/// its PCI parent's directory, exactly like Linux. # C: O(1)
pub(super) fn is_nesting_bus(bus: &str) -> bool {
    matches!(bus, "pci" | "virtio" | "platform")
}

/// Canonical nested `/sys/devices/...` path (no leading slash) for a device,
/// walking the model parent chain so a child sits under its parent's directory
/// exactly as Linux lays sysfs out (e.g. a PCI-backed virtio function lands at
/// `devices/pci0000:00/<bdf>/virtioN`, so `path_id`'s parent walk reaches the
/// PCI transport). Falls back to the flat bus root when the device — or a
/// claimed parent — is absent from the model. # C: O(depth)
pub(crate) fn dev_canon(bus: &str, addr: &str) -> String {
    match find_dev(bus, addr) {
        Some(dev) => dev_canon_dev(&dev),
        None => alloc::format!("{}/{}", dev_root_canon(bus), addr),
    }
}

fn dev_canon_dev(dev: &drv::Device) -> String {
    match dev.parent() {
        Some((pb, pa)) if find_dev(pb, pa).is_some() => {
            alloc::format!("{}/{}", dev_canon(pb, pa), dev.addr)
        }
        _ => alloc::format!("{}/{}", dev_root_canon(dev.bus), dev.addr),
    }
}

/// `../` sequence that climbs from a device directory at `canon` back to
/// `/sys`, so relative `subsystem`/`driver`/`parent` links resolve at any
/// nesting depth. # C: O(depth)
pub(crate) fn ups_prefix(canon: &str) -> String {
    "../".repeat(canon.split('/').count())
}
