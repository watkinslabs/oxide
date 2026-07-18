extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{mk_mode, DirContext, FileOps, FileType, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError};

use crate::DIR_PERM;

use super::device::make_link_inode;
use super::ids::{dev_root_canon, INO_SYS_DEV_BLOCK, INO_SYS_DEV_CHAR};

#[derive(Copy, Clone, Eq, PartialEq)]
pub(super) enum DevIndexKind { Char, Block }

pub(super) fn dev_index_kind(dev: &drv::Device) -> DevIndexKind {
    if dev.dev_class == "block" { DevIndexKind::Block } else { DevIndexKind::Char }
}

fn dev_index_name(major: u32, minor: u32) -> String {
    alloc::format!("{}:{}", major, minor)
}

pub(super) fn find_dev_by_index(kind: DevIndexKind, name: &str) -> Option<Arc<drv::Device>> {
    drv::devices().into_iter().find(|d| {
        let Some((major, minor)) = d.dev_t else { return false; };
        dev_index_kind(d) == kind && dev_index_name(major, minor) == name
    })
}

/// Canonical `/sys` DEVPATH for a device's uevent (Linux `add@<devpath>`).
/// udevd reads `/sys<DEVPATH>/uevent`, so this MUST match the real sysfs dir.
/// DRM cards live under their model parent (`crate::drm`), so a PCI-backed card
/// resolves to `devices/pci0000:00/<bdf>/virtioN/drm/cardN` — the nested path
/// `path_id`'s parent walk needs. Nesting-bus devices (pci/virtio/platform) use
/// their canonical nested path; class devices keep the flat `virtual/<class>`
/// root. # C: O(depth)
pub(super) fn dev_devpath(dev: &drv::Device) -> String {
    if dev.bus == "drm" {
        if let Some(path) = crate::drm::card_devpath(dev) {
            return path;
        }
        let sysname = dev.addr.rsplit('/').next().unwrap_or(dev.addr.as_str());
        return alloc::format!("/devices/virtual/drm/{}", sysname);
    }
    if dev.bus == "input" {
        return alloc::format!("/devices/virtual/input/{}/{}",
            crate::input::parent_name(&dev.addr), dev.addr);
    }
    if super::device::is_nesting_bus(dev.bus) {
        return alloc::format!("/{}", super::device::dev_canon(dev.bus, &dev.addr));
    }
    alloc::format!("/{}/{}", dev_root_canon(dev.bus), dev.addr)
}

fn dev_index_target(dev: &drv::Device) -> Vec<u8> {
    if let Some(target) = crate::drm::dev_index_target(dev) {
        return target;
    }
    if let Some(target) = crate::input::dev_index_target(dev) {
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

pub(super) fn make_sys_dev_index_inode(kind: DevIndexKind) -> InodeRef {
    let ino = match kind {
        DevIndexKind::Char => INO_SYS_DEV_CHAR,
        DevIndexKind::Block => INO_SYS_DEV_BLOCK,
    };
    InodeBuilder::new(ino, mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(SysDevIndexOps), Arc::new(SysDevIndexOps))
        .private(Arc::new(DevIndexData { kind }))
        .build()
}
