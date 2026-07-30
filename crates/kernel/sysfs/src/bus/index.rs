extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{mk_mode, DirContext, FileOps, FileType, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError};

use crate::DIR_PERM;

use super::device::{dev_canon_exact, make_device_link_inode};
use super::ids::{INO_SYS_DEV_BLOCK, INO_SYS_DEV_CHAR};

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
pub(super) fn dev_devpath(dev: &drv::Device) -> Option<String> {
    if dev.bus == "drm" {
        return crate::drm::card_devpath(dev);
    }
    if dev.bus == "input" {
        return crate::input::dev_devpath(dev);
    }
    Some(alloc::format!("/{}", dev_canon_exact(dev)?))
}

fn dev_index_target(dev: &drv::Device) -> Option<Vec<u8>> {
    if let Some(target) = crate::drm::dev_index_target(dev) {
        return Some(target);
    }
    if dev.bus == "input" {
        return crate::input::dev_index_target(dev);
    }
    Some(alloc::format!("../../{}", dev_canon_exact(dev)?).into_bytes())
}

/// `/sys/dev/char` and `/sys/dev/block` reverse dev_t indexes. Linux exposes
/// each `<major>:<minor>` as a symlink to the owning device kobject; deriving
/// this from `drv::devices()` keeps add/remove/readd behavior registry-owned.
struct SysDevIndexOps;
impl InodeOps for SysDevIndexOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let kind = inode.private::<DevIndexData>().ok_or(VfsError::Einval)?.kind;
        let dev = find_dev_by_index(kind, name).ok_or(VfsError::Enoent)?;
        let target = dev_index_target(&dev).ok_or(VfsError::Enoent)?;
        Ok(make_device_link_inode(dev, target))
    }
}
impl FileOps for SysDevIndexOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let kind = inode.private::<DevIndexData>().ok_or(VfsError::Einval)?.kind;
        let mut names: Vec<String> = Vec::new();
        for dev in drv::devices().iter() {
            let Some((major, minor)) = dev.dev_t else { continue; };
            if dev_index_kind(dev) != kind { continue; }
            if dev_index_target(dev).is_none() { continue; }
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
