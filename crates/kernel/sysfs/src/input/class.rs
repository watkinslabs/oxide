use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{
    mk_mode, DirContext, FileOps, FileType, Inode, InodeBuilder, InodeOps, InodeRef, KResult,
    VfsError,
};

use super::model::{input_devs, parent_name, INO_CLASS_INPUT, INO_INPUT_LINK};
use crate::DIR_PERM;

struct ClassInputOps;

impl InodeOps for ClassInputOps {
    fn lookup(&self, _inode: &Inode, name: &str) -> KResult<InodeRef> {
        let info = input_devs().into_iter()
            .find(|info| info.addr == name || parent_name(info) == name)
            .ok_or(VfsError::Enoent)?;
        let canon = if info.addr == name {
            info.sysfs_event_canon()
        } else {
            info.sysfs_parent_canon()
        }.ok_or(VfsError::Enoent)?;
        Ok(crate::make_symlink_inode_ino(
            alloc::format!("../../{canon}").into_bytes(),
            INO_INPUT_LINK,
        ))
    }
}

impl FileOps for ClassInputOps {
    /// kernfs / procfs attributes always install a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let devices = input_devs();
        let mut names = Vec::with_capacity(devices.len() * 2);
        for device in devices.iter() {
            names.push(parent_name(device));
            names.push(device.addr.clone());
        }
        crate::readdir::emit_names(inode, ctx, names.iter().map(|n| n.as_str()),
            FileType::Symlink)
    }
}

/// Register Linux input class and parentless virtual-device roots. # C: O(1)
pub fn init() {
    crate::register(
        "/sys/devices/virtual/input",
        super::topology::make_virtual_input_dir(),
    );
    crate::register(
        "/sys/class/input",
        InodeBuilder::new(
            INO_CLASS_INPUT,
            mk_mode(FileType::Directory, DIR_PERM),
            Arc::new(ClassInputOps),
            Arc::new(ClassInputOps),
        ).build(),
    );
}

#[cfg(test)]
pub(super) fn make_class_input_dir() -> InodeRef {
    InodeBuilder::new(
        INO_CLASS_INPUT,
        mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(ClassInputOps),
        Arc::new(ClassInputOps),
    ).build()
}
