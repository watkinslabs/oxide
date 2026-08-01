use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::{mk_mode, DirContext, FileOps, FileType, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError};

use super::device::make_input_parent_dir;
use super::model::{input_devs, parent_name, InputDevInfo, INO_INPUT_DIR, INO_VIRT_INPUT};
use crate::DIR_PERM;

fn children(bus: &str, addr: &str) -> Vec<InputDevInfo> {
    input_devs().into_iter()
        .filter(|info| info.device.parent() == Some((bus, addr)))
        .collect()
}

/// Whether this transport owns at least one inputN child. # C: O(N_devices)
pub(crate) fn has_parented_inputs(bus: &str, addr: &str) -> bool {
    !children(bus, addr).is_empty()
}

struct TransportInputData {
    bus: String,
    addr: String,
}

struct TransportInputOps;

impl InodeOps for TransportInputOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let parent = inode.private::<TransportInputData>().ok_or(VfsError::Einval)?;
        let info = children(&parent.bus, &parent.addr).into_iter()
            .find(|info| parent_name(info) == name)
            .ok_or(VfsError::Enoent)?;
        Ok(make_input_parent_dir(info.addr))
    }
}

impl FileOps for TransportInputOps {
    /// kernfs / procfs attributes always install a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let parent = inode.private::<TransportInputData>().ok_or(VfsError::Einval)?;
        let children = children(&parent.bus, &parent.addr);
        let names: Vec<String> = children.iter().map(parent_name).collect();
        crate::readdir::emit_names(inode, ctx, names.iter().map(|n| n.as_str()),
            FileType::Directory)
    }
}

/// The transport's Linux `input/` child directory. # C: O(1)
pub(crate) fn make_transport_input_dir(bus: &str, addr: &str) -> InodeRef {
    InodeBuilder::new(
        INO_INPUT_DIR,
        mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(TransportInputOps),
        Arc::new(TransportInputOps),
    )
    .private(Arc::new(TransportInputData {
        bus: String::from(bus),
        addr: String::from(addr),
    }))
    .build()
}

struct VirtualInputOps;

impl InodeOps for VirtualInputOps {
    fn lookup(&self, _inode: &Inode, name: &str) -> KResult<InodeRef> {
        let info = input_devs().into_iter()
            .filter(|info| info.device.parent().is_none())
            .find(|info| parent_name(info) == name)
            .ok_or(VfsError::Enoent)?;
        Ok(make_input_parent_dir(info.addr))
    }
}

impl FileOps for VirtualInputOps {
    /// kernfs / procfs attributes always install a `->poll`. # C: O(1)
    fn can_poll(&self, _file: &vfs::File) -> bool { true }
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let devices: Vec<InputDevInfo> = input_devs().into_iter()
            .filter(|info| info.device.parent().is_none())
            .collect();
        let names: Vec<String> = devices.iter().map(parent_name).collect();
        crate::readdir::emit_names(inode, ctx, names.iter().map(|n| n.as_str()),
            FileType::Directory)
    }
}

pub(super) fn make_virtual_input_dir() -> InodeRef {
    InodeBuilder::new(
        INO_VIRT_INPUT,
        mk_mode(FileType::Directory, DIR_PERM),
        Arc::new(VirtualInputOps),
        Arc::new(VirtualInputOps),
    )
    .build()
}
