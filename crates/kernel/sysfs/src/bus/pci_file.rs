// Attribute-file inodes for a PCI function. PCI attributes need what the
// generic sysfs attribute file does not carry: the opener's capability (the
// `config` window, the writes that can wedge a function) and the byte offset
// (`config` is a binary blob, not a rendered line).

use alloc::sync::Arc;
use alloc::vec::Vec;

use namespace_identity::{NamespaceKind, NamespaceRef};
use vfs::{mk_mode, File, FileOps, FileType, Inode, InodeBuilder, InodeRef, KResult, VfsError};

use crate::kobject::{attr_inode_ops, Attribute};

use super::ids::INO_ATTR;
use super::pci_attrs::{self, config, show, store, CONFIG_ATTR};

/// `i_private` of a PCI attribute file. # C: n/a
struct PciAttrData {
    device: Arc<drv::Device>,
    attr:   &'static Attribute,
}

/// Whether the opener held `CAP_SYS_ADMIN` in the initial user namespace
/// (Linux `file_ns_capable(filp, &init_user_ns, CAP_SYS_ADMIN)`). # C: O(1)
fn opener_is_privileged(file: &File) -> bool {
    let cred = file.file_cred();
    cred.has_cap(sched::cap::SYS_ADMIN)
        && NamespaceRef::ptr_eq(
            cred.user_namespace(),
            &namespace_identity::initial(NamespaceKind::User),
        )
}

struct PciAttrFileOps;

impl PciAttrFileOps {
    /// Serve one read of a non-`config` attribute. # C: O(n)
    fn text_read(data: &PciAttrData, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let body = Self::text_body(data)?;
        Ok(crate::read_window(&body, off, buf))
    }

    /// Render the attribute body, failing closed on a device that is no longer
    /// registered. # C: O(n)
    fn text_body(data: &PciAttrData) -> KResult<Vec<u8>> {
        super::device::dev_canon_exact(&data.device).ok_or(VfsError::Enodev)?;
        match show::body(&data.device, data.attr.name) {
            Some(body) => Ok(body),
            // uevent / modalias / driver_override are rendered by the shared
            // device kobject, which owns their bus-independent form.
            None => super::device::dev_attr(&data.device, data.attr.name).ok_or(VfsError::Enoent),
        }
    }

    /// Serve one write, with the opener's privilege. # C: O(n)
    fn dispatch_write(data: &PciAttrData, privileged: bool, off: u64, buf: &[u8]) -> KResult<usize> {
        super::device::dev_canon_exact(&data.device).ok_or(VfsError::Enoent)?;
        if data.attr.name == CONFIG_ATTR {
            return config::write(&data.device, off, buf);
        }
        match store::store(&data.device, data.attr.name, buf, privileged) {
            Some(result) => result,
            None => super::device::dev_store(&data.device, data.attr.name, buf),
        }
    }
}

impl FileOps for PciAttrFileOps {
    fn can_poll(&self, _file: &File) -> bool { true }

    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let data = inode.private::<PciAttrData>().ok_or(VfsError::Einval)?;
        if data.attr.name == CONFIG_ATTR {
            super::device::dev_canon_exact(&data.device).ok_or(VfsError::Enodev)?;
            // No open file description: serve the unprivileged window, the
            // one every reader is entitled to.
            return config::read(&data.device, false, off, buf);
        }
        Self::text_read(&data, off, buf)
    }

    fn read_file(&self, file: &File, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let data = file.inode().private::<PciAttrData>().ok_or(VfsError::Einval)?;
        if data.attr.name == CONFIG_ATTR {
            super::device::dev_canon_exact(&data.device).ok_or(VfsError::Enodev)?;
            return config::read(&data.device, opener_is_privileged(file), off, buf);
        }
        Self::text_read(&data, off, buf)
    }

    fn write(&self, inode: &Inode, off: u64, buf: &[u8]) -> KResult<usize> {
        let data = inode.private::<PciAttrData>().ok_or(VfsError::Einval)?;
        Self::dispatch_write(&data, false, off, buf)
    }

    fn write_file(&self, file: &File, off: u64, buf: &[u8]) -> KResult<usize> {
        let data = file.inode().private::<PciAttrData>().ok_or(VfsError::Einval)?;
        Self::dispatch_write(&data, opener_is_privileged(file), off, buf)
    }
}

/// Attribute-file inode for one PCI function. # C: O(1)
pub(super) fn make_pci_attr_inode(device: Arc<drv::Device>, attr: &'static Attribute) -> InodeRef {
    let size = if attr.name == CONFIG_ATTR { pci::uapi::CFG_SPACE_SIZE as u64 } else { 0 };
    InodeBuilder::new(INO_ATTR, mk_mode(FileType::Regular, attr.mode),
        attr_inode_ops(), Arc::new(PciAttrFileOps))
        .size(size)
        .private(Arc::new(PciAttrData { device, attr }))
        .build()
}

/// Look up one PCI attribute file by name. # C: O(1)
pub(super) fn lookup(device: &Arc<drv::Device>, name: &str) -> Option<InodeRef> {
    let attr = pci_attrs::find_attr(device, name)?;
    Some(make_pci_attr_inode(Arc::clone(device), attr))
}
