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

/// PCI BAR resource file: a binary device window selected by its BAR index.
struct PciResourceData { device: Arc<drv::Device>, bar: u8 }

const PCI_RESOURCE_PERM: u16 = 0o600;

struct PciResourceFileOps;
impl FileOps for PciResourceFileOps {
    fn read(&self, _inode: &Inode, _off: u64, _buf: &mut [u8]) -> KResult<usize> { Err(VfsError::Eio) }
    fn write(&self, _inode: &Inode, _off: u64, _buf: &[u8]) -> KResult<usize> { Err(VfsError::Eio) }
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

/// Binary sysfs file for one implemented PCI BAR. # C: O(1)
pub(super) fn make_resource_inode(device: Arc<drv::Device>, bar: u8) -> InodeRef {
    let size = device.resources.iter().find(|r| r.bar == bar)
        .map_or(0, |r| r.end.saturating_sub(r.start).saturating_add(1));
    InodeBuilder::new(INO_ATTR, mk_mode(FileType::Regular, PCI_RESOURCE_PERM),
        attr_inode_ops(), Arc::new(PciResourceFileOps))
        .size(size)
        .private(Arc::new(PciResourceData { device, bar }))
        .build()
}

/// Physical BAR range accepted by `mmap(2)`, or the resource's Linux errno.
/// # C: O(N_resources)
pub(crate) fn resource_mmap_backing(inode: &InodeRef) -> Option<Result<(u64, u64), VfsError>> {
    let data = inode.private::<PciResourceData>()?;
    if super::device::dev_canon_exact(&data.device).is_none() { return Some(Err(VfsError::Enodev)); }
    Some(resource_window(&data.device, data.bar))
}

/// BAR window suitable for a raw-PFN mapping. # C: O(N_resources)
fn resource_window(device: &drv::Device, bar: u8) -> Result<(u64, u64), VfsError> {
    let Some(r) = device.resources.iter().find(|r| r.bar == bar) else { return Err(VfsError::Enodev); };
    if r.flags & drv::IORESOURCE_MEM == 0 { return Err(VfsError::Eio); }
    let size = r.end.checked_sub(r.start).and_then(|n| n.checked_add(1)).ok_or(VfsError::Einval)?;
    let page = hal::PAGE_SIZE_BYTES;
    if r.start & (page - 1) != 0 { return Err(VfsError::Einval); }
    size.checked_add(page - 1).map(|n| (r.start, n & !(page - 1))).ok_or(VfsError::Einval)
}

#[cfg(test)]
mod resource_tests {
    use super::*;
    use alloc::string::ToString;

    fn device(r: drv::Resource) -> drv::Device {
        drv::Device::new("pci", "0000:00:03.0".to_string(), 0x1af4, 0x1041, 0)
            .with_resources(alloc::vec![r])
    }

    #[test]
    fn memory_bar_maps_its_page_rounded_window() {
        let d = device(drv::Resource { bar: 0, start: 0x4000_0000, end: 0x4000_0123, flags: drv::IORESOURCE_MEM });
        assert_eq!(resource_window(&d, 0), Ok((0x4000_0000, hal::PAGE_SIZE_BYTES)));
    }

    #[test]
    fn io_bar_and_unaligned_memory_bar_are_refused() {
        let io = device(drv::Resource { bar: 0, start: 0xc000, end: 0xc003, flags: drv::IORESOURCE_IO });
        assert_eq!(resource_window(&io, 0), Err(VfsError::Eio));
        let unaligned = device(drv::Resource { bar: 0, start: 0x4000_0001, end: 0x4000_1000, flags: drv::IORESOURCE_MEM });
        assert_eq!(resource_window(&unaligned, 0), Err(VfsError::Einval));
    }
}

/// Look up one PCI attribute file by name. # C: O(1)
pub(super) fn lookup(device: &Arc<drv::Device>, name: &str) -> Option<InodeRef> {
    let attr = pci_attrs::find_attr(device, name)?;
    Some(make_pci_attr_inode(Arc::clone(device), attr))
}
