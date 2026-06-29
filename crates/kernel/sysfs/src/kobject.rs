//! sysfs attribute model (Linux `include/linux/sysfs.h` + `fs/sysfs/`).
//! D27: the kobject `struct attribute` + `struct attribute_group` + `struct
//! sysfs_ops { show, store }` shape. A kobject's directory is populated from an
//! `AttrGroup` (the default attribute list) and each attribute file's contents
//! come from the object's `SysfsOps::show` (and writes go to `store`) — instead
//! of a per-directory ad-hoc `match name` that duplicated the attribute name
//! list and the body builder in two places.
//!
//! Scope (D27 partial): this provides the attribute/sysfs_ops abstraction and
//! drives the dynamic `/sys/class/net/<if>` attribute set from it. A full
//! `kset`/`kobject`-registration-driven population of the whole `/sys` tree
//! (devices auto-creating their dirs on `device_add`) is the remainder.

use alloc::sync::Arc;
use alloc::vec::Vec;
use vfs::{default_inode_ops, mk_mode, FileOps, FileType, Ino, Inode,
          InodeBuilder, InodeRef, KResult, VfsError};

/// A sysfs attribute (`struct attribute`): a `name` + a `mode`. The bytes are
/// produced on demand by the owning object's [`SysfsOps`], never stored here.
#[derive(Copy, Clone)]
pub struct Attribute {
    pub name: &'static str,
    pub mode: u16,
}

/// A default attribute group (`struct attribute_group`): the attribute set a
/// kobject's directory is populated with.
pub struct AttrGroup {
    pub attrs: &'static [Attribute],
}

impl AttrGroup {
    /// Find an attribute by name. # C: O(n)
    pub fn find(&self, name: &str) -> Option<&Attribute> {
        self.attrs.iter().find(|a| a.name == name)
    }
}

/// The `struct sysfs_ops` show/store dispatch for a kobject. `show` renders the
/// current value of `attr`; `store` consumes a write (default: read-only).
pub trait SysfsOps: Send + Sync {
    /// Render attribute `attr`'s current bytes (Linux `sysfs_ops->show`).
    fn show(&self, attr: &str) -> Option<Vec<u8>>;
    /// Consume a write to attribute `attr` (Linux `sysfs_ops->store`).
    /// # C: O(n)
    fn store(&self, _attr: &str, _buf: &[u8]) -> KResult<usize> { Err(VfsError::Erofs) }
}

/// `i_private` for an attribute file: the owning object's ops + the attribute
/// it represents. # C: n/a
struct AttrFileData {
    ops:  Arc<dyn SysfsOps>,
    name: &'static str,
}

/// `f_op` for a sysfs attribute file: `read` calls `sysfs_ops->show` (rendered
/// fresh per open, windowed), `write` calls `sysfs_ops->store`.
struct AttrFileOps;
impl FileOps for AttrFileOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<AttrFileData>().ok_or(VfsError::Einval)?;
        let body = d.ops.show(d.name).unwrap_or_default();
        Ok(super::read_window(&body, off, buf))
    }
    fn write(&self, inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        let d = inode.private::<AttrFileData>().ok_or(VfsError::Einval)?;
        d.ops.store(d.name, buf)
    }
}

/// Build the attribute file inode for `attr` backed by `ops` (Linux
/// `sysfs_add_file`). # C: O(1)
pub fn make_attr_inode(attr: &Attribute, ops: Arc<dyn SysfsOps>, ino: Ino) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, attr.mode), default_inode_ops(), Arc::new(AttrFileOps))
        .private(Arc::new(AttrFileData { ops, name: attr.name }))
        .build()
}
