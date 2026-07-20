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

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use vfs::{mk_mode, File, FileOps, FileType, Ino, Inode, InodeOps,
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
    fn show(&self, attr: &str) -> KResult<Vec<u8>>;
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

/// Sysfs attributes are regular-looking files whose writes are commands, not
/// stored file contents. Linux accepts `O_TRUNC` on them (including Rust's
/// `fs::write`), so truncation is a no-op before `sysfs_ops->store`.
struct AttrInodeOps;
impl InodeOps for AttrInodeOps {
    fn truncate(&self, _inode: &Inode, _len: u64) -> KResult<()> { Ok(()) }
}

/// `f_op` for a sysfs attribute file. Linux materializes `->show()` once for
/// an open sysfs file, then serves every partial read from that same result.
/// This matters for command-like read attributes such as zram-control/hot_add.
struct AttrFileOps;
impl FileOps for AttrFileOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<AttrFileData>().ok_or(VfsError::Einval)?;
        let body = d.ops.show(d.name)?;
        Ok(super::read_window(&body, off, buf))
    }
    fn read_file(&self, file: &File, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let raw = file.private_data();
        if raw == 0 { return Err(VfsError::Einval); }
        // SAFETY: `on_open_file` allocates exactly one immutable Vec and stores
        // its non-null pointer in this open file's private_data; release drops
        // it only after this final open-description reference is gone.
        let body = unsafe { &*(raw as *const Vec<u8>) };
        Ok(super::read_window(body, off, buf))
    }
    fn write(&self, inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        let d = inode.private::<AttrFileData>().ok_or(VfsError::Einval)?;
        d.ops.store(d.name, buf)
    }
    fn on_open_file(&self, file: &File) -> KResult<()> {
        // A write-only sysfs attribute has no `show` method in Linux.  Do not
        // call it merely because the leaf was opened: commands such as
        // zram's `mem_limit` must be usable through `O_WRONLY|O_TRUNC` even
        // though a read is prohibited by the inode mode.
        if !file.f_mode().contains(vfs::Fmode::READ) { return Ok(()); }
        let d = file.inode().private::<AttrFileData>().ok_or(VfsError::Einval)?;
        let body = Box::new(d.ops.show(d.name)?);
        file.set_private_data(Box::into_raw(body) as u64);
        Ok(())
    }
    fn on_release_file(&self, file: &File) {
        let raw = file.private_data();
        if raw == 0 { return; }
        // SAFETY: on_open_file allocated this Vec exclusively for this File,
        // and File::drop invokes release exactly once at last close.
        unsafe { drop(Box::from_raw(raw as *mut Vec<u8>)); }
        file.set_private_data(0);
    }
}

/// Build the attribute file inode for `attr` backed by `ops` (Linux
/// `sysfs_add_file`). # C: O(1)
pub fn make_attr_inode(attr: &Attribute, ops: Arc<dyn SysfsOps>, ino: Ino) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, attr.mode), Arc::new(AttrInodeOps), Arc::new(AttrFileOps))
        .private(Arc::new(AttrFileData { ops, name: attr.name }))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FailingOps;
    impl SysfsOps for FailingOps {
        fn show(&self, _attr: &str) -> KResult<Vec<u8>> { Err(VfsError::Enodev) }
    }

    struct StaticOps;
    impl SysfsOps for StaticOps {
        fn show(&self, _attr: &str) -> KResult<Vec<u8>> { Ok(b"ok\n".to_vec()) }
    }

    struct StoreOps;
    impl SysfsOps for StoreOps {
        fn show(&self, _attr: &str) -> KResult<Vec<u8>> { Ok(Vec::new()) }
        fn store(&self, attr: &str, buf: &[u8]) -> KResult<usize> {
            if attr != "live" || buf != b"value" { return Err(VfsError::Einval); }
            Ok(buf.len())
        }
    }

    #[test]
    fn attr_read_propagates_show_error() {
        let attr = Attribute { name: "dead", mode: 0o444 };
        let inode = make_attr_inode(&attr, Arc::new(FailingOps), 0x5510);
        let mut buf = [0u8; 8];
        assert_eq!(inode.read(0, &mut buf), Err(VfsError::Enodev));
    }

    #[test]
    fn attr_read_still_windows_success_body() {
        let attr = Attribute { name: "live", mode: 0o444 };
        let inode = make_attr_inode(&attr, Arc::new(StaticOps), 0x5511);
        let mut buf = [0u8; 8];
        let n = inode.read(1, &mut buf).expect("read attr");
        assert_eq!(&buf[..n], b"k\n");
    }

    #[test]
    fn attr_open_with_truncate_reaches_store() {
        let attr = Attribute { name: "live", mode: 0o644 };
        let inode = make_attr_inode(&attr, Arc::new(StoreOps), 0x5512);
        let dentry = vfs::Dentry::new_root(Arc::clone(&inode));
        let fdt = vfs::FdTable::new();
        let fd = vfs::file::install_open_at(&fdt, inode, dentry,
            vfs::OpenFlags::O_WRONLY | vfs::OpenFlags::O_TRUNC, 0, vfs::FileCred::root(), usize::MAX, None).unwrap();
        assert_eq!(fdt.get(fd).unwrap().write(b"value"), Ok(b"value".len()));
    }

    #[test]
    fn write_only_attr_open_does_not_require_show() {
        let attr = Attribute { name: "live", mode: 0o200 };
        let inode = make_attr_inode(&attr, Arc::new(FailingOps), 0x5513);
        let dentry = vfs::Dentry::new_root(Arc::clone(&inode));
        let fdt = vfs::FdTable::new();
        let fd = vfs::file::install_open_at(&fdt, inode, dentry,
            vfs::OpenFlags::O_WRONLY | vfs::OpenFlags::O_TRUNC, 0,
            vfs::FileCred::root(), usize::MAX, None).expect("open write-only attr");
        assert_eq!(fdt.get(fd).unwrap().write(b"value"), Err(VfsError::Erofs));
    }
}
