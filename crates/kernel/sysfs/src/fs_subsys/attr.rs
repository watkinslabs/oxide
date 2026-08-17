//! A `/sys/fs` attribute file whose value is produced on every read.
//!
//! A filesystem's sysfs attributes report LIVE state — free segments, a
//! checkpoint flag word, a feature bit. Serving them from bytes captured when
//! the file was created would report the state at mount forever, which reads
//! exactly like a working attribute and is worse than an absent one.
//!
//! So the two halves of the upstream `sysfs_ops` vector — `show` and `store`
//! — arrive as callables owned by the filesystem, and this module adapts them
//! to the crate's existing attribute-file inode ([`crate::kobject`]). The
//! filesystem never names a sysfs type, and sysfs never names a filesystem's.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use vfs::{Ino, InodeRef, KResult, VfsError};

use crate::kobject::{make_named_attr_inode, SysfsOps};

/// Renders an attribute's current bytes (upstream `sysfs_ops->show`).
pub type ShowFn = Arc<dyn Fn() -> KResult<Vec<u8>> + Send + Sync>;

/// Consumes a write to an attribute (upstream `sysfs_ops->store`). Returns the
/// count accepted, which is what the caller's `write(2)` reports.
pub type StoreFn = Arc<dyn Fn(&[u8]) -> KResult<usize> + Send + Sync>;

/// The `sysfs_ops` of a `/sys/fs` attribute, holding the filesystem's own two
/// callables. One attribute per object: the name is fixed at construction, so
/// the dispatch upstream does by attribute name is already resolved.
struct ClosureOps {
    show:  ShowFn,
    store: Option<StoreFn>,
}

impl SysfsOps for ClosureOps {
    /// # C: cost of the filesystem's own renderer
    fn show(&self, _attr: &str) -> KResult<Vec<u8>> { (self.show)() }

    /// A read-only attribute reports `EROFS` rather than accepting and
    /// discarding the write. # C: cost of the filesystem's own writer
    fn store(&self, _attr: &str, buf: &[u8]) -> KResult<usize> {
        match self.store.as_ref() {
            Some(f) => f(buf),
            None => Err(VfsError::Erofs),
        }
    }
}

/// Base of the inode numbers `/sys/fs` attribute files are minted from. Above
/// every hand-assigned sysfs id, so a new class cannot walk into this band.
const FS_ATTR_INO_BASE: Ino = 0x51F0_0000;

/// Attribute files this module has minted. An inode number is an identity the
/// superblock's cache keys on: two files sharing one would make the second
/// resolve to the first's contents.
static NEXT_INO: AtomicU64 = AtomicU64::new(0);

/// The next unused attribute inode number. # C: O(1)
pub(crate) fn next_ino() -> Ino {
    FS_ATTR_INO_BASE + NEXT_INO.fetch_add(1, Ordering::Relaxed)
}

/// Build the inode for one live attribute file. `mode` is the permission word
/// the directory entry carries — read-only attributes take `0444`, writable
/// ones `0644`, matching what the filesystem declared.
/// # C: O(1)
pub(crate) fn make(name: String, mode: u16, show: ShowFn, store: Option<StoreFn>) -> InodeRef {
    make_named_attr_inode(name, mode, Arc::new(ClosureOps { show, store }), next_ino())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two attribute files must not share an inode number: the superblock
    /// inode cache keys on it, so a collision serves one file's bytes from
    /// the other's inode.
    #[test]
    fn minted_inode_numbers_are_distinct_and_in_band() {
        let a = next_ino();
        let b = next_ino();
        assert_ne!(a, b);
        assert!(a >= FS_ATTR_INO_BASE && b >= FS_ATTR_INO_BASE);
    }

    /// The value must come from the callable on every read, not from a
    /// snapshot taken when the file was created.
    #[test]
    fn show_runs_on_every_read() {
        use core::sync::atomic::AtomicU32;
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let show: ShowFn = Arc::new(|| {
            let n = SEQ.fetch_add(1, Ordering::Relaxed);
            Ok(alloc::format!("{n}\n").into_bytes())
        });
        let inode = make(String::from("live"), 0o444, show, None);
        let mut buf = [0u8; 8];
        let n = inode.read(0, &mut buf).expect("first read");
        assert_eq!(&buf[..n], b"0\n");
        let n = inode.read(0, &mut buf).expect("second read");
        assert_eq!(&buf[..n], b"1\n");
    }

    /// An attribute the filesystem declared read-only refuses a write with
    /// the errno a read-only sysfs file gives.
    #[test]
    fn read_only_attribute_refuses_a_write() {
        let show: ShowFn = Arc::new(|| Ok(b"x\n".to_vec()));
        let inode = make(String::from("ro"), 0o444, show, None);
        assert_eq!(inode.write(0, b"1"), Err(VfsError::Erofs));
    }

    /// A writable attribute reaches its `store`, and the count it returns is
    /// what the write reports.
    #[test]
    fn writable_attribute_reaches_store() {
        let show: ShowFn = Arc::new(|| Ok(b"0\n".to_vec()));
        let store: StoreFn = Arc::new(|b: &[u8]| {
            if b == b"1" { Ok(b.len()) } else { Err(VfsError::Einval) }
        });
        let inode = make(String::from("rw"), 0o644, show, Some(store));
        assert_eq!(inode.write(0, b"1"), Ok(1));
        assert_eq!(inode.write(0, b"2"), Err(VfsError::Einval));
    }
}
