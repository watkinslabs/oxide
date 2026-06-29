//! ATTR_SIZE truncate must invalidate the inode page cache (Linux
//! `truncate_setsize` → `truncate_pagecache`, mm/truncate.c). `simple_setattr`,
//! after driving `i_op->truncate`, evicts resident `i_mapping` pages lying
//! wholly beyond the new `i_size`, so a later refault re-reads zeros/backing
//! rather than stale post-EOF bytes. The eviction is a no-op on grow (nothing
//! resident past the new size) and is skipped entirely for an inode without a
//! page cache. Synthetic `Inode` carrying a recording `AddressSpaceOps`.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use vfs::inode::Inode;
use vfs::mapping::AddressSpaceOps;
use vfs::setattr::{notify_change, Iattr, ATTR_SIZE};
use vfs::{Cred, FileType, Idmap, InodeRef, KResult, VfsError};

/// Address space that records every `invalidate_range(start, end)` the truncate
/// path issues — the page-drop call under test.
struct RecMapping { calls: Mutex<Vec<(u64, u64)>>, len: AtomicU64 }

impl AddressSpaceOps for RecMapping {
    fn shared_frame(&self, _off: u64) -> Option<u64> { None }
    fn read_at(&self, _off: u64, _dst: &mut [u8]) -> Result<usize, ()> { Ok(0) }
    fn size(&self) -> u64 { self.len.load(Ordering::Acquire) }
    fn invalidate_range(&self, start: u64, end: u64) -> usize {
        self.calls.lock().unwrap().push((start, end));
        0
    }
}

/// Regular file whose `truncate` resizes the logical size and whose `i_mapping`
/// is the recording address space.
struct MappedFile { size: AtomicU64, mapping: RecMapping }

impl MappedFile {
    fn new(len: u64) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            size: AtomicU64::new(len),
            mapping: RecMapping { calls: Mutex::new(Vec::new()), len: AtomicU64::new(len) },
        })
    }
    fn calls(&self) -> Vec<(u64, u64)> { self.mapping.calls.lock().unwrap().clone() }
}

impl Inode for MappedFile {
    fn ino(&self) -> vfs::Ino { 1 }
    fn file_type(&self) -> FileType { FileType::Regular }
    fn size(&self) -> u64 { self.size.load(Ordering::Acquire) }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    fn perm(&self) -> Option<u16> { Some(0o644) }
    fn uid(&self) -> Option<u32> { Some(0) }
    fn gid(&self) -> Option<u32> { Some(0) }
    fn truncate(&self, len: u64) -> KResult<()> {
        self.size.store(len, Ordering::Release);
        self.mapping.len.store(len, Ordering::Release);
        Ok(())
    }
    fn i_mapping(&self) -> Option<&dyn AddressSpaceOps> { Some(&self.mapping) }
}

fn size_change(n: u64) -> Iattr { Iattr { valid: ATTR_SIZE, size: n, ..Default::default() } }

/// Shrink: pages wholly beyond the new size are invalidated to EOF.
#[test]
fn shrink_invalidates_mapping_beyond_new_size() {
    let raw = MappedFile::new(16384);
    let inode: InodeRef = raw.clone();
    let mut ia = size_change(4096);
    notify_change(&Idmap::identity(), &inode, &mut ia, &Cred::root()).unwrap();
    assert_eq!(inode.size(), 4096);
    // Exactly one invalidation, from the new size to EOF (Linux truncate range).
    assert_eq!(raw.calls(), vec![(4096, u64::MAX)]);
}

/// Truncate to zero: the whole cache is invalidated [0, EOF).
#[test]
fn truncate_to_zero_invalidates_all() {
    let raw = MappedFile::new(8192);
    let inode: InodeRef = raw.clone();
    let mut ia = size_change(0);
    notify_change(&Idmap::identity(), &inode, &mut ia, &Cred::root()).unwrap();
    assert_eq!(raw.calls(), vec![(0, u64::MAX)]);
}

/// Grow still issues the invalidation at the new size (a no-op against an empty
/// post-EOF region) — matching Linux's unconditional `truncate_pagecache`.
#[test]
fn grow_invalidates_from_new_size() {
    let raw = MappedFile::new(4096);
    let inode: InodeRef = raw.clone();
    let mut ia = size_change(12288);
    notify_change(&Idmap::identity(), &inode, &mut ia, &Cred::root()).unwrap();
    assert_eq!(inode.size(), 12288);
    assert_eq!(raw.calls(), vec![(12288, u64::MAX)]);
}

/// An inode WITHOUT a page cache (`i_mapping` None) truncates cleanly with no
/// invalidation path — the `if let Some` guard skips it, no panic.
#[test]
fn no_mapping_inode_truncates_without_invalidate() {
    struct Plain { size: AtomicU64 }
    impl Inode for Plain {
        fn ino(&self) -> vfs::Ino { 2 }
        fn file_type(&self) -> FileType { FileType::Regular }
        fn size(&self) -> u64 { self.size.load(Ordering::Acquire) }
        fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
        fn perm(&self) -> Option<u16> { Some(0o644) }
        fn uid(&self) -> Option<u32> { Some(0) }
        fn gid(&self) -> Option<u32> { Some(0) }
        fn truncate(&self, len: u64) -> KResult<()> { self.size.store(len, Ordering::Release); Ok(()) }
    }
    let inode: InodeRef = std::sync::Arc::new(Plain { size: AtomicU64::new(100) });
    let mut ia = size_change(10);
    notify_change(&Idmap::identity(), &inode, &mut ia, &Cred::root()).unwrap();
    assert_eq!(inode.size(), 10);
}
