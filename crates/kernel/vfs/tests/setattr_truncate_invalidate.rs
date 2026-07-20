//! ATTR_SIZE truncate must invalidate the inode page cache (Linux
//! `truncate_setsize` → `truncate_pagecache`, mm/truncate.c). `simple_setattr`,
//! after driving `i_op->truncate`, evicts resident `i_mapping` pages lying
//! wholly beyond the new `i_size`, so a later refault re-reads zeros/backing
//! rather than stale post-EOF bytes. The eviction is a no-op on grow (nothing
//! resident past the new size) and is skipped entirely for an inode without a
//! page cache. Synthetic `Inode` carrying a recording `AddressSpaceOps`.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use vfs::inode::Inode;
use vfs::mapping::AddressSpaceOps;
use vfs::setattr::{notify_change, Iattr, ATTR_SIZE};
use vfs::{default_file_ops, mk_mode, InodeBuilder, InodeOps};
use vfs::{Cred, FileType, Idmap, InodeRef, KResult};

/// Address space that records every `invalidate_range(start, end)` the truncate
/// path issues — the page-drop call under test. Doubles as the inode's backend
/// state (`i_private`) so the truncate hook can update `len`.
struct RecMapping { calls: Mutex<Vec<(u64, u64)>>, len: AtomicU64 }

impl RecMapping {
    fn calls(&self) -> Vec<(u64, u64)> { self.calls.lock().unwrap().clone() }
}

impl AddressSpaceOps for RecMapping {
    fn shared_frame(&self, _off: u64) -> vfs::KResult<Option<vfs::SharedFrame>> { Ok(None) }
    fn read_at(&self, _off: u64, _dst: &mut [u8]) -> vfs::KResult<usize> { Ok(0) }
    fn size(&self) -> u64 { self.len.load(Ordering::Acquire) }
    fn invalidate_range(&self, start: u64, end: u64) -> usize {
        self.calls.lock().unwrap().push((start, end));
        0
    }
}

/// `i_op->truncate`: update the inode `i_size` and the recording mapping's `len`.
struct MappedOps;
impl InodeOps for MappedOps {
    fn truncate(&self, inode: &Inode, len: u64) -> KResult<()> {
        inode.set_size(len);
        if let Some(m) = inode.private::<RecMapping>() { m.len.store(len, Ordering::Release); }
        Ok(())
    }
}

/// Regular file (perm 0o644, owner root) whose `i_mapping` is the recording
/// address space. Returns the inode + the mapping so the test can read the
/// recorded invalidations.
fn make_mapped(len: u64) -> (InodeRef, Arc<RecMapping>) {
    let map = Arc::new(RecMapping { calls: Mutex::new(Vec::new()), len: AtomicU64::new(len) });
    let inode = InodeBuilder::new(1, mk_mode(FileType::Regular, 0o644), Arc::new(MappedOps), default_file_ops())
        .owner(0, 0).size(len).mapping(map.clone()).private(map.clone()).build();
    (inode, map)
}

fn size_change(n: u64) -> Iattr { Iattr { valid: ATTR_SIZE, size: n, ..Default::default() } }

/// Shrink: pages wholly beyond the new size are invalidated to EOF.
#[test]
fn shrink_invalidates_mapping_beyond_new_size() {
    let (inode, raw) = make_mapped(16384);
    let mut ia = size_change(4096);
    notify_change(&Idmap::identity(), &inode, &mut ia, &Cred::root()).unwrap();
    assert_eq!(inode.size(), 4096);
    // Exactly one invalidation, from the new size to EOF (Linux truncate range).
    assert_eq!(raw.calls(), vec![(4096, u64::MAX)]);
}

/// Truncate to zero: the whole cache is invalidated [0, EOF).
#[test]
fn truncate_to_zero_invalidates_all() {
    let (inode, raw) = make_mapped(8192);
    let mut ia = size_change(0);
    notify_change(&Idmap::identity(), &inode, &mut ia, &Cred::root()).unwrap();
    assert_eq!(raw.calls(), vec![(0, u64::MAX)]);
}

/// Grow still issues the invalidation at the new size (a no-op against an empty
/// post-EOF region) — matching Linux's unconditional `truncate_pagecache`.
#[test]
fn grow_invalidates_from_new_size() {
    let (inode, raw) = make_mapped(4096);
    let mut ia = size_change(12288);
    notify_change(&Idmap::identity(), &inode, &mut ia, &Cred::root()).unwrap();
    assert_eq!(inode.size(), 12288);
    assert_eq!(raw.calls(), vec![(12288, u64::MAX)]);
}

/// An inode WITHOUT a page cache (`i_mapping` None) truncates cleanly with no
/// invalidation path — the `if let Some` guard skips it, no panic.
#[test]
fn no_mapping_inode_truncates_without_invalidate() {
    struct PlainOps;
    impl InodeOps for PlainOps {
        fn truncate(&self, inode: &Inode, len: u64) -> KResult<()> { inode.set_size(len); Ok(()) }
    }
    let inode = InodeBuilder::new(2, mk_mode(FileType::Regular, 0o644), Arc::new(PlainOps), default_file_ops())
        .owner(0, 0).size(100).build();
    let mut ia = size_change(10);
    notify_change(&Idmap::identity(), &inode, &mut ia, &Cred::root()).unwrap();
    assert_eq!(inode.size(), 10);
}
