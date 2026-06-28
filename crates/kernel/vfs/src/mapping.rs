// `address_space` (Linux `struct inode.i_mapping`) — the per-inode page
// cache contract per `17§4` / `17§5`. ONE object per inode, keyed by page
// index, shared by every mapper of that inode (Linux `i_mapping`). This is
// the object that makes two `mmap()`s of the same inode see the same pages:
// the cache lives on the inode, not on the per-mmap backing.
//
// Trait only — the frame-backed concrete type lives in a pmm-capable crate
// (`fs` tmpfs/shmem; ext4 regular files). `vfs` deps are `hal`+`sync` (no
// pmm), so the address_space contract names no pmm types: page frames are
// raw physical addresses (`u64`), I/O is over byte slices. This keeps the
// frame store out of the foundational crate while letting the page-fault
// handler and `InodeFileBacking` route through one per-inode object.

/// Per-inode address space (Linux `struct address_space`, reached via
/// `inode->i_mapping`). Implemented by inodes whose data lives in
/// persistent page-cache frames (tmpfs/shmem now; regular files as ext4
/// opts in). All mappers of one inode share one implementor.
pub trait AddressSpaceOps: Send + Sync {
    /// `MAP_SHARED` cache frame for page-aligned file offset `off`,
    /// allocating + fill-from-backing on a cache miss. `Some(pa)` =
    /// the persistent PMM frame a shared mapping installs directly, so
    /// user writes alias the inode's own storage and propagate to
    /// `read`/`write` + every other mapper (Linux shmem / page cache).
    /// `None` only for an address space that cannot hand out a mappable
    /// frame. # C: O(log N_pages)
    fn shared_frame(&self, off: u64) -> Option<u64>;

    /// Copy bytes from the cache starting at file offset `off` into `dst`
    /// (the `MAP_PRIVATE` / read-fault fill, Linux `do_cow_fault`'s read
    /// of the cache page before the private COW copy). Short reads
    /// zero-fill the tail at the caller. `Err(())` = FS read failure.
    /// # C: O(dst.len)
    fn read_at(&self, off: u64, dst: &mut [u8]) -> Result<usize, ()>;

    /// Flush dirty cache pages to the backing store (`msync`/`fsync`).
    /// No-op for shmem (pages ARE the store). # C: O(N_dirty)
    fn writeback(&self) -> Result<(), ()> { Ok(()) }

    /// Logical size (Linux `i_size`) the cache reflects. # C: O(1)
    fn size(&self) -> u64;
}

#[cfg(test)]
mod tests {
    use super::AddressSpaceOps;
    use crate::inode::Inode;
    use crate::types::{FileType, Ino, KResult, VfsError};

    const PG: u64 = 4096;

    // A toy address_space: page idx -> a deterministic "frame" pa, shared by
    // every mapper. Models the per-inode page cache without pmm.
    struct ToyMapping;
    impl AddressSpaceOps for ToyMapping {
        fn shared_frame(&self, off: u64) -> Option<u64> { Some(0x10_0000 + (off / PG) * PG) }
        fn read_at(&self, _off: u64, dst: &mut [u8]) -> Result<usize, ()> {
            for b in dst.iter_mut() { *b = 0xAB; } Ok(dst.len())
        }
        fn size(&self) -> u64 { 8192 }
    }

    // Inode WITH an i_mapping — `mmap_shared_frame` must forward to it.
    struct MappedInode { m: ToyMapping }
    impl Inode for MappedInode {
        fn ino(&self) -> Ino { 1 }
        fn file_type(&self) -> FileType { FileType::Regular }
        fn size(&self) -> u64 { 8192 }
        fn lookup(&self, _n: &str) -> KResult<crate::InodeRef> { Err(VfsError::Enotdir) }
        fn i_mapping(&self) -> Option<&dyn AddressSpaceOps> { Some(&self.m) }
    }

    // Inode WITHOUT an i_mapping — default None on both hooks.
    struct PlainInode;
    impl Inode for PlainInode {
        fn ino(&self) -> Ino { 2 }
        fn file_type(&self) -> FileType { FileType::Regular }
        fn size(&self) -> u64 { 0 }
        fn lookup(&self, _n: &str) -> KResult<crate::InodeRef> { Err(VfsError::Enotdir) }
    }

    // The wiring contract: `mmap_shared_frame` forwards through `i_mapping`.
    #[test]
    fn mmap_shared_frame_forwards_through_i_mapping() {
        let i = MappedInode { m: ToyMapping };
        // Same offset → same frame as the address_space hands out (one cache).
        assert_eq!(i.mmap_shared_frame(0), i.i_mapping().unwrap().shared_frame(0));
        assert_eq!(i.mmap_shared_frame(PG), Some(0x10_0000 + PG));
        // Repeated calls are stable (shared, not per-call).
        assert_eq!(i.mmap_shared_frame(0), i.mmap_shared_frame(0));
    }

    // No i_mapping → no shareable frame (MAP_PRIVATE copy path upstream).
    #[test]
    fn plain_inode_has_no_mapping() {
        let i = PlainInode;
        assert!(i.i_mapping().is_none());
        assert_eq!(i.mmap_shared_frame(0), None);
    }
}
