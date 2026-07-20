// File-backed mmap wiring per `11§4` + `17§5`. Bridges
// `vfs::Inode` into the `vmm::FileBacking` trait the demand-page
// handler dispatches on. Each `InodeFileBacking` carries its own
// `PageCache`; a global per-inode cache hash lands once the inode
// keying surface is in place.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;

use block::{BlockError, CachedPage, InodeId, KResult as BlockResult, PageCache};
use vfs::{InodeRef, MAY_WRITE};
use vfs::inode::inode_owner_or_capable;
use vfs::idmap::IDENTITY;
use vmm::{FileBacking, FileBackingError, SharedFrame};

/// Read-side file backing for `VmaBacking::File`. Goes through a
/// dedicated `PageCache`, which fetches missing pages via
/// `Inode::read`. Matches Linux MAP_PRIVATE/MAP_SHARED read path;
/// MAP_SHARED writeback rides the dirty-tracking work.
pub struct InodeFileBacking {
    inode: InodeRef,
    cache: PageCache,
}

impl InodeFileBacking {
    /// # C: O(1)
    pub fn new(inode: InodeRef) -> Arc<Self> {
        Arc::new(Self { inode, cache: PageCache::new() })
    }
}

const PAGE: usize = 4096;

impl FileBacking for InodeFileBacking {
    /// Fill `dst` with bytes starting at file offset `off`. Aligns
    /// the request to PAGE_BYTES and consults the per-backing
    /// `PageCache`; on miss, fetches via `Inode::read`. Returns the
    /// number of bytes copied into `dst` (may be short at end-of-
    /// file — the handler zero-fills the tail).
    fn read_at(&self, off: u64, dst: &mut [u8]) -> Result<usize, FileBackingError> {
        // Per-inode address_space (Linux `i_mapping`): when the inode owns a
        // frame-backed page cache (tmpfs/shmem), read THROUGH it so every
        // mapper of this inode shares one address space (MM6) — not this
        // backing's private `PageCache`. Inodes without an `i_mapping`
        // (ext4 regular files, until they opt in) keep the per-backing cache
        // path below.
        if let Some(m) = self.inode.i_mapping() {
            return m.read_at(off, dst).map_err(vfs_error);
        }
        let mut written = 0usize;
        let inode_id = InodeId(self.inode.ino());
        // DIAG (debug-mount): every File-fault re-read of the libc .data/.bss
        // region (file off 0x1e6000..0x1e8000). If the lock page (0x1e7000) is
        // served MORE THAN ONCE for a process, a re-fault discarded ld.so's
        // .bss zero-fill — that's the wedge.
        #[cfg(feature = "debug-atexit")]
        if off >= 0x1e6000 && off < 0x1e8000 {
            let pid = sched::live::current().map(|c| c.tid).unwrap_or(0);
            klog::write_raw(b"[mnt] FILEREAD ino=");
            klog::write_hex_u64(self.inode.ino());
            klog::write_raw(b" off=");
            klog::write_hex_u64(off);
            klog::write_raw(b" pid=");
            klog::write_dec_u64(pid as u64);
            klog::write_raw(b"\n");
        }
        while written < dst.len() {
            let cur_off = off + written as u64;
            let page_off = cur_off & !((PAGE - 1) as u64);
            let in_page  = (cur_off - page_off) as usize;
            let want     = core::cmp::min(PAGE - in_page, dst.len() - written);
            let inode = Arc::clone(&self.inode);
            let p_off = page_off;
            let page_res: BlockResult<Arc<CachedPage>> = self.cache.read_page_with(
                inode_id,
                page_off,
                || -> BlockResult<alloc::vec::Vec<u8>> {
                    let mut buf = alloc::vec![0u8; PAGE];
                    match inode.read(p_off, &mut buf) {
                        Ok(n) => {
                            if n < PAGE {
                                for byte in &mut buf[n..] { *byte = 0; }
                            }
                            Ok(buf)
                        }
                        Err(_) => Err(BlockError::Eio),
                    }
                },
            );
            let page: Arc<CachedPage> = match page_res {
                Ok(p) => p,
                Err(_) => return if written == 0 { Err(FileBackingError::Io) } else { Ok(written) },
            };
            let data = page.data.lock();
            let avail = core::cmp::min(want, data.len().saturating_sub(in_page));
            if avail == 0 {
                // Past page bounds (cache filled to PAGE_BYTES; this
                // means a malformed in_page > PAGE). Bail.
                break;
            }
            dst[written..written + avail]
                .copy_from_slice(&data[in_page..in_page + avail]);
            written += avail;
            if avail < want {
                // Short read at end-of-file.
                break;
            }
        }
        // DIAG (debug-mount): for the libc lock page (off 0x1e7000) log the
        // byte the page cache SERVES at the lock offset 0xfe8. Correct file
        // content there is 0x73 ('s' from rodata that overlaps .bss). If this
        // is 0x73 → page cache is fine and the wedge is ld.so's memset not
        // persisting; if it's wrong (e.g. 0x2f '/') the page cache served the
        // wrong offset.
        #[cfg(feature = "debug-atexit")]
        if off == 0x1e7000 && dst.len() >= 0xfe9 {
            let pid = sched::live::current().map(|c| c.tid).unwrap_or(0);
            klog::write_raw(b"[mnt] LOCKBYTE ino=");
            klog::write_hex_u64(self.inode.ino());
            klog::write_raw(b" served0xfe8=");
            klog::write_hex_u64(dst[0xfe8] as u64);
            klog::write_raw(b" pid=");
            klog::write_dec_u64(pid as u64);
            klog::write_raw(b"\n");
        }
        Ok(written)
    }

    fn size_hint(&self) -> u64 { self.inode.size() }
    fn ino(&self) -> u64 { self.inode.ino() }
    fn file_rmap(&self) -> Option<Arc<vmm::FileRmap>> { Some(self.inode.file_rmap()) }
    /// MAP_SHARED: defer to the inode's page-frame store (tmpfs/memfd return
    /// a real frame; other inodes default to None → copy path). # C: O(log N)
    fn shared_frame(&self, off: u64) -> Result<Option<SharedFrame>, FileBackingError> {
        self.inode.mmap_shared_frame(off)
            .map(|frame| frame.map(|frame| SharedFrame { pa: frame.pa, map_ref_held: frame.map_ref_held }))
            .map_err(vfs_error)
    }

    /// `msync(MS_SYNC)`/range fsync writeback over the inode address_space.
    /// Inodes without an address_space have no mapped dirty frame store here.
    /// # C: O(N_dirty in range)
    fn writeback_range(&self, start: u64, end: u64) -> Result<(), ()> {
        if let Some(m) = self.inode.i_mapping() { m.writeback_range(start, end) } else { Ok(()) }
    }

    /// Non-faulting `mincore(2)` page-cache query. # C: O(log N_pages)
    fn mincore_page(&self, off: u64) -> bool {
        if let Some(m) = self.inode.i_mapping() {
            return m.mincore_page(off);
        }
        let page_off = off & !((PAGE - 1) as u64);
        self.cache.lookup(InodeId(self.inode.ino()), page_off)
            .map_or(false, |p| p.flags().contains(block::PageFlags::UPTODATE))
    }

    /// Linux `can_do_mincore()` file leg. # C: O(permission-check)
    fn mincore_can_reveal(&self) -> bool {
        let cred = crate::pathresolve::current_cred();
        inode_owner_or_capable(&IDENTITY, self.inode.as_ref(), &cred)
            || self.inode.permission(MAY_WRITE, &cred).is_ok()
    }

    /// `MADV_REMOVE` file punch-hole leg. # C: filesystem-dependent
    fn madvise_remove(&self, off: u64, len: u64) -> Result<(), FileBackingError> {
        self.inode.fallocate(off, len, true, false, true).map_err(|e| match e {
            vfs::VfsError::Eacces => FileBackingError::Acces,
            vfs::VfsError::Ebadf => FileBackingError::Badf,
            vfs::VfsError::Einval => FileBackingError::Inval,
            vfs::VfsError::Eio => FileBackingError::Io,
            vfs::VfsError::Enomem => FileBackingError::NoMem,
            vfs::VfsError::Eopnotsupp => FileBackingError::OpNotSupp,
            _ => FileBackingError::Inval,
        })
    }

    fn madvise_pageout(&self, off: u64, len: u64) -> Option<Result<usize, FileBackingError>> {
        self.inode.i_mapping()?.madvise_pageout(off, len).map(|result| result.map_err(vfs_error))
    }
}

fn vfs_error(e: vfs::VfsError) -> FileBackingError {
    match e {
        vfs::VfsError::Enomem => FileBackingError::NoMem,
        vfs::VfsError::Eacces => FileBackingError::Acces,
        vfs::VfsError::Ebadf => FileBackingError::Badf,
        vfs::VfsError::Einval => FileBackingError::Inval,
        vfs::VfsError::Eopnotsupp => FileBackingError::OpNotSupp,
        _ => FileBackingError::Io,
    }
}
