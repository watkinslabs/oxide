// File-backed mmap wiring per `11§4` + `17§5`. Bridges
// `vfs::Inode` into the `vmm::FileBacking` trait the demand-page
// handler dispatches on. Each `InodeFileBacking` carries its own
// `PageCache`; a global per-inode cache hash lands once the inode
// keying surface is in place.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;

use block::{BlockError, CachedPage, InodeId, KResult as BlockResult, PageCache};
use vfs::InodeRef;
use vmm::FileBacking;

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
    fn read_at(&self, off: u64, dst: &mut [u8]) -> Result<usize, ()> {
        let mut written = 0usize;
        let inode_id = InodeId(self.inode.ino());
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
                Err(_) => return if written == 0 { Err(()) } else { Ok(written) },
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
        Ok(written)
    }

    fn size_hint(&self) -> u64 { self.inode.size() }
}
