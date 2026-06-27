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
    /// MAP_SHARED: defer to the inode's page-frame store (tmpfs/memfd return
    /// a real frame; other inodes default to None → copy path). # C: O(log N)
    fn shared_frame(&self, off: u64) -> Option<u64> { self.inode.mmap_shared_frame(off) }
}
