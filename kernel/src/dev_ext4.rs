// P6-07: ext4 RO mounted at boot from a kernel-embedded image.
//
// `kernel/blobs/rootfs.img` is a real `mke2fs`-built ext4 image
// (1 MiB, no_journal, default features = extents on). We
// `include_bytes!` it, wrap in a read-only static-backed
// `BlockDevice`, and mount via `ext4::Mount`. Once the boot
// path calls `init()`, `lookup_path("/<name>")` and
// `read_file("/<name>")` resolve through the real driver.
//
// Future Limine-modules / virtio-blk path replaces the
// embedded image with a bootloader-loaded one without touching
// the public surface here.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicPtr, Ordering};

use block::{BlockDevice, BlockOp, BlockRequest, PageCache};
use block::types::{BlockError, InodeId, KResult, PAGE_BYTES};
use ext4::Mount;

/// Embedded ext4 image. Same fixture the crate-level tests use.
const ROOTFS: &'static [u8] = include_bytes!("../blobs/rootfs.img");

/// Backing block size for the in-kernel virtual disk.
const BLOCK_SIZE: u32 = 512;

/// Read-only static-image BlockDevice. Reads slice into the
/// caller's buffer; writes return `Eio` (we never mutate the
/// embedded image). No locking — the slice is `'static`.
pub struct StaticDisk {
    bytes:    &'static [u8],
    blk_size: u32,
}

// SAFETY: `&'static [u8]` is Sync + Send; no interior mutability.
unsafe impl Sync for StaticDisk {}
unsafe impl Send for StaticDisk {}

impl StaticDisk {
    /// # C: O(1)
    pub fn new(bytes: &'static [u8], blk_size: u32) -> Arc<Self> {
        Arc::new(Self { bytes, blk_size })
    }
}

impl BlockDevice for StaticDisk {
    fn block_size(&self) -> u32 { self.blk_size }
    fn capacity_blocks(&self) -> u64 {
        (self.bytes.len() as u64) / (self.blk_size as u64)
    }
    fn submit_sync(&self, req: &mut BlockRequest) -> KResult<()> {
        match req.op {
            BlockOp::Read => {
                let start = (req.start_block * self.blk_size as u64) as usize;
                let len   = (req.len_blocks as usize) * (self.blk_size as usize);
                if start + len > self.bytes.len() {
                    return Err(BlockError::Eio);
                }
                if req.buffer.len() < len {
                    req.buffer.resize(len, 0);
                }
                req.buffer[..len].copy_from_slice(&self.bytes[start..start+len]);
                Ok(())
            }
            BlockOp::Write   => Err(BlockError::Eio),  // read-only
            BlockOp::Flush   => Ok(()),
            BlockOp::Discard => Ok(()),                 // no-op
        }
    }
    fn flush(&self) -> KResult<()> { Ok(()) }
}

/// Cached Mount<'static>. Wrapped in AtomicPtr so the static
/// can be filled in by `init()` without `static mut`.
static MOUNT_PTR: AtomicPtr<Mount> = AtomicPtr::new(core::ptr::null_mut());

/// Page cache for ext4 reads. Keyed by (inode_id, page_offset);
/// pages are PAGE_BYTES-sized (= host page, typically 4 KiB).
/// Per `17§4.2` — cache misses go through `Mount::read_file_block`
/// for the logical-to-physical extent translation.
static PAGE_CACHE: PageCache = PageCache::new();

/// Hit / miss counters so the boot trace can prove the cache is
/// actually being used.
static CACHE_HITS:   core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static CACHE_MISSES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Snapshot (hits, misses).
/// # C: O(1)
pub fn cache_stats() -> (u64, u64) {
    use core::sync::atomic::Ordering;
    (CACHE_HITS.load(Ordering::Relaxed), CACHE_MISSES.load(Ordering::Relaxed))
}

/// Initialise the embedded ext4 mount. Idempotent — calling
/// twice is a no-op.
///
/// # SAFETY: caller is the boot path post-allocator-up; no
/// other CPU has yet seen `MOUNT_PTR`.
/// # C: O(N_groups + 1024) one-shot
pub unsafe fn init() {
    if !MOUNT_PTR.load(Ordering::Acquire).is_null() { return; }
    let disk = StaticDisk::new(ROOTFS, BLOCK_SIZE) as Arc<dyn BlockDevice>;
    let mount = match Mount::open(disk) {
        Ok(m)  => m,
        Err(_) => return,
    };
    let leaked = alloc::boxed::Box::leak(alloc::boxed::Box::new(mount));
    MOUNT_PTR.store(leaked as *mut _, Ordering::Release);
}

/// Look up an absolute path. Returns the inode number or
/// `None` if not mounted / not found / unsupported feature.
/// # C: O(path components × dir size)
pub fn lookup_path(path: &[u8]) -> Option<u32> {
    let p = MOUNT_PTR.load(Ordering::Acquire);
    if p.is_null() { return None; }
    // SAFETY: MOUNT_PTR was published via init() with the leaked Mount; reads are stable for the kernel lifetime.
    let mount = unsafe { &*p };
    mount.lookup_path(path).ok()
}

/// Read the entire content of a file by path. Returns `None`
/// for not-found / not-regular / read failure.
/// # C: O(file size)
pub fn read_file(path: &[u8]) -> Option<Vec<u8>> {
    let p = MOUNT_PTR.load(Ordering::Acquire);
    if p.is_null() { return None; }
    // SAFETY: MOUNT_PTR was published via init(); pointer is stable for the kernel lifetime.
    let mount = unsafe { &*p };
    let ino = mount.lookup_path(path).ok()?;
    let inode = mount.read_inode(ino).ok()?;
    if !inode.is_reg() { return None; }
    // Cache by (ext4 inode num, page-aligned file offset). Each
    // page covers PAGE_BYTES bytes (= host page, typically 4 KiB).
    // The cache miss path translates the page back into ext4
    // logical-block range and pulls from Mount::read_file_block,
    // which walks the inline extents.
    use core::sync::atomic::Ordering;
    let inode_id = InodeId(ino as u64);
    let mut out = Vec::with_capacity(inode.size as usize);
    let total = inode.size as usize;
    let pages = (total + PAGE_BYTES - 1) / PAGE_BYTES;
    for p in 0..pages {
        let page_off = (p as u64) * PAGE_BYTES as u64;
        let was_hit = PAGE_CACHE.lookup(inode_id, page_off).is_some();
        let cached = PAGE_CACHE.read_page_with(inode_id, page_off, || {
            // Miss: build PAGE_BYTES bytes from N ext4 logical
            // blocks. With ext4 block_size = 1024, that's 4 reads
            // per page; with 4096 it's 1 read.
            let bs = mount.sb.block_size as u64;
            let blocks_per_page = (PAGE_BYTES as u64 / bs) as u32;
            let first_blk = (page_off / bs) as u32;
            let mut buf = Vec::with_capacity(PAGE_BYTES);
            for i in 0..blocks_per_page {
                let blk = match mount.read_file_block(&inode, first_blk + i) {
                    Ok(b)  => b,
                    Err(ext4::MountError::NotFound) => alloc::vec![0u8; bs as usize],
                    Err(_) => return Err(BlockError::Eio),
                };
                buf.extend_from_slice(&blk);
            }
            Ok(buf)
        }).ok()?;
        if was_hit { CACHE_HITS.fetch_add(1, Ordering::Relaxed); }
        else       { CACHE_MISSES.fetch_add(1, Ordering::Relaxed); }
        let g = cached.data.lock();
        let remaining = total - out.len();
        let take = remaining.min(g.len());
        out.extend_from_slice(&g[..take]);
        drop(g);
        if out.len() >= total { break; }
    }
    Some(out)
}

/// Returns true iff the embedded ext4 mount is up.
/// # C: O(1)
pub fn mounted() -> bool {
    !MOUNT_PTR.load(Ordering::Acquire).is_null()
}
