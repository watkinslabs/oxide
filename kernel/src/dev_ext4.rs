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

/// Read-write Vec-backed BlockDevice initialised from a static
/// image. The kernel keeps a writable copy in heap memory; the
/// embedded `&'static [u8]` is the cold-boot snapshot. Writes
/// mutate the heap copy only — Phase 7b minimum (no persistent
/// disk yet, swapping the heap copy back to a real disk is
/// virtio-blk's job).
pub struct ImageDisk {
    bytes:    sync::Spinlock<Vec<u8>, sync::Inode>,
    blk_size: u32,
}

impl ImageDisk {
    /// Initialise from a `'static` snapshot — copy bytes into
    /// the heap so writes can mutate them without violating
    /// `'static`'s read-only contract.
    /// # C: O(N) once at boot
    pub fn from_static(bytes: &'static [u8], blk_size: u32) -> Arc<Self> {
        Arc::new(Self {
            bytes:    sync::Spinlock::new(bytes.to_vec()),
            blk_size,
        })
    }
}

impl BlockDevice for ImageDisk {
    fn block_size(&self) -> u32 { self.blk_size }
    fn capacity_blocks(&self) -> u64 {
        (self.bytes.lock().len() as u64) / (self.blk_size as u64)
    }
    fn submit_sync(&self, req: &mut BlockRequest) -> KResult<()> {
        let start = (req.start_block * self.blk_size as u64) as usize;
        let len   = (req.len_blocks as usize) * (self.blk_size as usize);
        match req.op {
            BlockOp::Read => {
                let g = self.bytes.lock();
                if start + len > g.len() { return Err(BlockError::Eio); }
                if req.buffer.len() < len { req.buffer.resize(len, 0); }
                req.buffer[..len].copy_from_slice(&g[start..start+len]);
                Ok(())
            }
            BlockOp::Write => {
                let mut g = self.bytes.lock();
                if start + len > g.len() { return Err(BlockError::Eio); }
                if req.buffer.len() < len { return Err(BlockError::Einval); }
                g[start..start+len].copy_from_slice(&req.buffer[..len]);
                Ok(())
            }
            BlockOp::Flush   => Ok(()),
            BlockOp::Discard => Ok(()),
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
    let disk = ImageDisk::from_static(ROOTFS, BLOCK_SIZE) as Arc<dyn BlockDevice>;
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

/// Phase 7b minimum: in-place write to an existing file. Bytes
/// `data` overwrite the start of the file's first block; data
/// length must be ≤ `sb.block_size`. No extent allocation, no
/// size growth, no journaling — just modifying bytes in an
/// existing extent. Invalidates the page cache for this inode
/// so subsequent reads see the new bytes.
/// # C: O(N_extents) + O(1) block I/O
pub fn write_file(path: &[u8], data: &[u8]) -> Option<()> {
    let p = MOUNT_PTR.load(Ordering::Acquire);
    if p.is_null() { return None; }
    // SAFETY: MOUNT_PTR was published via init(); pointer is stable for the kernel lifetime.
    let mount = unsafe { &*p };
    let ino = mount.lookup_path(path).ok()?;
    let inode = mount.read_inode(ino).ok()?;
    if !inode.is_reg() { return None; }
    let bs = mount.sb.block_size as usize;
    if data.len() > bs { return None; }
    // Read existing first block, splice in `data`, write whole
    // block back. Preserves trailing bytes within the same block.
    let mut blk = mount.read_file_block(&inode, 0).ok()?;
    if blk.len() < bs { blk.resize(bs, 0); }
    blk[..data.len()].copy_from_slice(data);
    mount.write_file_block(&inode, 0, &blk).ok()?;
    // Invalidate cached page so the next read sees fresh bytes.
    let inode_id = InodeId(ino as u64);
    PAGE_CACHE.invalidate(inode_id);
    Some(())
}

/// VFS Inode wrapping a regular ext4 file. Reads served from a
/// per-inode byte cache (refreshed after every successful write
/// or truncate). Writes round-trip through `Mount::write_at` and
/// invalidate the kernel page cache for this inode.
struct Ext4FileInode {
    ino:   u32,
    bytes: sync::Spinlock<Vec<u8>, sync::Inode>,
}

impl Ext4FileInode {
    fn refresh(&self) {
        if let Some(b) = read_full_file_by_ino(self.ino) {
            *self.bytes.lock() = b;
        }
    }
}

impl vfs::Inode for Ext4FileInode {
    fn ino(&self) -> vfs::Ino { (0x6E54_0000u64 | (self.ino as u64)) as vfs::Ino }
    fn file_type(&self) -> vfs::FileType { vfs::FileType::Regular }
    fn size(&self) -> u64 { self.bytes.lock().len() as u64 }
    fn lookup(&self, _n: &str) -> vfs::KResult<vfs::InodeRef> { Err(vfs::VfsError::Enotdir) }
    fn read(&self, off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        let g = self.bytes.lock();
        let off = off as usize;
        if off >= g.len() { return Ok(0); }
        let n = (g.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&g[off..off+n]);
        Ok(n)
    }
    fn write(&self, off: u64, buf: &[u8]) -> vfs::KResult<usize> {
        let p = MOUNT_PTR.load(Ordering::Acquire);
        if p.is_null() { return Err(vfs::VfsError::Eio); }
        // SAFETY: MOUNT_PTR published in init() and stable for kernel lifetime; sole writer is this fn under the file's natural exclusive flow.
        let mount = unsafe { &*p };
        mount.write_at(self.ino, off, buf).map_err(|_| vfs::VfsError::Eio)?;
        PAGE_CACHE.invalidate(InodeId(self.ino as u64));
        self.refresh();
        Ok(buf.len())
    }
    fn truncate(&self, len: u64) -> vfs::KResult<()> {
        let p = MOUNT_PTR.load(Ordering::Acquire);
        if p.is_null() { return Err(vfs::VfsError::Eio); }
        // SAFETY: MOUNT_PTR is published once at boot; reads stable for kernel lifetime.
        let mount = unsafe { &*p };
        mount.truncate_inode(self.ino, len).map_err(|_| vfs::VfsError::Eio)?;
        PAGE_CACHE.invalidate(InodeId(self.ino as u64));
        self.refresh();
        Ok(())
    }
}

/// Read the full bytes of an ext4 regular file by its inode
/// number — used internally to refresh `Ext4FileInode` after
/// writes.
/// # C: O(file size)
fn read_full_file_by_ino(ino: u32) -> Option<Vec<u8>> {
    let p = MOUNT_PTR.load(Ordering::Acquire);
    if p.is_null() { return None; }
    // SAFETY: MOUNT_PTR is published once at boot; reads stable for kernel lifetime.
    let mount = unsafe { &*p };
    let inode = mount.read_inode(ino).ok()?;
    if !inode.is_reg() { return None; }
    let bs = mount.sb.block_size as usize;
    let total = inode.size as usize;
    let n_blocks = (total + bs - 1) / bs;
    let mut out = Vec::with_capacity(total);
    for k in 0..n_blocks {
        let blk = match mount.read_file_block(&inode, k as u32) {
            Ok(b)  => b,
            Err(ext4::MountError::NotFound) => alloc::vec![0u8; bs],
            Err(_) => return None,
        };
        let take = core::cmp::min(bs, total - out.len());
        out.extend_from_slice(&blk[..take]);
    }
    Some(out)
}

/// Wrap `ino` (regular-file ext4 inode) in a writeable VFS Inode.
fn wrap_file(ino: u32) -> Option<vfs::InodeRef> {
    let bytes = read_full_file_by_ino(ino)?;
    Some(alloc::sync::Arc::new(Ext4FileInode {
        ino,
        bytes: sync::Spinlock::new(bytes),
    }) as vfs::InodeRef)
}

/// Look up `path` and return a VFS Inode wrapping the file
/// contents. Returns `None` for not-found / not-regular /
/// not-mounted. Used by `kernel_sys_open` to extend the open
/// path lookup chain to the real ext4 fs.
/// # C: O(file size) on first call (read), O(log N) on cache hit
pub fn lookup_inode(path: &[u8]) -> Option<vfs::InodeRef> {
    let p = MOUNT_PTR.load(Ordering::Acquire);
    if p.is_null() { return None; }
    // SAFETY: MOUNT_PTR is published once at boot; reads stable for kernel lifetime.
    let mount = unsafe { &*p };
    let ino = mount.lookup_path(path).ok()?;
    let inode = mount.read_inode(ino).ok()?;
    if !inode.is_reg() { return None; }
    wrap_file(ino)
}

/// Split `path` into (parent_path, basename). Returns None for
/// paths that lack a basename (e.g. `/`).
fn split_parent_and_name(path: &[u8]) -> Option<(&[u8], &[u8])> {
    if path.is_empty() || path[0] != b'/' { return None; }
    let pos = path.iter().rposition(|&c| c == b'/')?;
    let parent = if pos == 0 { &path[..1] } else { &path[..pos] };
    let name   = &path[pos + 1..];
    if name.is_empty() { return None; }
    Some((parent, name))
}

fn parent_inode(path: &[u8]) -> Option<(u32, &[u8])> {
    let p = MOUNT_PTR.load(Ordering::Acquire);
    if p.is_null() { return None; }
    // SAFETY: MOUNT_PTR is published once at boot; reads stable for kernel lifetime.
    let mount = unsafe { &*p };
    let (parent, name) = split_parent_and_name(path)?;
    let pino = mount.lookup_path(parent).ok()?;
    Some((pino, name))
}

/// Create a regular file at `path`. Returns the new VFS InodeRef.
/// `Enoent` if the parent directory doesn't exist (caller maps).
/// # C: O(N parent entries)
pub fn create_at(path: &[u8], mode_perm: u16) -> Option<vfs::InodeRef> {
    let p = MOUNT_PTR.load(Ordering::Acquire);
    if p.is_null() { return None; }
    // SAFETY: MOUNT_PTR is published once at boot; reads stable for kernel lifetime.
    let mount = unsafe { &*p };
    let (pino, name) = parent_inode(path)?;
    let new_ino = mount.create_file(pino, name, mode_perm).ok()?;
    PAGE_CACHE.invalidate(InodeId(new_ino as u64));
    wrap_file(new_ino)
}

/// Unlink the file at `path`. `Enoent` if missing.
/// # C: O(N parent entries) + (free blocks if last link)
pub fn unlink_at(path: &[u8]) -> Result<(), vfs::VfsError> {
    let p = MOUNT_PTR.load(Ordering::Acquire);
    if p.is_null() { return Err(vfs::VfsError::Eio); }
    // SAFETY: MOUNT_PTR is published once at boot; reads stable for kernel lifetime.
    let mount = unsafe { &*p };
    let (pino, name) = parent_inode(path).ok_or(vfs::VfsError::Enoent)?;
    let target = mount.lookup_path(path).map_err(|_| vfs::VfsError::Enoent)?;
    mount.unlink(pino, name).map_err(|_| vfs::VfsError::Eio)?;
    PAGE_CACHE.invalidate(InodeId(target as u64));
    Ok(())
}

/// Create an empty subdirectory at `path` with mode `mode_perm`.
/// # C: O(N parent entries)
pub fn mkdir_at(path: &[u8], mode_perm: u16) -> Result<(), vfs::VfsError> {
    let p = MOUNT_PTR.load(Ordering::Acquire);
    if p.is_null() { return Err(vfs::VfsError::Eio); }
    // SAFETY: MOUNT_PTR is published once at boot; reads stable for kernel lifetime.
    let mount = unsafe { &*p };
    let (pino, name) = parent_inode(path).ok_or(vfs::VfsError::Enoent)?;
    mount.create_dir(pino, name, mode_perm).map_err(|_| vfs::VfsError::Eio)?;
    Ok(())
}

/// Remove the (empty) directory at `path`.
/// # C: O(N parent entries)
pub fn rmdir_at(path: &[u8]) -> Result<(), vfs::VfsError> {
    let p = MOUNT_PTR.load(Ordering::Acquire);
    if p.is_null() { return Err(vfs::VfsError::Eio); }
    // SAFETY: MOUNT_PTR is published once at boot; reads stable for kernel lifetime.
    let mount = unsafe { &*p };
    let target = mount.lookup_path(path).map_err(|_| vfs::VfsError::Enoent)?;
    let inode = mount.read_inode(target).map_err(|_| vfs::VfsError::Eio)?;
    if !inode.is_dir() { return Err(vfs::VfsError::Enotdir); }
    let (pino, name) = parent_inode(path).ok_or(vfs::VfsError::Enoent)?;
    // dir_unlink + free_inode (no block frees — empty dirs have no
    // data blocks beyond the . / .. block we never allocated for
    // create_dir).
    mount.dir_unlink(pino, name).map_err(|_| vfs::VfsError::Eio)?;
    let _ = mount.free_inode(target);
    Ok(())
}

/// Rename `from` → `to` (same parent dir or different). Atomic
/// only at the dir-block level — implements as link-then-unlink
/// of the same inode. Cross-directory move supported when both
/// parents resolve.
/// # C: O(N parent entries) per directory
/// Hardlink `target_path` → `link_path`. Increments target's
/// nlink and adds a new dir entry; both names refer to the same
/// inode afterwards.
/// # C: O(N parent entries)
pub fn link_at(target_path: &[u8], link_path: &[u8]) -> Result<(), vfs::VfsError> {
    let p = MOUNT_PTR.load(Ordering::Acquire);
    if p.is_null() { return Err(vfs::VfsError::Eio); }
    // SAFETY: MOUNT_PTR is published once at boot; reads stable for kernel lifetime.
    let mount = unsafe { &*p };
    let target = mount.lookup_path(target_path).map_err(|_| vfs::VfsError::Enoent)?;
    let inode = mount.read_inode(target).map_err(|_| vfs::VfsError::Eio)?;
    if inode.is_dir() { return Err(vfs::VfsError::Eperm); }  // no dir hardlinks
    let (parent_ino, name_owned) = parent_inode(link_path).ok_or(vfs::VfsError::Enoent)?;
    let name: alloc::vec::Vec<u8> = name_owned.to_vec();
    let ftype = if inode.is_link() { ext4::DT_LNK } else { ext4::DT_REG };
    mount.run_journaled(|m| {
        m.dir_link(parent_ino, &name, target, ftype)?;
        m.adjust_nlink(target, 1)?;
        Ok(())
    }).map_err(|_| vfs::VfsError::Eio)
}

/// # C: O(1)
pub fn rename_at(from: &[u8], to: &[u8]) -> Result<(), vfs::VfsError> {
    let p = MOUNT_PTR.load(Ordering::Acquire);
    if p.is_null() { return Err(vfs::VfsError::Eio); }
    // SAFETY: MOUNT_PTR is published once at boot; reads stable for kernel lifetime.
    let mount = unsafe { &*p };
    let target = mount.lookup_path(from).map_err(|_| vfs::VfsError::Enoent)?;
    let inode = mount.read_inode(target).map_err(|_| vfs::VfsError::Eio)?;
    let (from_p, from_name_owned) = parent_inode(from).ok_or(vfs::VfsError::Enoent)?;
    let from_name: alloc::vec::Vec<u8> = from_name_owned.to_vec();
    let (to_p, to_name_owned)     = parent_inode(to).ok_or(vfs::VfsError::Enoent)?;
    let to_name: alloc::vec::Vec<u8> = to_name_owned.to_vec();
    let ftype = if inode.is_dir() { ext4::DT_DIR } else if inode.is_link() { ext4::DT_LNK } else { ext4::DT_REG };
    let dest_exists = mount.lookup_path(to).is_ok();
    // Run the entire rename inside one journal transaction so
    // dest-unlink (if any) + dir_link + source-unlink commit
    // atomically. Crash mid-rename either leaves the old name
    // bound or the new name bound — never both / neither.
    mount.run_journaled(|m| {
        if dest_exists { let _ = m.dir_unlink(to_p, &to_name); }
        m.dir_link(to_p, &to_name, target, ftype)?;
        m.dir_unlink(from_p, &from_name)?;
        Ok(())
    }).map_err(|_| vfs::VfsError::Eio)
}
