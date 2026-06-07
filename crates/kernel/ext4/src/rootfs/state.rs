// Per-mount ext4 state: the owning `Mount`, that mount's page cache,
// and that mount's O_TMPFILE orphan set. Every path/inode operation a
// mount performs goes through its own `RootfsState`, so a second mount
// (e.g. /home, a tools volume) can never read through the first
// mount's device nor corrupt its orphan tracking — Stage 3 of the
// disk-rootfs de-singletonisation.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use block::{BlockDevice, PageCache};
use block::types::{BlockError, InodeId, KResult, PAGE_BYTES};
use ::sync as sync;
use crate::Mount;

/// One mounted ext4 filesystem's kernel-side state.
pub struct RootfsState {
    /// Owning mount (its own dev/sb/state — `mount.rs`).
    pub mount: Arc<Mount>,
    /// Page cache keyed by (inode_id, page_offset). PER MOUNT, so inode
    /// numbers that collide across mounts don't alias cached pages.
    pub page_cache: PageCache,
    /// O_TMPFILE orphan inodes pending cleanup. `create_anonymous`
    /// inserts; `link_inode` removes; the close-path frees only if the
    /// closed inode is in this set. PER MOUNT.
    pub orphans: sync::Spinlock<Vec<u32>, sync::Tty>,
    /// Page-cache hit / miss counters (boot trace proof of cache use).
    pub cache_hits:   core::sync::atomic::AtomicU64,
    pub cache_misses: core::sync::atomic::AtomicU64,
}

impl RootfsState {
    /// Build state around an opened `Mount`.
    /// # C: O(1)
    pub fn new(mount: Arc<Mount>) -> Arc<Self> {
        Arc::new(Self {
            mount,
            page_cache: PageCache::new(),
            orphans: sync::Spinlock::new(Vec::new()),
            cache_hits:   core::sync::atomic::AtomicU64::new(0),
            cache_misses: core::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Open `dev` as a fresh ext4 mount + state.
    /// # C: O(N_groups + 1024)
    pub fn open(dev: Arc<dyn BlockDevice>) -> KResult<Arc<Self>> {
        let mount = Mount::open(dev).map_err(|_| BlockError::Eio)?;
        Ok(Self::new(Arc::new(mount)))
    }

    /// # C: O(1)
    pub fn orphan_insert(&self, ino: u32) { self.orphans.lock().push(ino); }
    /// # C: O(N orphans)
    pub fn orphan_remove(&self, ino: u32) -> bool {
        let mut g = self.orphans.lock();
        if let Some(pos) = g.iter().position(|&i| i == ino) { g.swap_remove(pos); true } else { false }
    }
    /// # C: O(N orphans)
    pub fn orphan_contains(&self, ino: u32) -> bool { self.orphans.lock().iter().any(|&i| i == ino) }

    /// (hits, misses) snapshot.
    /// # C: O(1)
    pub fn cache_stats(&self) -> (u64, u64) {
        (self.cache_hits.load(Ordering::Relaxed), self.cache_misses.load(Ordering::Relaxed))
    }

    /// Whole-path lookup → ext4 inode number.
    /// # C: O(path components × dir size)
    pub fn lookup_path(&self, path: &[u8]) -> Option<u32> { self.mount.lookup_path(path).ok() }

    /// Resolve a single child in directory `dir_ino`.
    /// # C: O(N_entries in dir)
    pub fn lookup_child_ino(&self, dir_ino: u32, name: &str) -> Option<u32> {
        let dir = self.mount.read_inode(dir_ino).ok()?;
        self.mount.lookup_in_dir(&dir, name.as_bytes()).ok()
    }

    /// Iterate dir entries at `path`, calling `f(name, file_type)`.
    /// # C: O(N entries)
    pub fn read_dir<F: FnMut(&[u8], u8)>(&self, path: &[u8], mut f: F) -> Option<()> {
        let ino = self.mount.lookup_path(path).ok()?;
        let inode = self.mount.read_inode(ino).ok()?;
        if !inode.is_dir() { return None; }
        let blk = self.mount.read_file_block(&inode, 0).ok()?;
        let _ = crate::iter_active(&blk, |e| {
            if e.name == b"." || e.name == b".." { return true; }
            f(e.name, e.file_type);
            true
        });
        Some(())
    }

    /// Read whole file at `path` via this mount's page cache.
    /// # C: O(file size)
    pub fn read_file(&self, path: &[u8]) -> Option<Vec<u8>> {
        let ino = self.mount.lookup_path(path).ok()?;
        let inode = self.mount.read_inode(ino).ok()?;
        if !inode.is_reg() { return None; }
        let inode_id = InodeId(ino as u64);
        let total = inode.size as usize;
        let mut out = Vec::with_capacity(total);
        let pages = (total + PAGE_BYTES - 1) / PAGE_BYTES;
        for p in 0..pages {
            let page_off = (p as u64) * PAGE_BYTES as u64;
            let was_hit = self.page_cache.lookup(inode_id, page_off).is_some();
            let cached = self.page_cache.read_page_with(inode_id, page_off, || {
                let bs = self.mount.sb.block_size as u64;
                let blocks_per_page = (PAGE_BYTES as u64 / bs) as u32;
                let first_blk = (page_off / bs) as u32;
                let mut buf = Vec::with_capacity(PAGE_BYTES);
                for i in 0..blocks_per_page {
                    let blk = match self.mount.read_file_block(&inode, first_blk + i) {
                        Ok(b)  => b,
                        Err(crate::MountError::NotFound) => alloc::vec![0u8; bs as usize],
                        Err(_) => return Err(BlockError::Eio),
                    };
                    buf.extend_from_slice(&blk);
                }
                Ok(buf)
            }).ok()?;
            if was_hit { self.cache_hits.fetch_add(1, Ordering::Relaxed); }
            else       { self.cache_misses.fetch_add(1, Ordering::Relaxed); }
            let g = cached.data.lock();
            let remaining = total - out.len();
            let take = remaining.min(g.len());
            out.extend_from_slice(&g[..take]);
            drop(g);
            if out.len() >= total { break; }
        }
        Some(out)
    }

    /// Read full bytes of regular file `ino` (refresh path).
    /// # C: O(file size)
    pub fn read_full_file(&self, ino: u32) -> Option<Vec<u8>> {
        let inode = self.mount.read_inode(ino).ok()?;
        if !inode.is_reg() { return None; }
        let bs = self.mount.sb.block_size as usize;
        let total = inode.size as usize;
        let n_blocks = (total + bs - 1) / bs;
        let mut out = Vec::with_capacity(total);
        for k in 0..n_blocks {
            let blk = match self.mount.read_file_block(&inode, k as u32) {
                Ok(b)  => b,
                Err(crate::MountError::NotFound) => alloc::vec![0u8; bs],
                Err(_) => return None,
            };
            let take = core::cmp::min(bs, total - out.len());
            out.extend_from_slice(&blk[..take]);
        }
        Some(out)
    }

    /// In-place first-block write (Phase 7b minimum).
    /// # C: O(N_extents) + O(1) block I/O
    pub fn write_file(&self, path: &[u8], data: &[u8]) -> Option<()> {
        let ino = self.mount.lookup_path(path).ok()?;
        let inode = self.mount.read_inode(ino).ok()?;
        if !inode.is_reg() { return None; }
        let bs = self.mount.sb.block_size as usize;
        if data.len() > bs { return None; }
        let mut blk = self.mount.read_file_block(&inode, 0).ok()?;
        if blk.len() < bs { blk.resize(bs, 0); }
        blk[..data.len()].copy_from_slice(data);
        self.mount.write_file_block(&inode, 0, &blk).ok()?;
        self.page_cache.invalidate(InodeId(ino as u64));
        Some(())
    }
}
