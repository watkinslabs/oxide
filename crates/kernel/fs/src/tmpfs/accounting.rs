use alloc::sync::Arc;

use core::sync::atomic::{AtomicU64, Ordering};

use super::limits::{FALLBACK_TOTAL_PAGES, PG};
use super::uapi::TMPFS_MAGIC;

pub struct TmpfsSb {
    max_blocks:  u64,
    max_inodes:  u64,
    used_blocks: AtomicU64,
    used_inodes: AtomicU64,
}

impl TmpfsSb {
    /// A bounded instance (`max_blocks` pages, `max_inodes` inodes). # C: O(1)
    pub(super) fn new(max_blocks: u64, max_inodes: u64) -> Arc<Self> {
        Arc::new(Self { max_blocks, max_inodes,
            used_blocks: AtomicU64::new(0), used_inodes: AtomicU64::new(0) })
    }
    /// Effectively-unbounded accounting (memfd/anon/coredump, hosted tests).
    /// # C: O(1)
    pub fn unlimited() -> Arc<Self> { Self::new(u64::MAX, u64::MAX) }
    /// Linux tmpfs default: half of physical RAM for blocks, and one inode per
    /// page of half-RAM, falling back to a large bound when the PMM is absent
    /// (hosted tests). # C: O(1)
    pub(super) fn default_limits() -> Arc<Self> {
        let total_pages = pmm::setup::pmm_static()
            .map(|p| p.free_pages() + p.allocated_pages())
            .filter(|&t| t != 0)
            .unwrap_or(FALLBACK_TOTAL_PAGES);
        let half = total_pages / 2;
        Self::new(half, half)
    }
    /// Reserve one block; `false` (caller → `ENOSPC`) at the limit. # C: O(1)
    pub(super) fn charge_block(&self) -> bool {
        let mut cur = self.used_blocks.load(Ordering::Relaxed);
        loop {
            if cur >= self.max_blocks { return false; }
            match self.used_blocks.compare_exchange_weak(cur, cur + 1, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return true,
                Err(c) => cur = c,
            }
        }
    }
    /// Release `n` blocks. # C: O(1)
    pub(super) fn free_blocks(&self, n: u64) { if n != 0 { self.used_blocks.fetch_sub(n, Ordering::Relaxed); } }
    /// Reserve one inode; `false` (caller → `ENOSPC`) at the limit. # C: O(1)
    pub(super) fn charge_inode(&self) -> bool {
        let mut cur = self.used_inodes.load(Ordering::Relaxed);
        loop {
            if cur >= self.max_inodes { return false; }
            match self.used_inodes.compare_exchange_weak(cur, cur + 1, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return true,
                Err(c) => cur = c,
            }
        }
    }
    /// Release one inode. # C: O(1)
    pub(super) fn free_inode(&self) { self.used_inodes.fetch_sub(1, Ordering::Relaxed); }
    /// `statfs(2)` block/inode accounting subset (Linux `shmem_statfs`).
    /// # C: O(1)
    pub(super) fn statfs(&self) -> vfs::SbStatFs {
        let ub = self.used_blocks.load(Ordering::Relaxed);
        let ui = self.used_inodes.load(Ordering::Relaxed);
        let bfree = self.max_blocks.saturating_sub(ub);
        let ffree = self.max_inodes.saturating_sub(ui);
        vfs::SbStatFs {
            f_type:   TMPFS_MAGIC,
            f_bsize:  PG as u32,
            f_blocks: self.max_blocks,
            f_bfree:  bfree,
            f_bavail: bfree,
            f_files:  self.max_inodes,
            f_ffree:  ffree,
            ..Default::default()
        }
    }
}
