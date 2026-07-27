use alloc::sync::Arc;

use core::sync::atomic::{AtomicU64, Ordering};

use super::limits::{FALLBACK_TOTAL_PAGES, PG};

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
    /// Total physical RAM in pages (PMM live pool), falling back to a large
    /// bound when the PMM is absent (hosted tests). # C: O(1)
    pub(super) fn total_ram_pages() -> u64 {
        pmm::setup::pmm_static()
            .map(|p| p.free_pages() + p.allocated_pages())
            .filter(|&t| t != 0)
            .unwrap_or(FALLBACK_TOTAL_PAGES)
    }
    /// Linux tmpfs default: half of physical RAM for blocks, and one inode per
    /// page of half-RAM, falling back to a large bound when the PMM is absent
    /// (hosted tests). # C: O(1)
    pub(super) fn default_limits() -> Arc<Self> {
        let half = Self::total_ram_pages() / 2;
        Self::new(half, half)
    }
    /// Build accounting from parsed `-o size=/nr_blocks=/nr_inodes=` options,
    /// defaulting any unspecified cap to Linux's half-RAM. `size=` (bytes) is
    /// rounded up to pages inside `resolve_blocks`. # C: O(1)
    pub(super) fn from_opts(opts: &super::mount_opts::TmpfsOpts) -> Arc<Self> {
        let half = Self::total_ram_pages() / 2;
        Self::new(opts.resolve_blocks(half), opts.resolve_inodes(half))
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
    /// `statfs(2)` block/inode accounting (Linux `shmem_statfs`). An UNBOUNDED
    /// instance (`max_blocks == u64::MAX`, the memfd/anon/coredump backing)
    /// leaves the counts zero exactly as Linux does when `sbinfo->max_blocks`
    /// is 0 — reporting `u64::MAX` blocks would make `df` print an
    /// eight-exabyte filesystem. # C: O(1)
    pub(super) fn statfs(&self, magic: u64) -> vfs::SbStatFs {
        let mut st = vfs::SbStatFs {
            f_type:    magic,
            f_bsize:   PG as u32,
            f_frsize:  PG as u32,
            f_namelen: vfs::path::NAME_MAX as u64,
            ..Default::default()
        };
        if self.max_blocks != u64::MAX {
            let bfree = self.max_blocks.saturating_sub(self.used_blocks.load(Ordering::Relaxed));
            st.f_blocks = self.max_blocks;
            st.f_bfree  = bfree;
            st.f_bavail = bfree;
        }
        if self.max_inodes != u64::MAX {
            st.f_files = self.max_inodes;
            st.f_ffree = self.max_inodes.saturating_sub(self.used_inodes.load(Ordering::Relaxed));
        }
        st
    }
}
