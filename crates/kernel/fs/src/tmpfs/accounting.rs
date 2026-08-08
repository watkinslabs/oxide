use alloc::sync::{Arc, Weak};

use core::sync::atomic::{AtomicU64, Ordering};

use sync::{Inode as InodeClass, Spinlock};
use vfs::superblock::SuperBlock;

use super::limits::{FALLBACK_TOTAL_PAGES, PG};
use super::quota::TmpfsQuota;

/// One mounted instance's superblock state: the ceilings it enforces, the
/// usage it has against them, and the mount options that change how it
/// behaves rather than how much it holds.
///
/// This is the ONLY place a mount's options live. Every consumer reads them
/// from here — there is no second copy on the filesystem object, on the root
/// inode, or in the parse context, so no two of them can disagree about
/// whether this mount swaps.
pub struct TmpfsSb {
    max_blocks:  u64,
    max_inodes:  u64,
    used_blocks: AtomicU64,
    used_inodes: AtomicU64,
    /// `-o noswap`: this mount's pages are never written to swap.
    noswap:      bool,
    /// `-o inode64`: inode numbers may use the full 64-bit space.
    full_inums:  bool,
    /// `-o quota`/`usrquota`/`grpquota` and the four `*_hardlimit=` ceilings:
    /// the per-OWNER accounting this mount enforces on top of its mount-wide
    /// ceilings.
    quota:       TmpfsQuota,
    /// The superblock this instance's quota state lives on, stamped at
    /// `fill_super`. An instance with no superblock (memfd/anon/coredump, and
    /// the root inode built before the back-stamp) has no quota domain.
    sb:          Spinlock<Weak<SuperBlock>, InodeClass>,
}

impl TmpfsSb {
    /// A bounded instance (`max_blocks` pages, `max_inodes` inodes) with
    /// default mount options. # C: O(1)
    pub(super) fn new(max_blocks: u64, max_inodes: u64) -> Arc<Self> {
        Arc::new(Self { max_blocks, max_inodes,
            used_blocks: AtomicU64::new(0), used_inodes: AtomicU64::new(0),
            noswap: false, full_inums: false,
            quota: TmpfsQuota::off(), sb: Spinlock::new(Weak::new()) })
    }

    /// Record the superblock this instance's quota state lives on. # C: O(1)
    pub(super) fn bind_sb(&self, sb: &Weak<SuperBlock>) { *self.sb.lock() = sb.clone(); }
    /// The superblock a quota charge is made against, absent for an instance
    /// with no quota domain. # C: O(1)
    pub(super) fn quota_sb(&self) -> Option<Arc<SuperBlock>> { self.sb.lock().upgrade() }
    /// This mount's quota configuration. # C: O(1)
    pub(super) fn quota(&self) -> TmpfsQuota { self.quota }

    /// Whether this mount may write a page to swap (`shmem_writeout`'s
    /// `sbinfo->noswap` test). The single point both the shrinker and an
    /// explicit page-out consult. # C: O(1)
    pub(super) fn may_swap_out(&self) -> bool { !self.noswap }

    /// Whether this mount's inode numbers may use the full 64-bit space.
    /// # C: O(1)
    pub(super) fn full_inums(&self) -> bool { self.full_inums }

    /// Allocate this mount's next inode number, applying its inode-number
    /// width. # C: O(1)
    pub(super) fn alloc_ino(&self) -> vfs::Ino {
        super::inode::constrain_ino(super::inode::next_ino_raw(), self.full_inums())
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
    /// Build a mount's superblock state from its parsed options: the ceilings
    /// (defaulting to half of RAM) and every behavioural option, in one object
    /// so no consumer has to look anywhere else for them. # C: O(1)
    pub(super) fn from_opts(opts: &super::mount_opts::TmpfsOpts) -> Arc<Self> {
        let half = Self::total_ram_pages() / 2;
        Arc::new(Self {
            max_blocks: opts.resolve_blocks(half),
            max_inodes: opts.resolve_inodes(half),
            used_blocks: AtomicU64::new(0), used_inodes: AtomicU64::new(0),
            noswap: opts.noswap,
            full_inums: opts.full_inums(),
            quota: TmpfsQuota::from_opts(opts),
            sb: Spinlock::new(Weak::new()),
        })
    }
    /// Reserve `n` blocks as ONE admission: a request that does not fit takes
    /// nothing, so a partially-satisfied reservation can never be left behind
    /// for the caller to unwind. # C: O(1)
    pub(super) fn charge_blocks(&self, n: u64) -> bool {
        let mut cur = self.used_blocks.load(Ordering::Relaxed);
        loop {
            let Some(next) = cur.checked_add(n) else { return false; };
            if next > self.max_blocks { return false; }
            match self.used_blocks.compare_exchange_weak(cur, next, Ordering::Relaxed, Ordering::Relaxed) {
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
