// One mounted instance's enforced state.
//
// This is the ONLY place a hugetlbfs mount's options live: its granule, the
// subpool its `size=`/`min_size=` became, its inode ceiling, and the ownership
// its root carries. Every consumer reads them from here, so no two of them can
// disagree about how big the mount is.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicI64, Ordering};

use pmm::hugetlb::{self, HugePageSize, Subpool};
use sync::{Inode as InodeClass, Spinlock};
use vfs::{KResult, VfsError};

use super::limits::{DEFAULT_ROOT_GID, DEFAULT_ROOT_MODE, DEFAULT_ROOT_UID, NO_LIMIT};
use super::mount_opts::HugetlbfsOpts;

pub struct HugetlbfsSb {
    /// The granule every file on this mount is made of.
    size:        HugePageSize,
    /// `size=`/`min_size=` accounting. Absent when the mount named neither, in
    /// which case it charges straight through to the global pool.
    spool:       Option<Spinlock<Subpool, InodeClass>>,
    /// `nr_inodes=`, or [`NO_LIMIT`].
    max_inodes:  i64,
    free_inodes: AtomicI64,
    uid:         u32,
    gid:         u32,
    mode:        u16,
}

impl HugetlbfsSb {
    /// Build a mount's state from its parsed options.
    ///
    /// A mount that names a `min_size=` takes that reservation from the global
    /// pool HERE, once, and holds it for its lifetime — which is what makes a
    /// minimum a guarantee rather than a hope. A pool that cannot cover it
    /// fails the mount with `ENOMEM` rather than mounting something that
    /// silently cannot honour its own floor.
    /// # C: O(min_size pages)
    pub(super) fn from_opts(opts: &HugetlbfsOpts, pool_max: u64) -> KResult<Arc<Self>> {
        let size = opts.size();
        let sizes = opts.resolve(pool_max)?;
        let max_inodes = opts.max_inodes();
        let spool = if Subpool::is_limited(sizes.max_hpages, sizes.min_hpages) {
            if sizes.min_hpages != NO_LIMIT && sizes.min_hpages > 0 {
                hugetlb::reserve(size, sizes.min_hpages as u64).map_err(|()| VfsError::Enomem)?;
            }
            Some(Spinlock::new(Subpool::new(sizes.max_hpages, sizes.min_hpages)))
        } else { None };
        Ok(Arc::new(Self {
            size, spool, max_inodes,
            free_inodes: AtomicI64::new(max_inodes),
            uid:  opts.uid.unwrap_or(DEFAULT_ROOT_UID),
            gid:  opts.gid.unwrap_or(DEFAULT_ROOT_GID),
            mode: opts.mode.unwrap_or(DEFAULT_ROOT_MODE),
        }))
    }

    /// An instance with no ceiling of any kind: the kernel-private mount that
    /// backs `memfd_create(MFD_HUGETLB)` and anonymous `mmap(MAP_HUGETLB)`,
    /// which the global pool alone bounds.
    /// # C: O(1)
    pub(super) fn unlimited(size: HugePageSize) -> Arc<Self> {
        Arc::new(Self {
            size, spool: None, max_inodes: NO_LIMIT, free_inodes: AtomicI64::new(NO_LIMIT),
            uid: DEFAULT_ROOT_UID, gid: DEFAULT_ROOT_GID, mode: DEFAULT_ROOT_MODE,
        })
    }

    /// This mount's granule. # C: O(1)
    pub(super) fn huge_size(&self) -> HugePageSize { self.size }
    /// Root-inode permission bits. # C: O(1)
    pub(super) fn mode(&self) -> u16 { self.mode }
    /// Root-inode owner. # C: O(1)
    pub(super) fn owner(&self) -> (u32, u32) { (self.uid, self.gid) }

    /// Take one inode slot; `false` (caller → `ENOSPC`) at `nr_inodes=`.
    /// # C: O(1)
    pub(super) fn charge_inode(&self) -> bool {
        if self.max_inodes == NO_LIMIT { return true; }
        let mut cur = self.free_inodes.load(Ordering::Relaxed);
        loop {
            if cur <= 0 { return false; }
            match self.free_inodes.compare_exchange_weak(cur, cur - 1, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_)  => return true,
                Err(c) => cur = c,
            }
        }
    }

    /// Give one inode slot back. # C: O(1)
    pub(super) fn free_inode(&self) {
        if self.max_inodes != NO_LIMIT { self.free_inodes.fetch_add(1, Ordering::Relaxed); }
    }

    /// Reserve `n` huge pages for a mapping of a file on this mount.
    ///
    /// The mount's own ceiling is charged first, then whatever the global pool
    /// still has to promise. A reservation is taken when the mapping is
    /// established, not when it is touched, so a program that maps more than
    /// the mount can hold learns it from `mmap` rather than from a fault it
    /// cannot handle — which is why the errno here is `ENOMEM`.
    /// # C: O(n)
    pub(super) fn reserve_pages(&self, n: u64) -> KResult<()> {
        if n == 0 { return Ok(()); }
        let global = match &self.spool {
            Some(sp) => sp.lock().get_pages(n as i64).map_err(|()| VfsError::Enomem)?.global_delta,
            None     => n as i64,
        };
        if global <= 0 { return Ok(()); }
        match hugetlb::reserve(self.size, global as u64) {
            Ok(())  => Ok(()),
            Err(()) => {
                // The mount's charge must not survive a global refusal, or the
                // mount would count pages nothing ever promised.
                if let Some(sp) = &self.spool { let _ = sp.lock().put_pages(n as i64); }
                Err(VfsError::Enomem)
            }
        }
    }

    /// Give `n` reserved-but-unfaulted pages back.
    /// # C: O(1)
    pub(super) fn unreserve_pages(&self, n: u64) {
        if n == 0 { return; }
        let global = match &self.spool { Some(sp) => sp.lock().put_pages(n as i64), None => n as i64 };
        if global > 0 { hugetlb::unreserve(self.size, global as u64); }
    }

    /// Charge one page a mapping is faulting WITHOUT a reservation covering it
    /// — a read of a file page nothing reserved. Refused with `ENOSPC`: unlike
    /// a mapping, this is a write into a filesystem that is full.
    /// # C: O(1)
    pub(super) fn charge_unreserved_page(&self) -> KResult<()> {
        if let Some(sp) = &self.spool {
            sp.lock().get_pages(1).map_err(|()| VfsError::Enospc)?;
        }
        Ok(())
    }

    /// Release one page the mount held.
    /// # C: O(1)
    pub(super) fn uncharge_page(&self) {
        if let Some(sp) = &self.spool { let _ = sp.lock().put_pages(1); }
    }

    /// `statfs(2)` — Linux reports block counts only for a mount with a
    /// subpool, because a mount with no ceiling has no total to report.
    /// # C: O(1)
    pub(super) fn statfs(&self) -> vfs::SbStatFs {
        let mut st = vfs::SbStatFs {
            f_type:    super::uapi::HUGETLBFS_MAGIC,
            f_bsize:   self.size.bytes() as u32,
            f_frsize:  self.size.bytes() as u32,
            f_namelen: vfs::path::NAME_MAX as u64,
            ..Default::default()
        };
        if let Some(sp) = &self.spool {
            let g = sp.lock();
            if let (Some(blocks), Some(free)) = (g.blocks(), g.blocks_free()) {
                st.f_blocks = blocks;
                st.f_bfree  = free;
                st.f_bavail = free;
            }
            drop(g);
            if self.max_inodes != NO_LIMIT {
                st.f_files = self.max_inodes as u64;
                st.f_ffree = self.free_inodes.load(Ordering::Relaxed).max(0) as u64;
            }
        }
        st
    }

    /// `/proc/mounts` option string. Only what differs from the defaults, plus
    /// the page size, which is always shown because it is the one thing a
    /// hugetlbfs mount cannot be understood without.
    /// # C: O(1)
    pub(super) fn show_options(&self) -> alloc::string::String {
        use core::fmt::Write;
        let mut s = alloc::string::String::new();
        if self.uid != DEFAULT_ROOT_UID { let _ = write!(s, ",uid={}", self.uid); }
        if self.gid != DEFAULT_ROOT_GID { let _ = write!(s, ",gid={}", self.gid); }
        if self.mode != DEFAULT_ROOT_MODE { let _ = write!(s, ",mode={:o}", self.mode); }
        if self.max_inodes != NO_LIMIT { let _ = write!(s, ",nr_inodes={}", self.max_inodes); }
        let kib = self.size.bytes() / 1024;
        if kib >= 1024 { let _ = write!(s, ",pagesize={}M", kib / 1024); }
        else           { let _ = write!(s, ",pagesize={}K", kib); }
        if let Some(sp) = &self.spool {
            let g = sp.lock();
            if g.max_hpages != NO_LIMIT {
                let _ = write!(s, ",size={}", (g.max_hpages as u64) << self.size.shift());
            }
            if g.min_hpages != NO_LIMIT {
                let _ = write!(s, ",min_size={}", (g.min_hpages as u64) << self.size.shift());
            }
        }
        s
    }
}
