// Per-mount ext4 state: the owning `Mount`, that mount's page cache,
// and that mount's O_TMPFILE orphan set. Every path/inode operation a
// mount performs goes through its own `RootfsState`, so a second mount
// (e.g. /home, a tools volume) can never read through the first
// mount's device nor corrupt its orphan tracking — Stage 3 of the
// disk-rootfs de-singletonisation.

use alloc::sync::{Arc, Weak};
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
    /// `i_sb` backref (Linux `inode->i_sb` / `s_fs_info ↔ sb`). Back-stamped
    /// by `FileSystem::set_sb` once the VFS `SuperBlock` is built (a transient
    /// empty `Weak` exists only between `fs.root()` and fill-super's
    /// `set_sb`). Every `Ext4*Inode::i_sb()` upgrades this, so `fsid()`
    /// derives from the per-instance `sb.s_dev` (Linux `st_dev`), not a
    /// hardcoded constant. PER MOUNT.
    pub sb: sync::Spinlock<Weak<vfs::SuperBlock>, sync::Inode>,
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
    /// FIFREEZE state (Linux `sb->s_writers.frozen`). Set by
    /// `Ext4SuperOps::freeze_fs`, cleared by `thaw_fs`. PER MOUNT.
    pub frozen: core::sync::atomic::AtomicBool,
    /// Quota options this mount was given (`usrquota`, `usrjquota=`, `jqfmt=`,
    /// …). Sole owner of the mount's quota-option truth: `enable_mount_quotas`
    /// reads it to decide which classes load, from which file, and whether
    /// limits are enforced or only usage tracked. PER MOUNT.
    pub quota_opts: sync::Spinlock<crate::mount_opts::SbQuotaOpts, sync::Inode>,
}

impl RootfsState {
    /// Build state around an opened `Mount`.
    /// # C: O(1)
    pub fn new(mount: Arc<Mount>) -> Arc<Self> {
        Arc::new(Self {
            mount,
            sb: sync::Spinlock::new(Weak::new()),
            page_cache: PageCache::new(),
            orphans: sync::Spinlock::new(Vec::new()),
            cache_hits:   core::sync::atomic::AtomicU64::new(0),
            cache_misses: core::sync::atomic::AtomicU64::new(0),
            frozen:       core::sync::atomic::AtomicBool::new(false),
            quota_opts:   sync::Spinlock::new(crate::mount_opts::SbQuotaOpts::default()),
        })
    }

    /// On-disk quota feature bits of this mount. # C: O(1)
    pub fn quota_features(&self) -> crate::mount_opts::FsQuotaFeatures {
        crate::mount_opts::FsQuotaFeatures {
            quota: self.mount.sb.has_quota(),
            project: self.mount.sb.has_project(),
        }
    }

    /// Snapshot of the quota options in force on this mount. # C: O(MAXQUOTAS)
    pub fn quota_opts(&self) -> crate::mount_opts::SbQuotaOpts { self.quota_opts.lock().clone() }

    /// Parse `data` and fold its quota options into this mount's option state.
    /// `quota_loaded` selects remount semantics. Nothing is applied unless the
    /// whole data string is accepted. # C: O(len(data))
    /// `next` is boxed and this stays out of its caller's frame for the reason
    /// given on `mount_opts::configure`: this runs on the root-filesystem mount
    /// path, the deepest chain the stack-depth gate measures.
    #[inline(never)]
    pub fn configure_mount_opts(&self, data: &str, quota_loaded: bool) -> vfs::KResult<()> {
        let feat = self.quota_features();
        let mut next = alloc::boxed::Box::new(self.quota_opts());
        crate::mount_opts::configure(data, &feat, &mut next, quota_loaded)?;
        *self.quota_opts.lock() = *next;
        Ok(())
    }

    /// Back-stamp the owning VFS `SuperBlock` (`FileSystem::set_sb`). # C: O(1)
    pub fn set_sb(self: &Arc<Self>, sb: Weak<vfs::SuperBlock>) -> vfs::KResult<()> {
        self.mount.set_vfs_superblock(sb.clone());
        let live = sb.upgrade().ok_or(vfs::VfsError::Enodev)?;
        // `__ext4_fill_super` (Linux fs/ext4/super.c) publishes the on-disk
        // timestamp window BEFORE the fs is usable, so `timestamp_truncate`
        // clamps utimes/current_time to what ext4 can actually store: whole
        // seconds capped at 2038 without `i_atime_extra`, else nanoseconds out
        // to year 2446. `s_time_min` is `S32_MIN` either way — 1901-12-13, so
        // a restored pre-1970 archive timestamp is NOT clamped to the epoch.
        let (gran, min, max) =
            crate::timestamp::time_range_for_inode_size(self.mount.sb.inode_size as usize);
        live.set_time_gran(gran);
        live.set_time_range(min, max);
        *self.sb.lock() = sb;
        if let Err(e) = self.enable_mount_quotas(&live, false) {
            self.mount.set_vfs_superblock(Weak::new());
            *self.sb.lock() = Weak::new();
            return Err(e);
        }
        let _ = self.mount.orphan_cleanup();
        Ok(())
    }

    /// Turn on every quota class this mount's options + on-disk features ask
    /// for. Delegates to `mountquota`. # C: O(quota files)
    pub(crate) fn enable_mount_quotas(self: &Arc<Self>, sb: &Arc<vfs::SuperBlock>, allow_readonly: bool) -> vfs::KResult<()> {
        super::mountquota::enable_mount_quotas(self, sb, allow_readonly)
    }

    /// Owning `SuperBlock` (`i_sb`), if the SB is built and live. # C: O(1)
    pub fn i_sb(&self) -> Option<Arc<vfs::SuperBlock>> { self.sb.lock().upgrade() }

    /// Open `dev` as a fresh ext4 mount + state.
    /// # C: O(N_groups + 1024)
    pub fn open(dev: Arc<dyn BlockDevice>) -> KResult<Arc<Self>> {
        let mount = Mount::open_with_orphan_cleanup(dev, false).map_err(|_| BlockError::Eio)?;
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

    /// The filesystem's STABLE identity — the folded on-disk UUID `statfs`
    /// reports as `f_fsid`, which survives across mounts.
    ///
    /// NOT `st_dev`. `st_dev` is the per-mount ephemeral `sb.s_dev`, reached
    /// through [`vfs::Inode::fsid`], and it is what an fsnotify mark keys on.
    /// The two are different number spaces and this one is neither a
    /// substitute for nor derivable from the other.
    ///
    /// Delegates rather than deriving: the fold has exactly one implementation
    /// so a caller cannot be handed two different "identities" for one
    /// filesystem. It previously computed a SECOND, incompatible hash of the
    /// same UUID while documenting itself as `st_dev` — three numbers claiming
    /// to be one filesystem's identity, two of them documented as each other.
    /// # C: O(1)
    pub fn uuid_fsid(&self) -> u64 {
        crate::superblock::uuid_to_fsid(&self.mount.sb.uuid)
    }

    /// Whole-path lookup → ext4 inode number.
    /// # C: O(path components × dir size)
    pub fn lookup_path(&self, path: &[u8]) -> Option<u32> { self.mount.lookup_path(path).ok() }

    /// Resolve a single child in directory `dir_ino`.
    /// # C: O(N_entries in dir)
    pub fn lookup_child_ino(&self, dir_ino: u32, name: &str) -> Option<u32> {
        self.lookup_child_ino_result(dir_ino, name).ok()
    }

    /// Resolve one child without discarding backend lookup errors. # C: O(N_entries)
    pub fn lookup_child_ino_result(&self, dir_ino: u32, name: &str) -> Result<u32, crate::MountError> {
        let dir = self.mount.read_inode(dir_ino)?;
        self.mount.lookup_in_dir(&dir, name.as_bytes())
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
            // DIAG (debug-mount): for LARGE files (libc.so.6 ~2.4 MB) log the
            // content of block 487 (file off 0x1e7000 — where libc's .bss lock
            // lives). On a clean boot this is libc's real .data bytes; on a
            // wedged boot, if read_full_file mis-maps the block, it shows
            // ANOTHER block's bytes (e.g. "/lib64/..."). Names which block read
            // returned wrong content.
            #[cfg(feature = "debug-mount")]
            if total > 0x180000 && k == 487 {
                // Also resolve the physical block: if PHYS varies across reads
                // → extent-mapping race; if PHYS is stable but the bytes vary →
                // data-read race in virtio-blk.
                let phys = self.mount.resolve_pblock(&inode, k as u32).unwrap_or(0);
                klog::write_raw(b"[mnt] LIBCBLK ino=");
                klog::write_dec_u64(ino as u64);
                klog::write_raw(b" phys=");
                klog::write_dec_u64(phys);
                klog::write_raw(b" b0_3=");
                for i in 0..4usize { klog::write_hex_u64(blk.get(i).copied().unwrap_or(0) as u64); klog::write_raw(b","); }
                klog::write_raw(b" b0xfe8=");
                klog::write_hex_u64(blk.get(0xfe8).copied().unwrap_or(0) as u64);
                klog::write_raw(b"\n");
            }
            let take = core::cmp::min(bs, total - out.len());
            out.extend_from_slice(&blk[..take]);
        }
        Some(out)
    }

    /// Page-cache-backed read of regular file `ino` into `dst` starting at
    /// byte `off` (Linux `address_space` fill). Pages are keyed by `InodeId`
    /// in this mount's shared `page_cache`, so every mapper/reader of one
    /// inode hits the SAME cached pages — the `i_mapping` read-side share.
    /// Short read past EOF; holes read as zero. # C: O(dst.len)
    pub fn read_cached(&self, ino: u32, off: u64, dst: &mut [u8]) -> Result<usize, ()> {
        let inode = self.mount.read_inode(ino).map_err(|_| ())?;
        if !inode.is_reg() { return Err(()); }
        let inode_id = InodeId(ino as u64);
        let total = inode.size;
        let mut written = 0usize;
        while written < dst.len() {
            let cur = off + written as u64;
            if cur >= total { break; }
            let page_off = cur & !((PAGE_BYTES as u64) - 1);
            let in_page  = (cur - page_off) as usize;
            let cached = self.page_cache.read_page_with(inode_id, page_off, || {
                let bs = self.mount.sb.block_size as u64;
                let blocks_per_page = (PAGE_BYTES as u64 / bs).max(1) as u32;
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
            }).map_err(|_| ())?;
            let g = cached.data.lock();
            let avail_in_page = g.len().saturating_sub(in_page);
            let want = (dst.len() - written).min(avail_in_page).min((total - cur) as usize);
            if want == 0 { break; }
            dst[written..written + want].copy_from_slice(&g[in_page..in_page + want]);
            written += want;
        }
        Ok(written)
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
