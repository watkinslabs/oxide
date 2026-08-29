use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use crate::jbd2::StagedBlock;
use super::super::{JournalHandle, Mount, MountError};
use super::ctx_id;
use super::super::io::read_byte_range;
use super::metadata::publish_metadata;

struct MetadataPrefetchJob {
    mount: Arc<Mount>,
    first_lba: u64,
    blocks: u32,
}

#[cfg(target_os = "oxide-kernel")]
fn run_metadata_prefetch(raw: usize) {
    // SAFETY: the raw pointer is created by Box::into_raw below and queued at
    // most once; the worker takes ownership before running the I/O.
    let job = unsafe { Box::from_raw(raw as *mut MetadataPrefetchJob) };
    let _ = job.mount.prefetch_metadata_blocks(job.first_lba, job.blocks);
    job.mount.finish_metadata_prefetch(job.first_lba);
}

impl Mount {
    /// Queue an inode-table window for asynchronous cache warming. The mount
    /// owns the job through its Arc; a Weak self-reference means the queued
    /// work cannot keep an otherwise-unmounted volume alive indefinitely.
    /// # C: O(1) enqueue + O(window) worker I/O
    pub(crate) fn prefetch_metadata_blocks_async(&self, first_lba: u64, blocks: u32) {
        if blocks == 0 { return; }
        let should_queue = {
            let mut state = self.state.lock();
            state.metadata_prefetches.insert(first_lba)
        };
        if !should_queue { return; }
        let Some(owner) = self.self_ref.lock().upgrade() else {
            // Standalone hosted Mount values are not Arc-owned. Preserve the
            // deterministic hosted behavior while the real mount path uses
            // the asynchronous worker below.
            let _ = self.prefetch_metadata_blocks(first_lba, blocks);
            self.finish_metadata_prefetch(first_lba);
            return;
        };
        let raw = Box::into_raw(Box::new(MetadataPrefetchJob { mount: owner, first_lba, blocks }));
        #[cfg(target_os = "oxide-kernel")]
        if sched::live::workqueue::queue_work(run_metadata_prefetch, raw as usize) { return; }
        // Hosted tests have no worker thread. If queue_work refuses on target,
        // reclaim and run synchronously rather than leaking the job.
        let job = unsafe { Box::from_raw(raw) };
        let _ = job.mount.prefetch_metadata_blocks(job.first_lba, job.blocks);
        job.mount.finish_metadata_prefetch(job.first_lba);
    }

    fn finish_metadata_prefetch(&self, first_lba: u64) {
        self.state.lock().metadata_prefetches.remove(&first_lba);
    }

    /// Warm a contiguous inode-table window into the canonical metadata cache.
    /// The read is one owned block-device operation, while publication remains
    /// per filesystem block so ordinary metadata readers and invalidation use
    /// the same source of truth. # C: O(window) cache publication + 1 I/O
    pub(crate) fn prefetch_metadata_blocks(&self, first_lba: u64, blocks: u32)
        -> Result<(), MountError>
    {
        if blocks == 0 { return Ok(()); }
        let bs = self.sb.block_size as u64;
        let bytes = read_byte_range(&*self.dev, first_lba * bs, blocks as usize * bs as usize)?;
        if bytes.len() != blocks as usize * bs as usize { return Err(MountError::BlockIo); }
        let epoch = self.state.lock().metadata_epoch;
        let mut state = self.state.lock();
        if state.metadata_epoch != epoch { return Ok(()); }
        for i in 0..blocks as u64 {
            let start = i as usize * bs as usize;
            let end = start + bs as usize;
            if state.shadow.as_ref().is_some_and(|shadow| shadow.contains_key(&(first_lba + i))) {
                continue;
            }
            publish_metadata(&mut state, first_lba + i,
                             alloc::sync::Arc::new(bytes[start..end].to_vec()));
        }
        Ok(())
    }

    /// Open a shadow scope: every `metadata_write` inside `f`
    /// populates `state.shadow` with the new fs-block bytes;
    /// shadow-aware reads (`read_metadata_block`, `read_meta_byte_range`)
    /// see the staged bytes immediately, so multiple sub-ops
    /// (e.g. two `alloc_block` calls) within one fs op observe
    /// each other's writes. At scope close, the shadow drains
    /// into `commit_metadata` as one JBD2 transaction. On
    /// `Err`, the shadow is dropped (no commit, no target writes).
    ///
    /// Re-entrant: nested calls participate in the outermost
    /// shadow without opening a new one.
    /// # C: O(N shadow blocks) commit + 2 journal I/Os + N target I/Os
    /// Serialize + run a top-level metadata transaction. Acquires the reentrant
    /// transaction gate for the current context so concurrent tasks/CPUs can't
    /// race the group bitmaps / GDT / superblock counters / shadow; nested
    /// same-context calls join without re-locking. # C: same as inner.
    pub fn run_journaled<R, F>(&self, f: F) -> Result<R, MountError>
    where F: FnOnce(&Self) -> Result<R, MountError>
    {
        if self.batch_is_running() { return self.run_batch_handle(f); }
        self.txn_acquire();
        let r = self.run_journaled_inner(f, false);
        self.txn_release();
        r
    }

    /// Run a metadata transaction whose durable journal commit is returned to
    /// the caller, while home-block checkpointing remains with the background
    /// checkpoint owner. Create operations use this Linux-shaped boundary so
    /// VFS inode locks do not cover unrelated home writeback. # C: O(N staged) journal I/O
    pub(crate) fn run_journaled_deferred<R, F>(&self, f: F) -> Result<R, MountError>
    where F: FnOnce(&Self) -> Result<R, MountError>
    {
        if self.batch_is_running() { return self.run_batch_handle(f); }
        self.txn_acquire();
        let r = self.run_journaled_inner(f, true);
        self.txn_release();
        r
    }

    fn batch_is_running(&self) -> bool {
        let s = self.state.lock();
        s.batch && s.shadow.is_some()
    }

    /// Run one handle in the running batch while retaining the transaction
    /// gate across the operation body. The shadow, allocator mirrors, and
    /// rollback frame are one coupled ownership unit until their buffer-head
    /// equivalent is complete.
    /// # C: O(1) admission/finalization + F
    fn run_batch_handle<R, F>(&self, f: F) -> Result<R, MountError>
    where F: FnOnce(&Self) -> Result<R, MountError>
    {
        self.txn_acquire();
        if !self.batch_is_running() {
            let r = self.run_journaled_inner(f, false);
            self.txn_release();
            return r;
        }
        let id = crate::mount::core::ctx_id();
        self.state.lock().handles.entry(id)
            .or_insert_with(|| JournalHandle { frames: alloc::vec::Vec::new() })
            .frames.push(alloc::collections::BTreeMap::new());
        let r = f(self);
        let result = match r {
            Ok(v) => { self.batch_frame_commit(); Ok(v) }
            Err(e) => { self.batch_frame_rollback(); Err(e) }
        };
        self.txn_release();
        if result.is_ok() { self.maybe_commit_batch()?; }
        result
    }

    /// Try to claim the transaction gate, retaining same-context reentrancy.
    /// # C: O(1)
    fn try_txn_acquire(&self, me: u64) -> bool {
        use ::core::sync::atomic::Ordering;
        if self.txn_owner.load(Ordering::Acquire) == me {
            self.txn_depth.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        if self.txn_owner.compare_exchange(0, me, Ordering::AcqRel, Ordering::Relaxed).is_err() {
            return false;
        }
        self.txn_depth.store(1, Ordering::Relaxed);
        true
    }

    /// Try the transaction gate for an asynchronous owner without sleeping.
    /// # C: O(1)
    pub(crate) fn try_txn_acquire_current(&self) -> bool {
        self.try_txn_acquire(ctx_id())
    }

    /// Reentrant transaction-gate acquire keyed on `ctx_id()`. A contender
    /// publishes on the mount's wait queue, rechecks the atomic claim, then
    /// sleeps until the releasing owner wakes it.
    /// # Ctx: process
    /// # Sleeps: yes on contention
    /// # C: O(N wakeups)
    pub(crate) fn txn_acquire(&self) {
        let me = ctx_id();
        if self.try_txn_acquire(me) { return; }
        // SAFETY: this process-context waiter holds neither the transaction
        // gate nor the state lock; release publishes owner=0 before wake_all.
        let _ = unsafe {
            sched::live::wait_event_uninterruptible(&self.txn_wait, || self.try_txn_acquire(me))
        };
    }

    /// Release one level of the transaction gate; frees it at depth 0.
    /// # C: O(1)
    pub(crate) fn txn_release(&self) {
        use ::core::sync::atomic::Ordering;
        if self.txn_depth.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.txn_owner.store(0, Ordering::Release);
            self.txn_wait.wake_all();
        }
    }

    fn run_journaled_inner<R, F>(&self, f: F, defer_checkpoint: bool) -> Result<R, MountError>
    where F: FnOnce(&Self) -> Result<R, MountError>
    {
        let (already_open, batch) = { let s = self.state.lock(); (s.shadow.is_some(), s.batch) };
        if already_open {
            if !batch { return f(self); }
            // Batch mode: this op JOINS the running transaction. Push an undo
            // frame so a failure rolls back only THIS op's staged blocks (and
            // its metadata-buffer mutations, refreshed from the restored shadow)
            // without discarding prior batched ops. Success merges the frame up
            // (or drops it at top level, leaving the writes in the running txn).
            let id = crate::mount::core::ctx_id();
            self.state.lock().handles.entry(id)
                .or_insert_with(|| JournalHandle { frames: alloc::vec::Vec::new() })
                .frames.push(alloc::collections::BTreeMap::new());
            let r = f(self);
            match r {
                Ok(v) => { self.batch_frame_commit(); self.maybe_commit_batch()?; Ok(v) }
                Err(e) => { self.batch_frame_rollback(); Err(e) }
            }
        } else {
            self.state.lock().shadow = Some(alloc::collections::BTreeMap::new());
            let r = f(self);
            let shadow = self.state.lock().shadow.take().unwrap_or_default();
            match r {
                Ok(v) => {
                    if !shadow.is_empty() {
                        let staged: Vec<StagedBlock> = shadow.into_iter()
                            .map(|(target_lba, data)| StagedBlock { target_lba, data })
                            .collect();
                        if defer_checkpoint {
                            self.commit_metadata_deferred(staged.clone())?;
                        } else {
                            self.commit_metadata(staged.clone())?;
                        }
                        self.cache_committed(&staged);
                        let mut s = self.state.lock();
                        for buffer in s.metadata_buffers.values() {
                            buffer.transaction_owner.store(0, ::core::sync::atomic::Ordering::Release);
                        }
                        s.block_bitmap_cache.clear();
                        s.group_free_order.clear();
                        s.group_free_order_index.clear();
                        s.group_avg_fragment_order.clear();
                        s.group_avg_fragment_index.clear();
                        s.committed_generation = s.running_generation;
                        s.running_generation = 0;
                    }
                    Ok(v)
                }
                Err(e) => {
                    self.refresh_cached_meta();
                    Err(e)
                }
            }
        }
    }

    /// Join the current batch with an undo frame, without re-entering the
    /// transaction gate or asking the batch owner to consider a commit. The
    /// caller must already own the outer transaction; this is the Linux-shaped
    /// equivalent of a helper receiving the caller's existing journal handle.
    /// # C: O(1) frame setup + F
    pub(crate) fn run_journaled_joined<R, F>(&self, f: F) -> Result<R, MountError>
    where F: FnOnce(&Self) -> Result<R, MountError>
    {
        let batch = { let s = self.state.lock(); s.shadow.is_some() && s.batch };
        if !batch { return f(self); }
        let id = crate::mount::core::ctx_id();
        self.state.lock().handles.entry(id)
            .or_insert_with(|| JournalHandle { frames: alloc::vec::Vec::new() })
            .frames.push(alloc::collections::BTreeMap::new());
        match f(self) {
            Ok(v) => { self.batch_frame_commit(); Ok(v) }
            Err(e) => { self.batch_frame_rollback(); Err(e) }
        }
    }

    /// Run a top-level create op with `creating` set (which defers the
    /// size-triggered batch commit until AFTER the transaction gate is released:
    /// the batch commit's `dev.flush` SLEEPS on the virtio completion, and
    /// yielding I/O while the gate is held livelocks a spinning contender). The
    /// gate is now taken inside `run_journaled` for EVERY mutator, so creates no
    /// longer need a separate lock; the commit still drains the shadow atomically
    /// under `state.lock`, so ordering is preserved.
    /// # C: same as the inner op + amortized O(1) deferred commit
    pub(crate) fn create_op<R, F>(&self, f: F) -> Result<R, MountError>
    where F: FnOnce(&Self) -> Result<R, MountError>
    {
        let r = {
            self.creating.store(true, ::core::sync::atomic::Ordering::Release);
            let r = self.run_journaled_deferred(f);
            self.creating.store(false, ::core::sync::atomic::Ordering::Release);
            r
        };
        let v = match r {
            Ok(v) => v,
            Err(e) => {
                self.refresh_cached_meta();
                return Err(e);
            }
        };
        self.maybe_commit_batch()?;
        Ok(v)
    }

    /// Drop allocator summaries after a failed operation restores the
    /// shadow-aware metadata image. # C: O(1)
    pub(crate) fn refresh_cached_meta(&self) {
        // A failed batched operation may have restored bitmap bytes in the
        // shadow after the allocator published a cache entry. Drop all bitmap
        // snapshots so the next group scan revalidates against that view.
        let mut s = self.state.lock();
        s.block_bitmap_cache.clear();
        s.group_free_order.clear();
        s.group_free_order_index.clear();
        s.group_avg_fragment_order.clear();
        s.group_avg_fragment_index.clear();
    }

    /// Refresh allocator mirrors after one handle rolls back. Only reload the
    /// GDT/SB blocks touched by that handle, while holding metadata ownership
    /// for those blocks so another handle's update cannot be lost.
    /// # C: O(N touched metadata blocks + GDT bytes)
    pub(crate) fn refresh_cached_meta_for(&self, affected: &[u64]) {
        let bs = self.sb.block_size as u64;
        if bs == 0 || affected.is_empty() { return; }
        let _ = bs;
        let mut s = self.state.lock();
        s.block_bitmap_cache.clear();
        s.group_free_order.clear();
        s.group_free_order_index.clear();
        s.group_avg_fragment_order.clear();
        s.group_avg_fragment_index.clear();
    }

    /// No-op alias kept for legacy call sites. The shadow
    /// scope mid-flushes implicitly through `metadata_write`
    /// populating state.shadow which subsequent reads consult.
    /// # C: O(1)
    pub fn flush_pending_tx(&self) -> Result<(), MountError> { Ok(()) }

    pub(crate) fn mark_inode_dirty(&self, ino: u32, datasync: bool) {
        let mut s = self.state.lock();
        let tid = s.running_generation;
        if tid == 0 { return; }
        let e = s.inode_generations.entry(ino).or_insert((0, 0));
        e.0 = tid;
        if datasync { e.1 = tid; }
    }

    pub(crate) fn inode_sync_needed(&self, ino: u32, datasync: bool) -> bool {
        let s = self.state.lock();
        let tid = s.inode_generations.get(&ino).map_or(0, |p| if datasync { p.1 } else { p.0 });
        tid != 0 && tid > s.committed_generation
    }

    pub(crate) fn mark_generation_barriered(&self, generation: u64) {
        let mut s = self.state.lock();
        if generation > s.barrier_generation { s.barrier_generation = generation; }
    }

    /// Read `len` bytes starting at `byte_off`, splicing in
    /// shadow-buffered fs-block bytes where present. Use this
    /// in metadata read paths inside a `run_journaled` scope so
    /// staged-but-uncommitted writes are visible.
    /// # C: O(N affected fs blocks)
    #[inline(never)]
    pub fn read_meta_byte_range(&self, byte_off: u64, len: usize) -> Result<Vec<u8>, MountError> {
        if len == 0 { return Ok(Vec::new()); }
        let bs = self.sb.block_size as u64;
        let first_blk = byte_off / bs;
        let last_byte = byte_off.saturating_add(len as u64);
        let last_blk_excl = (last_byte + bs - 1) / bs;
        let n_blocks = (last_blk_excl - first_blk) as u32;
        let inner_off = (byte_off - first_blk * bs) as usize;
        // Assemble the requested range directly.  The previous implementation
        // first built a complete block-aligned buffer and then cloned the
        // requested slice, doubling transient metadata allocation during
        // mount and bitmap reads.  Linux's buffer-cache readers copy only the
        // bytes requested by the caller; keep the same shadow/cache source
        // while avoiding that second temporary allocation.
        //
        // The per-block read is the SHARED one for the same reason: an inode
        // read wants 256 bytes out of a 4 KiB block, and taking an owned copy
        // of the block first made every inode read allocate and copy the whole
        // block to throw all but the slot away.
        let mut out = Vec::with_capacity(len);
        for i in 0..n_blocks as u64 {
            let block = self.read_metadata_block_shared(first_blk + i)?;
            let start = if i == 0 { inner_off } else { 0 };
            let end = core::cmp::min(bs as usize, inner_off + len - out.len());
            out.extend_from_slice(&block[start..end]);
        }
        debug_assert_eq!(out.len(), len);
        Ok(out)
    }

    /// Read the authoritative free-blocks counter from the shadow/cache-backed
    /// superblock buffer, as Linux reads `s_free_blocks_count` from its cached
    /// superblock rather than maintaining a second mutable counter.
    /// # C: O(1) cached metadata read
    pub fn state_free_blocks(&self) -> u64 {
        let Ok(sb) = self.read_meta_byte_range(
            crate::superblock::SUPERBLOCK_OFFSET,
            crate::superblock::SUPERBLOCK_LEN) else { return self.sb.free_blocks_count; };
        let lo = u32::from_le_bytes(sb[crate::superblock::SB_OFF_FREE_BLOCKS_LO..crate::superblock::SB_OFF_FREE_BLOCKS_LO + 4].try_into().unwrap()) as u64;
        let hi = u32::from_le_bytes(sb[crate::superblock::SB_OFF_FREE_BLOCKS_HI..crate::superblock::SB_OFF_FREE_BLOCKS_HI + 4].try_into().unwrap()) as u64;
        (hi << 32) | lo
    }

    /// Read the authoritative free-inodes counter from the superblock buffer.
    /// # C: O(1) cached metadata read
    pub fn state_free_inodes(&self) -> u32 {
        let Ok(sb) = self.read_meta_byte_range(
            crate::superblock::SUPERBLOCK_OFFSET,
            crate::superblock::SUPERBLOCK_LEN) else { return self.sb.free_inodes_count; };
        u32::from_le_bytes(sb[crate::superblock::SB_OFF_FREE_INODES..crate::superblock::SB_OFF_FREE_INODES + 4].try_into().unwrap())
    }
}
