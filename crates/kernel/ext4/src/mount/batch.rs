use alloc::vec::Vec;

use crate::jbd2::StagedBlock;

use super::{Mount, MountError};

impl Mount {
    /// Enable cross-operation batching. Idempotent. # C: O(1)
    pub fn begin_batch(&self) {
        self.txn_acquire();
        {
            let mut s = self.state.lock();
            s.batch = true;
            if s.shadow.is_none() { s.shadow = Some(alloc::collections::BTreeMap::new()); }
        }
        self.txn_release();
    }

    /// Commit the running transaction while excluding metadata readers and
    /// mutators from the shadow-drain through the final target-device write.
    /// # C: O(N shadow blocks) + one journal commit
    pub fn commit_batch(&self) -> Result<(), MountError> {
        self.commit_batch_for(None, true).map(|_| ())
    }

    /// Commit the running transaction from the periodic journal owner. The
    /// commit record is made durable, but its home blocks remain for the
    /// checkpoint pass instead of extending this timer's critical section.
    /// # C: O(N shadow blocks) journal I/O; home writeback is asynchronous
    pub(crate) fn commit_batch_background(&self) -> Result<(), MountError> {
        self.commit_batch_for(None, false).map(|_| ())
    }

    /// Wait for a durable journal commit; checkpoint only for whole-fs sync.
    /// Direct synchronous writes require a device flush. Returns true only
    /// when that direct-write barrier was completed. # C: O(transaction I/O)
    pub(crate) fn commit_batch_for(&self, inode: Option<(u32, bool)>, wait_checkpoint: bool) -> Result<bool, MountError> {
        #[cfg(feature = "debug-fsync-latency")]
        let gate_ns = crate::fsync_latency::now_ns();
        loop {
            self.txn_acquire();
            // The gate serializes committers. Only a recursive call from its
            // owner can see the flag set here; another task must wait.
            if self.committing_batch.load(core::sync::atomic::Ordering::Acquire) {
                self.txn_release();
                return Ok(false);
            }
            let (active, nested) = {
                let s = self.state.lock();
                (s.active_handles != 0, s.handles.contains_key(&super::core::ctx_id()))
            };
            if !active { break; }
            self.txn_release();
            if nested { return Ok(false); }
            // SAFETY: commit admission holds no lock while active metadata
            // handles finish and notify the mount's batch waiters.
            let _ = unsafe {
                sched::live::wait_event_uninterruptible(&self.batch_wait,
                    || self.state.lock().active_handles == 0)
            };
        }
        self.committing_batch.store(true, core::sync::atomic::Ordering::Release);
        let _commit_guard = BatchCommitGuard(self);
        #[cfg(feature = "debug-fsync-latency")]
        crate::fsync_latency::report(b"batch-gate", gate_ns, 0);
        let needed = inode.map_or(true, |(ino, datasync)| self.inode_sync_needed(ino, datasync));
        #[cfg(feature = "debug-fsync-latency")]
        let staged_blocks = self.state.lock().shadow.as_ref().map_or(0, |s| s.len() as u64);
        #[cfg(feature = "debug-fsync-latency")]
        let commit_ns = crate::fsync_latency::now_ns();
        // Ordered-mode data submission is part of the commit, not a prelude to
        // it: it allocates blocks and stages their bitmaps through the same
        // transaction. Run outside the gate, alongside another context's
        // writeback, two allocations read the same group bitmap and one
        // overwrote the other -- an extent pointing at blocks the bitmap calls
        // free, which the next allocation then hands to a second file.
        let result = if !needed {
            Ok(false)
        } else {
            #[cfg(feature = "debug-fsync-latency")]
            let started_ns = crate::fsync_latency::now_ns();
            let ordered = self.order_data_before_commit();
            #[cfg(feature = "debug-fsync-latency")]
            crate::fsync_latency::report(b"batch-order", started_ns, 0);
            ordered.and_then(|()| self.commit_batch_inner())
        };
        #[cfg(feature = "debug-fsync-latency")]
        crate::fsync_latency::report(b"batch-commit", commit_ns, staged_blocks);
        result?;
        if wait_checkpoint { self.checkpoint_pending()?; }
        // Journal commits already published a durable recovery record.
        // Direct writes have no such fence: synchronous callers must flush
        // even when only file data changed and no metadata commit was needed.
        // Background direct writeback leaves the barrier generation untouched.
        if self.sb.journal_inum == 0 && self.behaviour().barrier
            && (wait_checkpoint || inode.is_some())
        {
            self.dev.flush().map_err(|_| MountError::BlockIo)?;
            let generation = self.state.lock().committed_generation;
            self.mark_generation_barriered(generation);
            return Ok(true);
        }
        Ok(false)
    }

    /// `data=ordered`: put this mount's dirty file data on the device BEFORE
    /// the metadata that references it commits.
    ///
    /// That ordering is the entire difference between `ordered` and
    /// `writeback`. Without it a crash between the metadata commit and the data
    /// writeback leaves a committed extent pointing at a block still holding
    /// whatever was there before — someone else's deleted file, readable by
    /// whoever now owns the extent. `writeback` accepts exactly that in
    /// exchange for not waiting here; `journal` needs nothing here because its
    /// data already went through the journal with the metadata.
    ///
    /// Runs under the reentrant transaction gate. All dirty inodes must be
    /// ordered because the running metadata transaction spans the mount.
    /// # C: O(N_dirty) when ordered, O(1) otherwise
    fn order_data_before_commit(&self) -> Result<(), MountError> {
        if !self.behaviour().data.orders_data() { return Ok(()); }
        crate::rootfs::framecache::writeback_dirty(Some(self)).map_err(|_| MountError::BlockIo)
    }

    fn commit_batch_inner(&self) -> Result<bool, MountError> {
        let staged: Vec<StagedBlock> = {
            let s = self.state.lock();
            if !s.batch { return Ok(false); }
            s.shadow.as_ref().into_iter().flatten()
                .map(|(&target_lba, data)| StagedBlock { target_lba, data: data.clone() })
                .collect()
        };
        if !staged.is_empty() {
            let seq = self.commit_metadata_deferred(staged.clone())?;
            self.cache_committed(&staged);
            let mut s = self.state.lock();
            for buffer in s.metadata_buffers.values() {
                buffer.transaction_owner.store(0, core::sync::atomic::Ordering::Release);
            }
            s.block_bitmap_cache.clear();
            s.group_free_order.clear();
            s.group_free_order_index.clear();
            s.group_avg_fragment_order.clear();
            s.group_avg_fragment_index.clear();
            // Retire the committed blocks from the running transaction. They
            // are on the device and `cache_committed` has just published them
            // to the clean buffer cache, so every reader still sees them —
            // but leaving them staged made the NEXT commit collect and write
            // them a second time, and the one after that a third, so a batch
            // of N commits wrote O(N^2) blocks. Only the empty-staged path
            // below used to reset the shadow, which is the path that never
            // runs while a workload is dirtying metadata.
            //
            // Safe to reset here rather than merge: the commit runs inside the
            // transaction gate, which excludes mutators from staging a newer
            // version for the whole of it.
            s.shadow = Some(alloc::collections::BTreeMap::new());
            s.committed_generation = s.running_generation;
            s.running_generation = 0;
            return Ok(seq == 0);
        }
        // Dirty metadata remains shadow-visible until every journal/home write
        // succeeds. Readers therefore see one coherent version throughout
        // writeback; the transaction gate excludes mutators from adding a newer
        // version before this committed generation is retired.
        self.state.lock().shadow = Some(alloc::collections::BTreeMap::new());
        Ok(false)
    }

    /// Keep the running transaction bounded at top-level operation boundaries.
    /// # C: amortized O(1); O(N) on the commit tick
    /// The running batch has filled: ask for a commit, do not perform one.
    ///
    /// The reference wakes its journal thread here. An operation that tips the
    /// batch over is simply the one that happened to be running; making it also
    /// write the journal, flush the ordered data and drive the block layer puts
    /// all of that under whatever it was doing, which is why a `rename` was the
    /// kernel's deepest call path. Flagging and waking hands the work to the
    /// periodic committer, which runs it on its own stack.
    ///
    /// The hard ceiling is the backpressure the reference gets from a full
    /// journal: a batch that keeps growing while the committer has not yet run
    /// must not grow without bound, so a normal caller waits for the periodic
    /// committer. The flusher callback cannot wait on itself and hands control
    /// back to the enclosing pass instead.
    /// # C: O(1), or waits at the ceiling
    pub(crate) fn maybe_commit_batch(&self) -> Result<(), MountError> {
        const BATCH_MAX_BLOCKS: usize = 512;
        /// Growth tolerated between the flag and the committer's next visit.
        const BATCH_CEILING_BLOCKS: usize = BATCH_MAX_BLOCKS * 4;
        if self.creating.load(::core::sync::atomic::Ordering::Acquire)
            || self.committing_batch.load(::core::sync::atomic::Ordering::Acquire)
        { return Ok(()); }
        let blocks = {
            let s = self.state.lock();
            if s.active_handles != 0 { 0 } else { s.shadow.as_ref().map_or(0, |m| m.len()) }
        };
        if blocks >= BATCH_CEILING_BLOCKS {
            self.batch_full.store(true, ::core::sync::atomic::Ordering::Release);
            block::pagecache::wake_flusher();
            // The flusher owns the callback stack and its later commit pass.
            // Waiting here would wait for this same thread to return, so the
            // callback must hand the commit back to its caller.
            if !block::pagecache::in_flusher_context() {
                // SAFETY: this process-context waiter owns no transaction or
                // mount-state lock; the flusher wakes it after the commit.
                let _ = unsafe { sched::live::wait_event_uninterruptible(&self.batch_wait, || {
                    let s = self.state.lock();
                    s.shadow.as_ref().map_or(true, |shadow| shadow.len() < BATCH_CEILING_BLOCKS)
                }) };
            }
        }
        if blocks >= BATCH_MAX_BLOCKS {
            self.batch_full.store(true, ::core::sync::atomic::Ordering::Release);
            block::pagecache::wake_flusher();
        }
        Ok(())
    }

    pub(super) fn batch_frame_commit(&self) {
        let mut s = self.state.lock();
        let id = crate::mount::core::ctx_id();
        let handle = match s.handles.get_mut(&id) { Some(handle) => handle, None => return };
        let frame = match handle.frames.pop() { Some(f) => f, None => return };
        if let Some(parent) = handle.frames.last_mut() {
            for (lba, prev) in frame { parent.entry(lba).or_insert(prev); }
        }
        if handle.frames.is_empty() {
            s.handles.remove(&id);
            debug_assert!(s.active_handles != 0);
            s.active_handles -= 1;
        }
    }

    pub(super) fn batch_frame_rollback(&self) {
        let id = crate::mount::core::ctx_id();
        let frame = {
            let mut s = self.state.lock();
            let Some(handle) = s.handles.get_mut(&id) else { return; };
            let frame = handle.frames.pop().unwrap_or_default();
            if handle.frames.is_empty() {
                s.handles.remove(&id);
                debug_assert!(s.active_handles != 0);
                s.active_handles -= 1;
            }
            frame
        };
        let affected: alloc::vec::Vec<u64> = frame.keys().copied().collect();
        // Keep the same ownership order as allocator updates: the cached GDT
        // image is protected before any metadata-buffer ownership is taken.
        // Reversing this order lets an allocator hold GDT while waiting for a
        // buffer that rollback holds while refreshing GDT.
        // SAFETY: process context, with no spinlock held.
        let _gdt_guard = unsafe { self.gdt_lock.lock() };
        // The shadow restore is itself a metadata write. Keep every block in
        // the frame exclusively owned from before the restore through mirror
        // refresh; otherwise another handle can RMW a block between those
        // two steps and resurrect bytes this rollback just removed.
        let _rollback_guards = self.metadata_write_guards_for_lbas(&affected);
        let mut restored = alloc::vec::Vec::new();
        {
            let mut s = self.state.lock();
            for (lba, prev) in frame {
                let owned = s.metadata_buffers.get(&lba)
                    .is_some_and(|buffer| buffer.transaction_owner.load(core::sync::atomic::Ordering::Acquire) == id);
                if !owned { continue; }
                if let Some(shadow) = s.shadow.as_mut() {
                    match prev {
                        Some(bytes) => { shadow.insert(lba, bytes); }
                        None => { shadow.remove(&lba); }
                    }
                    restored.push(lba);
                }
            }
        }
        // Rebuild only mirrors whose metadata blocks this handle restored.
        // A whole-mount refresh could overwrite a concurrent handle's newer
        // descriptor/counter state once handles share the running batch.
        self.refresh_cached_meta_for(&restored);
    }
}

struct BatchCommitGuard<'a>(&'a Mount);

impl Drop for BatchCommitGuard<'_> {
    fn drop(&mut self) {
        self.0.committing_batch.store(false, ::core::sync::atomic::Ordering::Release);
        self.0.txn_release();
        self.0.batch_wait.wake_all();
    }
}
