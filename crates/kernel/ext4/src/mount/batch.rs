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
        self.commit_batch_for(None).map(|_| ())
    }

    pub(crate) fn commit_batch_for(&self, inode: Option<(u32, bool)>) -> Result<bool, MountError> {
        if self.committing_batch.swap(true, core::sync::atomic::Ordering::AcqRel) {
            // A writeback operation can reach this method through a nested
            // journaled write. The outer commit owns the ordering/commit
            // sequence; starting another one here would recurse through the
            // block device and consume the task stack.
            return Ok(false);
        }
        let _commit_guard = BatchCommitGuard(&self.committing_batch);
        #[cfg(feature = "debug-fsync-latency")]
        let started_ns = crate::fsync_latency::now_ns();
        self.order_data_before_commit(inode.map(|(ino, _)| ino))?;
        #[cfg(feature = "debug-fsync-latency")]
        crate::fsync_latency::report(b"batch-order", started_ns, 0);
        #[cfg(feature = "debug-fsync-latency")]
        let gate_ns = crate::fsync_latency::now_ns();
        self.txn_acquire();
        #[cfg(feature = "debug-fsync-latency")]
        crate::fsync_latency::report(b"batch-gate", gate_ns, 0);
        let needed = inode.map_or(true, |(ino, datasync)| self.inode_sync_needed(ino, datasync));
        #[cfg(feature = "debug-fsync-latency")]
        let staged_blocks = self.state.lock().shadow.as_ref().map_or(0, |s| s.len() as u64);
        #[cfg(feature = "debug-fsync-latency")]
        let commit_ns = crate::fsync_latency::now_ns();
        let result = if needed { self.commit_batch_inner() } else { Ok(false) };
        #[cfg(feature = "debug-fsync-latency")]
        crate::fsync_latency::report(b"batch-commit", commit_ns, staged_blocks);
        self.txn_release();
        let direct = match result {
            Ok(direct) => direct,
            Err(err) => {
                self.batch_wait.wake_all();
                return Err(err);
            }
        };
        self.batch_wait.wake_all();
        let generation = self.state.lock().committed_generation;
        let barrier_needed = direct && self.behaviour().barrier && {
            let s = self.state.lock();
            generation > s.barrier_generation
        };
        if !needed || !barrier_needed { return Ok(false); }
        self.dev.flush().map_err(|_| MountError::BlockIo)?;
        self.mark_generation_barriered(generation);
        Ok(true)
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
    /// Runs BEFORE the transaction gate is taken: the writeback stages through
    /// that same gate, and the commit it precedes must see what it produced.
    /// # C: O(N_dirty) when ordered, O(1) otherwise
    fn order_data_before_commit(&self, inode: Option<u32>) -> Result<(), MountError> {
        if !self.behaviour().data.orders_data() { return Ok(()); }
        let result = match inode {
            Some(ino) => crate::rootfs::framecache::writeback_inode(self, ino),
            None => crate::rootfs::framecache::writeback_dirty(Some(self)),
        };
        result.map_err(|_| MountError::BlockIo)
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
            let seq = self.commit_metadata(staged.clone())?;
            self.cache_committed(&staged);
            let mut s = self.state.lock();
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
            if s.undo.is_empty() { s.shadow.as_ref().map_or(0, |m| m.len()) } else { 0 }
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
        let frame = match s.undo.pop() { Some(f) => f, None => return };
        if let Some(parent) = s.undo.last_mut() {
            for (lba, prev) in frame { parent.entry(lba).or_insert(prev); }
        }
    }

    pub(super) fn batch_frame_rollback(&self) {
        let frame = { self.state.lock().undo.pop().unwrap_or_default() };
        {
            let mut s = self.state.lock();
            if let Some(shadow) = s.shadow.as_mut() {
                for (lba, prev) in frame {
                    match prev {
                        Some(bytes) => { shadow.insert(lba, bytes); }
                        None => { shadow.remove(&lba); }
                    }
                }
            }
        }
        self.refresh_cached_meta();
    }
}

struct BatchCommitGuard<'a>(&'a ::core::sync::atomic::AtomicBool);

impl Drop for BatchCommitGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, ::core::sync::atomic::Ordering::Release);
    }
}
