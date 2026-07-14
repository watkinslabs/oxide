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
        self.txn_acquire();
        let result = self.commit_batch_inner();
        self.txn_release();
        result
    }

    fn commit_batch_inner(&self) -> Result<(), MountError> {
        let staged: Vec<StagedBlock> = {
            let s = self.state.lock();
            if !s.batch { return Ok(()); }
            s.shadow.as_ref().into_iter().flatten()
                .map(|(&target_lba, data)| StagedBlock { target_lba, data: data.clone() })
                .collect()
        };
        if !staged.is_empty() { let _ = self.commit_metadata(staged)?; }
        // Dirty metadata remains shadow-visible until every journal/home write
        // succeeds. Readers therefore see one coherent version throughout
        // writeback; the transaction gate excludes mutators from adding a newer
        // version before this committed generation is retired.
        self.state.lock().shadow = Some(alloc::collections::BTreeMap::new());
        Ok(())
    }

    /// Keep the running transaction bounded at top-level operation boundaries.
    /// # C: amortized O(1); O(N) on the commit tick
    pub(crate) fn maybe_commit_batch(&self) -> Result<(), MountError> {
        const BATCH_MAX_BLOCKS: usize = 512;
        if self.creating.load(::core::sync::atomic::Ordering::Acquire) { return Ok(()); }
        let over = {
            let s = self.state.lock();
            s.undo.is_empty() && s.shadow.as_ref().map_or(0, |m| m.len()) >= BATCH_MAX_BLOCKS
        };
        if over { self.commit_batch()?; }
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
