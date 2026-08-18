//! Writable, sealing, and read-only admission for one live MD array.

use core::sync::atomic::{AtomicU32, AtomicU8, Ordering};

use block::{BlockError, BlockOp, BlockRequest, KResult};

const READ_WRITE: u8 = 0;
const SEALING: u8 = 1;
const READ_ONLY: u8 = 2;

/// Array-owned mutable lifecycle state. New writes are closed before raw
/// block-cache writeback drains; that drain is the one permitted writer while
/// the state is sealing.
pub(crate) struct State {
    mode: AtomicU8,
    writers: AtomicU32,
    #[cfg(target_os = "oxide-kernel")]
    drain_wait: sched::live::WaitList,
}

/// One modifying request admitted by [`State`]. Dropping it publishes the
/// end of that request to a lifecycle transition waiting in process context.
pub(crate) struct WriteToken<'a> { state: &'a State }

impl State {
    /// Fresh arrays are writable. # C: O(1)
    pub(crate) const fn new() -> Self {
        Self {
            mode: AtomicU8::new(READ_WRITE), writers: AtomicU32::new(0),
            #[cfg(target_os = "oxide-kernel")]
            drain_wait: sched::live::WaitList::new(),
        }
    }

    /// Admit one request. Cache writeback is distinguished from a caller's
    /// new write so the pre-existing dirty cache can drain during sealing.
    /// # C: O(1)
    pub(crate) fn admit(&self, request: &BlockRequest) -> KResult<Option<WriteToken<'_>>> {
        if !modifies(request.op) { return Ok(None); }
        loop {
            let before = self.mode.load(Ordering::Acquire);
            if before == READ_ONLY { return Err(BlockError::Erofs); }
            if before != READ_WRITE && !(before == SEALING && request.writeback) { return Err(BlockError::Ebusy); }
            self.writers.fetch_add(1, Ordering::AcqRel);
            let after = self.mode.load(Ordering::Acquire);
            if after == READ_WRITE || (after == SEALING && request.writeback) {
                return Ok(Some(WriteToken { state: self }));
            }
            self.release_writer();
        }
    }

    /// Close ordinary writes. A repeated read-only transition matches the
    /// array operation's `ENXIO`; a concurrent transition remains busy.
    /// # C: O(1)
    pub(crate) fn begin_read_only(&self) -> KResult<()> {
        match self.mode.compare_exchange(READ_WRITE, SEALING, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => Ok(()),
            Err(READ_ONLY) => Err(BlockError::Enxio),
            Err(_) => Err(BlockError::Ebusy),
        }
    }

    /// Wait until every request admitted before a sealing edge has retired.
    /// # C: O(in-flight writes) # Ctx: process # Sleeps: yes
    pub(crate) fn wait_for_writers(&self) {
        #[cfg(target_os = "oxide-kernel")]
        {
            // SAFETY: the caller is a lifecycle ioctl in process context and
            // holds no MD member, queue, or mapping lock while sleeping.
            unsafe { sched::live::wait_event_uninterruptible(&self.drain_wait,
                || self.writers.load(Ordering::Acquire) == 0); }
        }
        #[cfg(not(target_os = "oxide-kernel"))]
        while self.writers.load(Ordering::Acquire) != 0 { sync::spin_relax::relax(); }
    }

    /// Finish a successful read-only transition. Changing the mode before the
    /// final drain prevents a new writeback request from entering afterward.
    /// # C: O(in-flight writes) # Ctx: process # Sleeps: yes
    pub(crate) fn finish_read_only(&self) -> KResult<()> {
        if self.mode.compare_exchange(SEALING, READ_ONLY, Ordering::AcqRel, Ordering::Acquire).is_err() {
            return Err(BlockError::Ebusy);
        }
        self.wait_for_writers();
        Ok(())
    }

    /// Reopen after a failed transition before returning the operation error.
    /// # C: O(1)
    pub(crate) fn cancel_read_only(&self) { self.mode.store(READ_WRITE, Ordering::Release); }

    /// Return a live read-only array to read-write service. # C: O(1)
    pub(crate) fn restart_read_write(&self) -> KResult<()> {
        self.mode.compare_exchange(READ_ONLY, READ_WRITE, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ()).map_err(|_| BlockError::Ebusy)
    }

    fn release_writer(&self) {
        let last = self.writers.fetch_sub(1, Ordering::AcqRel) == 1;
        #[cfg(target_os = "oxide-kernel")]
        if last { self.drain_wait.wake_all(); }
        #[cfg(not(target_os = "oxide-kernel"))]
        let _ = last;
    }
}

impl Drop for WriteToken<'_> {
    fn drop(&mut self) { self.state.release_writer(); }
}

const fn modifies(op: BlockOp) -> bool {
    matches!(op, BlockOp::Write | BlockOp::WriteZeroes { .. } | BlockOp::Discard)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealing_admits_only_preexisting_cache_writeback() {
        let state = State::new();
        state.begin_read_only().expect("seal");
        let ordinary = BlockRequest::new_write(0, 1, alloc::vec![0; 512]);
        assert!(matches!(state.admit(&ordinary), Err(BlockError::Ebusy)));
        let writeback = ordinary.as_writeback();
        let token = state.admit(&writeback).expect("writeback").expect("token");
        drop(token);
        state.finish_read_only().expect("read-only");
        assert!(matches!(state.admit(&writeback), Err(BlockError::Erofs)));
    }
}
