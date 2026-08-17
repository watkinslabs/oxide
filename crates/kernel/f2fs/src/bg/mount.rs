//! What the mount calls: start, stop, balance, and parking a checkpoint's
//! freed runs.
//!
//! This is the whole surface the rest of the filesystem uses. Everything else
//! under `bg` is reached from here or from the thread loops, so a caller never
//! has to know whether a thread is running — the same call does the work
//! inline when there is nobody to hand it to.

use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::KResult;

use crate::mount::{errno_to_vfs, F2fs};
use crate::volume::discard::Range;

use super::round;
use super::run;

impl F2fs {
    /// Start the background threads this mount's options ask for.
    ///
    /// Called once the mount is published, not during it: a thread that woke
    /// before the mount was reachable would find a filesystem nothing could
    /// hand it work through.
    ///
    /// Both threads start even when cleaning is off. The discard thread is
    /// not the cleaner — it announces space the volume has already freed —
    /// and the cleaner stays parked so a remount can turn it on without a
    /// mount cycle, which is what upstream's remount path does.
    /// # C: O(1)
    pub fn start_background(self: &Arc<Self>) { run::start(self); }

    /// Stop the background threads and hand the device everything still
    /// parked.
    ///
    /// The order is the contract. Threads first, so nothing is issuing while
    /// the list is drained, and the drain second, because the checkpoint the
    /// unmount writes says the volume is trimmed.
    /// # C: O(one pass of each thread + runs waiting)
    pub fn stop_background(&self) {
        run::stop(self);
        round::drain_discards(self);
    }

    /// Park the runs a checkpoint has just made safe to announce.
    ///
    /// A mount with a discard thread parks them and wakes it; one without —
    /// hosted, or read-only, or before the threads start — announces them
    /// itself, because the alternative is a list that grows and is never
    /// issued.
    /// # C: O(runs), plus the announce when there is no thread
    pub(crate) fn queue_discards(&self, runs: Vec<Range>) {
        if runs.is_empty() { return; }
        if !self.bg().discard_running.load(core::sync::atomic::Ordering::Acquire) {
            self.announce_free(&runs);
            return;
        }
        self.bg().dcc.lock().extend(runs);
        self.bg().wake_discard();
    }

    /// Keep the volume able to allocate, after an operation that used space.
    ///
    /// `need` says whether the operation changed the node tree; one that only
    /// rewrote bytes already allocated has not grown the caches a checkpoint
    /// retires.
    ///
    /// Mounted `gc_merge`, the cleaning half is handed to the cleaner thread
    /// and this caller waits on it rather than cleaning itself. That is not an
    /// optimisation: with several writers short of space at once, each one
    /// cleaning would have them all moving blocks out of each other's victims.
    /// # C: O(main segments), plus a clean or a checkpoint when one is due
    pub fn balance(self: &Arc<Self>, need: bool) -> KResult<()> {
        let now = { self.volume_now().now_secs() };
        self.bg().note_activity(now);
        let enough = {
            let mut v = self.volume_now();
            if !v.writable() { return Ok(()); }
            v.load_segments().map_err(errno_to_vfs)?;
            v.has_enough_free_secs(0, 0)
        };
        if !enough && self.options().gc_merge && run::delegate_gc(self) { return Ok(()); }
        self.volume_now().balance_fs(need).map_err(errno_to_vfs)
    }

    /// Whether this mount asked for its checkpoints to be merged. # C: O(1)
    pub fn merges_checkpoints(&self) -> bool { self.options().checkpoint_merge }

    /// Make everything durable, through the merge thread where the mount asked
    /// for one.
    ///
    /// N callers arriving at once do not need N checkpoints: a checkpoint is
    /// WHOLE, so one write makes all of their promises true. The exemptions are
    /// the decision's own (`checkpoint::merge`), and a caller the thread cannot
    /// serve keeps the write rather than waiting for one that will not come.
    /// # C: O(a checkpoint), or O(1) plus the wait
    pub fn checkpoint_merged(self: &Arc<Self>, waiting: bool) -> KResult<()> {
        let r = crate::checkpoint::merge::Request {
            merge: self.merges_checkpoints(),
            thread_running: self.bg()
                .ckpt_running.load(core::sync::atomic::Ordering::Acquire),
            umounting: self.bg().stopping(),
            waiting,
        };
        self.checkpoint_via(&r, || run::delegate_checkpoint(self))
    }

    /// The dispatch itself, with the handing-over lifted out.
    ///
    /// Separate so it can be driven where there is no thread to hand anything
    /// to: a build that decided perfectly and then never asked, or asked and
    /// then wrote its own anyway, is exactly the shape of an unwired feature,
    /// and neither is visible through the mount's own entry point on a hosted
    /// build.
    /// # C: O(a checkpoint), or O(1) plus the delegate
    pub(crate) fn checkpoint_via(&self, r: &crate::checkpoint::merge::Request,
                                 delegate: impl FnOnce() -> Option<KResult<()>>) -> KResult<()> {
        if crate::checkpoint::merge::takes_the_thread(r) {
            if let Some(out) = delegate() { return out; }
        }
        self.checkpoint_now()
    }

    /// Ask the cleaner for a pass now, whatever its sleep had been.
    /// # C: O(1)
    pub fn wake_gc(&self) { self.bg().wake_gc(); }

    /// Ask the discard thread for a round now. # C: O(1)
    pub fn wake_discard(&self) { self.bg().wake_discard(); }
}

/// The last thing a mount does, whether or not the unmount path said so.
///
/// The explicit stop belongs in `put_super`, before the final checkpoint, so
/// nothing is cleaning while it is written. This is the backstop for every
/// other way a mount can go away — a failed mount, a dropped reference, a
/// caller that never had a superblock — and without it those paths would leave
/// two threads holding a weak reference to a filesystem that no longer exists
/// and a list of freed runs the device is never told about.
impl Drop for F2fs {
    /// # C: O(one pass of each thread + runs waiting)
    fn drop(&mut self) {
        run::stop(self);
        round::drain_discards(self);
        // After both threads have stopped, so nothing is adding entries to the
        // caches this empties, and here rather than in `put_super` for the same
        // reason the stop has a backstop: a failed mount and a dropped
        // reference must also come out of the reclaim list, or a later pass
        // walks a weak reference to a filesystem that no longer exists.
        crate::shrink::leave(self);
    }
}
