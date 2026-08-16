//! Reconfiguring a mounted volume from a new option line.
//!
//! A remount is not a fresh mount with the old one's state kept. The line is
//! read on top of the volume's OWN defaults, so an option the new line stops
//! naming goes back to its default rather than persisting invisibly — which is
//! the difference between `mount -o remount,background_gc=off` followed by
//! `mount -o remount` leaving the cleaner off forever, and it coming back on.
//!
//! The threads are the reason this cannot be a pure option swap. Two of them
//! exist for the length of the mount and read a knob every round, so turning
//! cleaning off is a knob write; but a mount going read-only has to STOP them,
//! because a cleaner that runs on a read-only mount moves blocks nobody may
//! write, and one coming back read-write has to start them again. A remount
//! that changed the options and left the threads alone is the gap this closes:
//! the option would be reported, and nothing would act on it.
//!
//! Order is the contract, and it is the reference's. The options are checked
//! BEFORE anything is changed, so a line that is refused leaves the mount
//! exactly as it was; the threads are moved after, because a thread started
//! against options that were then rejected is a thread running the wrong
//! policy.

use alloc::sync::Arc;

use vfs::KResult;

use crate::consistency::{resolve_remount, Sbi};
use crate::features::Access;
use crate::opts::facts::Facts;
use crate::opts::{BackgroundGc, Options};

use super::{errno_to_vfs, F2fs};

impl F2fs {
    /// The state the consistency pass checks a new line against. # C: O(1)
    pub fn remount_state(&self, want_ro: bool) -> Sbi {
        let v = self.volume.lock();
        let sb = v.super_block();
        Sbi {
            facts: Facts {
                feature: sb.feature,
                segment_count_main: sb.segment_count_main,
                hw_support_discard: self.supports_discard(),
                // A mount asked to go read-only IS read-only for the purpose of
                // every clause: checking the line against the state it is
                // moving to is the only way `norecovery` and `flush_merge` get
                // the right answer.
                mount_ro: want_ro || v.access() == Access::ReadOnly,
            },
            cur: *v.options(),
            remount: true,
            quota_on: v.quota_active(),
            casefold_loadable: v.casefold().is_some() || !crate::features::has_casefold(sb.feature),
        }
    }

    /// Reconfigure this mount from `data`.
    ///
    /// Nothing changes unless everything is accepted. A refused line leaves the
    /// options, the writability and the threads exactly as they were, which is
    /// what lets a caller retry a corrected line against a mount that is still
    /// serving.
    /// # C: O(len(data)), plus starting or stopping the threads
    pub fn remount(self: &Arc<Self>, data: &str, want_ro: bool) -> KResult<()> {
        let sbi = self.remount_state(want_ro);
        let (opts, _) = resolve_remount(&sbi, data).map_err(errno_to_vfs)?;
        // Going read-only is a state change a reader must see, so what the
        // mount has done is pushed out BEFORE it stops being able to push.
        //
        // Whether it IS going read-only is asked of the mount, not of the
        // facts the line was checked against: those already fold the request
        // in (`mount_ro` is `want_ro ||` the volume's own answer), so testing
        // them here asked "going read-only and not going read-only" and the
        // flush never ran.
        let going_ro = want_ro && self.volume.lock().writable();
        if going_ro {
            // The flush is taken as if the volume were going away, and says so
            // for its duration: a reader watching the status word sees the
            // same mark an unmount raises, which is what tells it the writes
            // in flight are the last ones.
            {
                let mut v = self.volume.lock();
                v.set_closing(true);
                // Forced, as the reference forces it: the mount is about to
                // stop being able to write, so the flush must happen even if
                // nothing has changed since the last one — the checkpoint it
                // leaves is what says the volume was put down cleanly.
                v.mark_dirty();
            }
            let out = self.checkpoint();
            self.volume.lock().set_closing(false);
            out?;
        }
        {
            let mut v = self.volume.lock();
            let permitted = v.access() == Access::ReadWrite;
            v.adopt_options(opts);
            v.set_writable(!want_ro && permitted);
        }
        self.retune_background(&opts);
        Ok(())
    }

    /// Move the threads to what the new options ask for.
    ///
    /// Two shapes, not one. The cleaner's eagerness is a KNOB the running
    /// thread reads every round, so turning it off does not stop the thread —
    /// which is what lets a later remount turn it back on without a mount
    /// cycle. Writability is not a knob: a read-only mount must have no
    /// cleaner at all, because the pass it would make writes.
    /// # C: O(one pass of each thread) when the threads move
    pub(crate) fn retune_background(self: &Arc<Self>, opts: &Options) {
        *self.bg().bggc.lock() = opts.background_gc;
        // A cleaner asked for now rather than at its next ordinary wake: a
        // remount that turned it on and left it asleep for five minutes has not
        // done what the caller asked.
        if opts.background_gc != BackgroundGc::Off { self.bg().wake_gc(); }
        if !self.is_writable() {
            // Raised here rather than left to the stop machinery: it is the
            // mount's statement that no pass may run, and a build that spawns
            // no threads must still record the decision.
            self.bg().halt();
            self.stop_background();
            return;
        }
        // Cleared before the start, or the threads would see the unmount flag
        // an earlier read-only remount raised and wind straight back up.
        self.bg().resume();
        self.start_background();
    }
}

#[cfg(test)]
#[path = "../tests/remount.rs"]
mod tests;
