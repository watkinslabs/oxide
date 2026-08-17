//! Asking the members to empty their write caches, and what a refusal costs.
//!
//! The decisions are in `devices::barrier`, where they can be checked without a
//! device. What is here is the part that needs one: issuing the barrier,
//! charging it, retrying a member that refused, and stopping the checkpoint when
//! a member keeps refusing — because a pack written over a member whose cache
//! never reached the medium records a state the volume does not hold.

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::devices::barrier::{self, FLUSH_RETRIES};

use super::Volume;

impl<S: SectorSource> Volume<S> {
    /// Empty one member's write cache, and charge it.
    ///
    /// A medium with no volatile cache is asked for nothing, and that is not a
    /// swallowed request: everything written to it is already on the medium, so
    /// the barrier has no work and the promise holds without it. The decision is
    /// the block layer's own — the same one that turns a durability promise into
    /// commands — rather than a test written out here, so a medium cannot be
    /// fenced by one path and not by another.
    ///
    /// The charge is a COUNT and not a byte total: a barrier carries no data, so
    /// the bytes are zero by construction rather than by an omission. Charged
    /// only when a command actually went down, because a figure that counted
    /// barriers nobody issued would report cost that was never paid.
    /// # C: one device barrier
    fn barrier_member(&self, member: usize) -> Result<(), Errno> {
        let seq = block::durability::sequence(
            self.source.write_cache(), false, block::durability::PREFLUSH, false);
        if seq.is_noop() { return Ok(()); }
        self.source.flush_device(member)?;
        self.io_account(crate::stats::iostat::Io::FsFlush, 0, false);
        Ok(())
    }

    /// Make everything this mount has written to the medium durable ON it.
    ///
    /// What `fsync` reaches when it took the chain path. The chain is a run of
    /// node blocks a later mount goes looking for; a device is free to hold them
    /// in its cache and to reorder them, so without this the call returns having
    /// promised durability for bytes a power cut still loses.
    ///
    /// Every member is asked, not only the dirty ones: this is not the
    /// checkpoint's pass, and the file whose blocks are being fenced may sit on
    /// any of them.
    /// # C: one barrier per member
    pub(crate) fn issue_flush(&self) -> Result<(), Errno> {
        for i in 0..self.source.members() { self.barrier_member(i)?; }
        Ok(())
    }

    /// The same, on the ladder an `fsync` decides it by.
    ///
    /// `atomic` says the caller is committing an atomic write, whose node chain
    /// is ordered by its own construction; see `devices::barrier`.
    /// # C: one barrier per member, or none
    pub(crate) fn fsync_barrier(&self, atomic: bool) -> Result<(), Errno> {
        if !barrier::fsync_needs_flush(self.opts.barrier, self.opts.fsync_mode, atomic) {
            return Ok(());
        }
        self.issue_flush()
    }

    /// Empty the caches of every member this checkpoint's pack will REFER TO,
    /// leaving the member that carries the pack to the commit block.
    ///
    /// Retried rather than escalated on: a barrier is a whole-cache operation
    /// and a transient refusal is worth asking again for. A member that keeps
    /// refusing is not survivable — the pack about to be written names blocks on
    /// it — so this filesystem stops checkpointing rather than record a state the
    /// medium does not hold, which is the reference's own answer.
    ///
    /// A member's bit is lowered only after ITS barrier succeeded. Clearing the
    /// whole set at the end would let a later checkpoint commit over a member
    /// whose barrier failed, with nothing left to say so.
    /// # C: one barrier per dirty member
    pub(crate) fn flush_device_cache(&mut self) -> Result<(), Errno> {
        let targets = barrier::checkpoint_flush_targets(
            self.opts.barrier, self.source.members(), self.dirty_devs.get().mask());
        for i in targets.iter() {
            let mut outcome = Ok(());
            for _ in 0..FLUSH_RETRIES {
                outcome = self.barrier_member(i);
                if outcome.is_ok() { break; }
            }
            match outcome {
                Ok(()) => {
                    let mut d = self.dirty_devs.get();
                    d.clear(i);
                    self.dirty_devs.set(d);
                }
                Err(e) => {
                    self.stop_checkpoint(crate::errrec::StopReason::FlushFail, false);
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    /// Note that a write landed on the member holding `addr`.
    ///
    /// Called from the one place every block write of this filesystem goes
    /// through, so a member cannot become dirty without the checkpoint learning
    /// of it. A volume of one member records nothing: its only member carries
    /// the pack, and the pack's commit block is what fences it.
    /// # C: O(devices)
    pub(crate) fn note_device_write(&self, addr: u32) {
        if !self.devs.is_multi() { return; }
        let (member, _) = self.devs.target(addr);
        let mut d = self.dirty_devs.get();
        d.mark(member);
        self.dirty_devs.set(d);
    }
}
