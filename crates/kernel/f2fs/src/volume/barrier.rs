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
    pub(crate) fn flush_members(&self, mask: u64) -> Result<(), Errno> {
        for i in (0..64usize).filter(|i| mask & (1u64 << i) != 0) {
            self.barrier_member(i)?;
        }
        Ok(())
    }
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

    /// Make ONE FILE's writes durable on the members they actually landed on.
    ///
    /// What `fsync` reaches when it took the chain path. The chain is a run of
    /// node blocks a later mount goes looking for; a device is free to hold them
    /// in its cache and to reorder them, so without this the call returns having
    /// promised durability for bytes a power cut still loses.
    ///
    /// A file whose blocks all sit on one member of a six-member volume owes one
    /// barrier, not six, and a barrier is a whole-cache operation rather than a
    /// rounding error. Which members those are is the decision's
    /// (`devices::barrier::fsync_flush_targets`), and it answers "every member"
    /// for a volume of one and for a file nothing is recorded against — a caller
    /// that cannot tell "nothing written" from "not recorded" must not skip a
    /// barrier it may owe.
    /// # C: one barrier per member the file's blocks landed on
    pub(crate) fn issue_flush_for(&self, ino: u32) -> Result<(), Errno> {
        let targets = barrier::fsync_flush_targets(
            self.source.members(), self.dirty_ino_devs.mask(ino));
        for i in targets.iter() { self.barrier_member(i)?; }
        Ok(())
    }

    /// The same, on the ladder an `fsync` decides it by.
    ///
    /// `atomic` says the caller is committing an atomic write, whose node chain
    /// is ordered by its own construction; see `devices::barrier`.
    ///
    /// The file's in-place record is retired only when a barrier was actually
    /// issued. A mount that skipped one has not made those bytes durable, and
    /// forgetting the debt would mean the next `fsync` — which may be the one
    /// that could have paid it — no longer knows it is owed.
    /// # C: one barrier per member, or none
    pub(crate) fn fsync_barrier(&mut self, ino: u32, atomic: bool) -> Result<(), Errno> {
        if !barrier::fsync_needs_flush(self.opts.barrier, self.opts.fsync_mode, atomic) {
            return Ok(());
        }
        let targets = barrier::fsync_flush_targets(
            self.source.members(), self.dirty_ino_devs.mask(ino));
        if self.deferred_flush.is_some() {
            self.deferred_flush = Some((ino, targets_mask(targets)));
            return Ok(())
        }
        self.issue_flush_for(ino)?;
        self.update_writes.borrow_mut().fenced(ino);
        // The members this file's blocks were on have emptied their caches, so
        // it owes nothing until it is written to again. Dropped only after the
        // barriers succeeded: an entry cleared on a failed barrier would let the
        // next `fsync` of the same file skip a member still holding its bytes.
        self.dirty_ino_devs.forget(ino);
        Ok(())
    }

    /// Note that a page of `ino` was rewritten where it lay.
    ///
    /// See the field: such a write leaves the file's recorded shape untouched,
    /// so nothing else in this filesystem can afterwards tell that the device
    /// is holding bytes somebody was promised were durable.
    /// # C: O(log files)
    pub(crate) fn note_inplace_write(&self, ino: u32) {
        self.update_writes.borrow_mut().record(ino);
    }

    /// How many files have a rewrite in place that no barrier has reached.
    ///
    /// The reference keeps this as a list of inode numbers on the mount, for
    /// the same reason and with the same lifetime: raised where a page is
    /// rewritten where it lay, dropped by the barrier that makes it durable.
    /// # C: O(1)
    pub(crate) fn unfenced_inplace_files(&self) -> usize { self.update_writes.borrow().len() }

    /// Whether `ino` has a rewrite in place that no barrier has reached.
    /// # C: O(log files)
    pub(crate) fn owes_inplace_barrier(&self, ino: u32) -> bool {
        self.update_writes.borrow().owed(ino)
    }

    /// Every file's rewrite is on the medium, because something fenced them
    /// all at once.
    ///
    /// A checkpoint does exactly that: its commit block is written under a
    /// pre-flush, so every write this mount made — the rewrites in place among
    /// them — is on the medium before the block lands. Called only when that
    /// promise was actually made; a mount that asked for no barriers wrote the
    /// commit block plain and fenced nothing, so it has retired no debt.
    /// # C: O(files owed)
    pub(crate) fn note_all_fenced(&mut self) {
        self.update_writes.borrow_mut().fenced_all();
        self.dirty_ino_devs.clear();
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

    /// Note that a write of `ino` landed on the member holding `addr`.
    ///
    /// Beside the volume-wide mark, not instead of it: the two answer different
    /// questions — which members a CHECKPOINT depends on, and which members one
    /// FILE's `fsync` must fence — and a checkpoint's answer cannot be derived
    /// from one file's.
    ///
    /// Called from the writers that know whose block it is, which is every
    /// writer into a log. Metadata writes have no owning file and are covered by
    /// the volume-wide mark alone, exactly as the reference covers them.
    /// # C: O(log files), plus O(devices)
    pub(crate) fn note_file_write(&mut self, ino: u32, addr: u32) {
        self.note_device_write(addr);
        if !self.devs.is_multi() { return; }
        let (member, _) = self.devs.target(addr);
        self.dirty_ino_devs.mark(ino, member);
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

    pub(crate) fn take_deferred_flush(&mut self) -> Option<(u32, u64)> {
        self.deferred_flush.take()
    }

    pub(crate) fn complete_deferred_flush(&mut self, ino: u32) {
        self.update_writes.borrow_mut().fenced(ino);
        self.dirty_ino_devs.forget(ino);
    }
}

fn targets_mask(targets: barrier::Members) -> u64 {
    targets.iter().fold(0, |m, i| m | (1u64 << i))
}
