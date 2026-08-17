//! Charging space and inodes, and giving them back.
//!
//! Nothing here reaches the medium: the records and the identities they belong to
//! were acquired before the operation started (`acquire`), so a charge is a limit
//! decision and two counter updates.

use crate::quota::{self, Ask, Info, Verdict};
use crate::uapi::MAX_QUOTAS;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::volume::Volume;

impl<S: SectorSource> Volume<S> {

    /// What the decision is made against, for one kind. # C: O(1)
    fn ask_for(&self, kind: usize, info: &Info, space: bool, reserve: bool) -> Ask {
        Ask {
            now: self.clock,
            grace: if space { u64::from(info.bgrace) } else { u64::from(info.igrace) },
            // The privileged caller may exceed a hard limit, which is what
            // keeps a full volume repairable. Who that is belongs to the
            // layer that knows who is running, and it already decides it —
            // including the one format where the exemption does not apply.
            exempt: vfs::quota_ignore_hardlimit(self.quota_setup[kind].fmt, info.flags),
            enforced: quota::types::enforced(&self.quota_setup[kind]),
            // A promise is stricter than an allocation: it may not spend a
            // grace period nothing has started yet.
            allocating: !reserve,
        }
    }

    /// Charge `bytes` of space to `ino`'s owners, refusing when it does not
    /// fit.
    ///
    /// Nothing is charged to any kind until EVERY kind has agreed, so a
    /// refusal by the second leaves the first uncharged rather than leaking a
    /// charge for an allocation that never happened.
    /// # C: O(kinds) after the first touch
    pub(crate) fn charge_space(&mut self, ino: u32, bytes: u64) -> Result<(), Errno> {
        self.charge(ino, bytes, 0, false)
    }

    /// Charge one inode to `ino`'s owners. # C: O(kinds)
    pub(crate) fn charge_inode(&mut self, ino: u32) -> Result<(), Errno> {
        self.charge(ino, 0, 1, false)
    }

    /// Promise `bytes` to `ino`'s owners before the block exists.
    ///
    /// The promise, not the charge, is what a limit refuses. An allocation
    /// that then fails for want of room gives the promise back, so nothing is
    /// ever charged for a block that was never made — and a promise still
    /// outstanding is counted against every later request, so the same space
    /// cannot be promised twice.
    /// # C: O(kinds)
    pub(crate) fn reserve_space(&mut self, ino: u32, bytes: u64) -> Result<(), Errno> {
        self.charge(ino, bytes, 0, true)
    }

    /// Take up a promise: the space is occupied now, and the two together do
    /// not move. # C: O(kinds)
    pub(crate) fn claim_space(&mut self, ino: u32, bytes: u64) -> Result<(), Errno> {
        self.move_reserved(ino, bytes, true)
    }

    /// Give back a promise nothing took up. # C: O(kinds)
    pub(crate) fn release_reserved_space(&mut self, ino: u32, bytes: u64) -> Result<(), Errno> {
        self.move_reserved(ino, bytes, false)
    }

    /// The two ends of a promise. Never refuses: both directions are the
    /// consequence of a decision already taken. # C: O(kinds)
    fn move_reserved(&mut self, ino: u32, bytes: u64, claim: bool) -> Result<(), Errno> {
        if !self.quota_active() { return Ok(()); }
        let Some(who) = self.dquot_owners_of(ino) else { return Ok(()) };
        for kind in 0..MAX_QUOTAS {
            if !quota::types::accounted(&self.quota_setup[kind]) { continue; }
            let id = who.id(kind);
            let Some(mut d) = self.dq_held(kind, id) else { continue };
            if claim {
                quota::limit::claim_space(&mut d, bytes);
            } else {
                quota::limit::release_reserved(&mut d, bytes);
            }
            self.dquots.insert((kind, id), d);
            self.dq_dirty.insert((kind, id));
        }
        self.dirty = true;
        Ok(())
    }

    /// The one charging path, for space taken and for space promised.
    ///
    /// Operates on records ALREADY HELD and touches no quota file. The records
    /// were acquired by `dquot_initialize` at the entry of the operation this
    /// charge belongs to, which is what makes that true — and what keeps a
    /// quota-file read out from under a node write. A kind holding no record
    /// for this identity is skipped, not failed: the acquisition already
    /// decided that kind has nothing to charge against.
    /// # C: O(kinds)
    fn charge(&mut self, ino: u32, bytes: u64, inodes: u64, reserve: bool) -> Result<(), Errno> {
        if !self.quota_active() { return Ok(()); }
        let Some(who) = self.dquot_owners_of(ino) else { return Ok(()) };
        let mut verdicts = [(0usize, Verdict::Allow, Verdict::Allow); MAX_QUOTAS];
        let mut n = 0usize;
        for kind in 0..MAX_QUOTAS {
            if !quota::types::accounted(&self.quota_setup[kind]) { continue; }
            let id = who.id(kind);
            let Some(d) = self.dq_held(kind, id) else { continue };
            let Some(info) = self.dq_info_held(kind) else { continue };
            let sv = if bytes > 0 {
                quota::limit::space(&d, bytes, &self.ask_for(kind, &info, true, reserve))
            } else {
                Verdict::Allow
            };
            // An inode is never promised ahead of being made, so the inode
            // axis is always an allocation.
            let iv = if inodes > 0 {
                quota::limit::inodes(&d, inodes, &self.ask_for(kind, &info, false, false))
            } else {
                Verdict::Allow
            };
            if !sv.allowed() || !iv.allowed() { return Err(Errno::Edquot); }
            verdicts[n] = (kind, sv, iv);
            n += 1;
        }
        for &(kind, sv, iv) in verdicts.iter().take(n) {
            let id = who.id(kind);
            let Some(mut d) = self.dq_held(kind, id) else { continue };
            if bytes > 0 && reserve { quota::limit::apply_reserve(&mut d, bytes, sv); }
            if bytes > 0 && !reserve { quota::limit::apply_space(&mut d, bytes, sv); }
            if inodes > 0 { quota::limit::apply_inodes(&mut d, inodes, iv); }
            self.dquots.insert((kind, id), d);
            self.dq_dirty.insert((kind, id));
        }
        self.dirty = true;
        Ok(())
    }

    /// Give space back. Never refuses: a release that failed would leave the
    /// count claiming space nothing occupies. # C: O(kinds)
    pub(crate) fn uncharge_space(&mut self, ino: u32, bytes: u64) -> Result<(), Errno> {
        self.uncharge(ino, bytes, 0)
    }

    /// Give one inode back. # C: O(kinds)
    pub(crate) fn uncharge_inode(&mut self, ino: u32) -> Result<(), Errno> {
        self.uncharge(ino, 0, 1)
    }

    /// # C: O(kinds)
    fn uncharge(&mut self, ino: u32, bytes: u64, inodes: u64) -> Result<(), Errno> {
        if !self.quota_active() { return Ok(()); }
        let Some(who) = self.dquot_owners_of(ino) else { return Ok(()) };
        for kind in 0..MAX_QUOTAS {
            if !quota::types::accounted(&self.quota_setup[kind]) { continue; }
            let id = who.id(kind);
            let Some(mut d) = self.dq_held(kind, id) else { continue };
            if bytes > 0 { quota::limit::free_space(&mut d, bytes); }
            if inodes > 0 { quota::limit::free_inodes(&mut d, inodes); }
            self.dquots.insert((kind, id), d);
            self.dq_dirty.insert((kind, id));
        }
        self.dirty = true;
        Ok(())
    }
}
