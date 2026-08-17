//! Charging allocations to the identities that own them.
//!
//! The decode, the tree walk and the limit decision are pure and live under
//! `quota`. This is the half that makes them mean something: every block a
//! file gains and every inode a directory gains is charged here, and a mount
//! that enforces limits refuses the allocation rather than recording an
//! overdraft after the fact.
//!
//! Records are CACHED, not read per allocation. A quota file is an ordinary
//! inode, so reading one costs a file read; doing that per block would make
//! every write O(quota file). The cache is written back at checkpoint, which
//! is also when the rest of the volume's counts become durable — so a crash
//! loses the same window of accounting it loses of everything else.
//!
//! A quota file's OWN blocks are never charged. Charging the growth of the
//! file that records an identity's usage to that identity is a loop that does
//! not terminate.

use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::quota::{self, Ask, Dqblk, Info, Verdict};
use crate::uapi::{BLKSIZE, I_SIZE, MAX_QUOTAS};

use super::dnode::put64;
use super::Volume;

/// The three kinds, in the order the superblock lists their inodes.
pub const USRQUOTA: usize = 0;
pub const GRPQUOTA: usize = 1;
pub const PRJQUOTA: usize = 2;

/// The identity an allocation is charged to, one id per kind.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Owners([u32; MAX_QUOTAS]);

impl Owners {
    /// # C: O(1)
    pub fn new(uid: u32, gid: u32, projid: u32) -> Self { Owners([uid, gid, projid]) }

    /// # C: O(1)
    pub fn id(&self, kind: usize) -> u32 { self.0[kind] }
}

/// Whether a record has nothing left to say: no limits, and nothing in use.
///
/// Such a record is removed rather than kept, the way the reference drops a
/// record whose last reference goes while it holds nothing. Keeping it would
/// make a quota file grow once per identity that ever allocated a byte and
/// never shrink.
/// # C: O(1)
fn unused_record(d: &Dqblk) -> bool {
    d.bhardlimit == 0
        && d.bsoftlimit == 0
        && d.ihardlimit == 0
        && d.isoftlimit == 0
        && d.curspace == 0
        && d.curinodes == 0
}

impl<S: SectorSource> Volume<S> {
    /// Who an inode's allocations are charged to. # C: O(1 block)
    pub(crate) fn owners_of(&self, ino: u32) -> Result<Owners, Errno> {
        let i = self.read_inode(ino)?;
        Ok(Owners::new(i.uid, i.gid, i.projid))
    }

    /// Whether `ino` is one of the volume's own quota files. # C: O(kinds)
    pub(crate) fn is_quota_file(&self, ino: u32) -> bool {
        if quota::types::is_quota_inode(&self.sb.qf_ino, self.sb.feature, ino) { return true; }
        // A file the MOUNT named is as much a quota file as one the
        // superblock names, and the reason not to charge it is the same:
        // charging the growth of the file that records an identity's usage to
        // that identity does not terminate.
        ino != 0 && self.quota_setup.iter().any(|s| s.named && s.ino == ino)
    }

    /// Resolve every quota file the MOUNT named to the inode holding it.
    ///
    /// Those files are ordinary entries in the volume's root, so this cannot
    /// happen until there is a volume to look them up in. A name that does
    /// not resolve leaves its kind unaccounted rather than failing the mount:
    /// the reference logs and carries on, and a volume that refuses to mount
    /// over a missing quota file leaves nobody able to put one there.
    /// # C: O(kinds * depth)
    #[inline(never)]
    pub(crate) fn open_named_quota_files(&mut self) {
        for kind in 0..MAX_QUOTAS {
            if !self.quota_setup[kind].named { continue; }
            let Some(name) = self.opts.jquota.names[kind] else {
                self.quota_setup[kind] = quota::Setup::OFF;
                continue;
            };
            let found = self
                .read_inode(self.sb.root_ino)
                .and_then(|root| self.lookup(&root, self.sb.root_ino, name.as_bytes()));
            match found {
                Ok(e) => self.quota_setup[kind].ino = e.ino,
                Err(_) => self.quota_setup[kind] = quota::Setup::OFF,
            }
        }
    }

    /// The parsed header of one kind's file. # C: O(file bytes) once
    fn dq_info(&mut self, kind: usize) -> Result<Info, Errno> {
        if let Some(i) = self.quota_info[kind].clone() { return Ok(i); }
        let ino = self.quota_setup[kind].ino;
        if ino == 0 { return Err(Errno::Enodata); }
        let file = self.read_quota_file(ino)?;
        let info = quota::info::parse(&file, kind).map_err(|_| Errno::Eio)?;
        quota::info::check(&info, file.len()).map_err(|_| Errno::Eio)?;
        self.quota_info[kind] = Some(info.clone());
        Ok(info)
    }

    /// One kind's whole file. # C: O(file bytes)
    fn read_quota_file(&self, ino: u32) -> Result<Vec<u8>, Errno> {
        let inode = self.read_inode(ino)?;
        self.read_whole(&inode, ino)
    }

    /// The record for one identity, loaded once and then cached.
    ///
    /// An identity the tree has no slot for reads as an empty record rather
    /// than an error: it has simply never allocated anything, and refusing
    /// would make the first allocation by every new user fail.
    /// # C: O(file bytes) on the first touch, O(log ids) after
    pub(crate) fn dq_get(&mut self, kind: usize, id: u32) -> Result<Dqblk, Errno> {
        // Bringing an identity's record in is what "initialise the quotas of
        // this inode" means here, so it is where a mount asking for that step
        // to fail gets its failure.
        if crate::fault::time_to_inject(&self.fault, crate::fault::Fault::DquotInit) {
            return Err(Errno::Esrch);
        }
        if let Some(d) = self.dquots.get(&(kind, id)) { return Ok(d.clone()); }
        let info = self.dq_info(kind)?;
        let file = self.read_quota_file(self.quota_setup[kind].ino)?;
        let d = quota::tree::read(&file, &info, id).map_err(|_| Errno::Eio)?.unwrap_or_default();
        self.dquots.insert((kind, id), d.clone());
        Ok(d)
    }

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
        if !self.quota_active() || self.is_quota_file(ino) { return Ok(()); }
        let who = self.owners_of(ino)?;
        for kind in 0..MAX_QUOTAS {
            if !quota::types::accounted(&self.quota_setup[kind]) { continue; }
            let id = who.id(kind);
            let Ok(mut d) = self.dq_get(kind, id) else { continue };
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
    /// # C: O(kinds)
    fn charge(&mut self, ino: u32, bytes: u64, inodes: u64, reserve: bool) -> Result<(), Errno> {
        if !self.quota_active() || self.is_quota_file(ino) { return Ok(()); }
        let who = self.owners_of(ino)?;
        let mut verdicts = [(0usize, Verdict::Allow, Verdict::Allow); MAX_QUOTAS];
        let mut n = 0usize;
        for kind in 0..MAX_QUOTAS {
            if !quota::types::accounted(&self.quota_setup[kind]) { continue; }
            let id = who.id(kind);
            let d = self.dq_get(kind, id)?;
            let info = self.dq_info(kind)?;
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
            let mut d = self.dq_get(kind, id)?;
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
        if !self.quota_active() || self.is_quota_file(ino) { return Ok(()); }
        let who = self.owners_of(ino)?;
        for kind in 0..MAX_QUOTAS {
            if !quota::types::accounted(&self.quota_setup[kind]) { continue; }
            let id = who.id(kind);
            let Ok(mut d) = self.dq_get(kind, id) else { continue };
            if bytes > 0 { quota::limit::free_space(&mut d, bytes); }
            if inodes > 0 { quota::limit::free_inodes(&mut d, inodes); }
            self.dquots.insert((kind, id), d);
            self.dq_dirty.insert((kind, id));
        }
        self.dirty = true;
        Ok(())
    }

    /// Whether any kind is accounted at all. # C: O(kinds)
    pub(crate) fn quota_active(&self) -> bool {
        self.quota_setup.iter().any(quota::types::accounted)
    }

    /// What each kind resolved to on this mount. # C: O(1)
    pub fn quota_setup(&self) -> &[quota::Setup] { &self.quota_setup }

    /// A record as this mount currently has it. # C: O(file bytes) once
    pub fn quota_record(&mut self, kind: usize, id: u32) -> Result<Dqblk, Errno> {
        self.dq_get(kind, id)
    }

    /// Replace one identity's record, for a caller setting limits rather than
    /// allocating.
    ///
    /// The cache is the truth this mount charges against, so a record changed
    /// here takes effect on the very next allocation; the medium catches up at
    /// the next checkpoint with everything else the counts describe. Writing
    /// the file directly instead would leave the cache still enforcing the old
    /// limits until something evicted it.
    /// # C: O(1)
    pub fn set_quota_record(&mut self, kind: usize, id: u32, d: Dqblk) -> Result<(), Errno> {
        if kind >= MAX_QUOTAS { return Err(Errno::Einval); }
        if !quota::types::accounted(&self.quota_setup[kind]) { return Err(Errno::Esrch); }
        self.dquots.insert((kind, id), d);
        self.dq_dirty.insert((kind, id));
        self.dirty = true;
        Ok(())
    }

    /// The next identity at or after `id` this kind holds a record for, and
    /// that record.
    ///
    /// Walking the identity space one number at a time is not an option — it
    /// is the whole of a four-byte number — so the answer comes off the
    /// tree's own shape. A kind this volume does not account has no next
    /// identity rather than an empty one, which is how a caller tells "no
    /// records" from "no accounting".
    /// # C: O(file bytes)
    pub fn quota_next_record(&mut self, kind: usize, id: u32)
        -> Result<Option<(u32, Dqblk)>, Errno> {
        if kind >= MAX_QUOTAS { return Err(Errno::Einval); }
        if !quota::types::accounted(&self.quota_setup[kind]) { return Err(Errno::Esrch); }
        let info = self.dq_info(kind)?;
        let file = self.read_quota_file(self.quota_setup[kind].ino)?;
        quota::tree::next_record(&file, &info, id).map_err(|e| e.errno())
    }

    /// Write every changed record back into its file.
    ///
    /// Runs at checkpoint, with the rest of the volume's counts. A record the
    /// tree has no slot for GETS one: the first allocation by an identity is
    /// exactly the case with no slot, so a checkpoint that dropped it would
    /// leave every new uid, gid and project unaccounted for good. A record
    /// with nothing left in it is removed instead of written, which is what
    /// keeps the file from keeping a slot for every identity that ever
    /// touched the volume.
    /// # C: O(dirty ids * file bytes)
    pub(crate) fn flush_quotas(&mut self) -> Result<(), Errno> {
        if self.dq_dirty.is_empty() { return Ok(()); }
        let dirty: Vec<(usize, u32)> = self.dq_dirty.iter().copied().collect();
        for kind in 0..MAX_QUOTAS {
            let ids: Vec<u32> = dirty.iter().filter(|(k, _)| *k == kind).map(|(_, i)| *i).collect();
            if ids.is_empty() { continue; }
            let ino = self.quota_setup[kind].ino;
            if ino == 0 { continue; }
            let mut info = self.dq_info(kind)?;
            let mut file = self.read_quota_file(ino)?;
            let mut touched = false;
            for id in ids {
                let Some(d) = self.dquots.get(&(kind, id)).cloned() else { continue };
                let r = if unused_record(&d) {
                    quota::tree::delete(&mut file, &mut info, id)
                } else {
                    quota::tree::write_or_create(&mut file, &mut info, id, &d)
                };
                r.map_err(|e| e.errno())?;
                touched = true;
            }
            if touched {
                // The header carries the block count and both free lists, so
                // a tree that grew and a header that did not describes a file
                // whose new blocks nothing can find again.
                quota::info::store(&mut file, &info).map_err(|e| e.errno())?;
                self.quota_info[kind] = Some(info);
                self.write_quota_file(ino, &file)?;
            }
        }
        self.dq_dirty.clear();
        Ok(())
    }

    /// Put a quota file's bytes back.
    ///
    /// Written through the ordinary file path, so the blocks it occupies are
    /// allocated and accounted like any other — except for the charge, which
    /// `is_quota_file` suppresses.
    /// # C: O(file bytes)
    fn write_quota_file(&mut self, ino: u32, bytes: &[u8]) -> Result<(), Errno> {
        for (i, chunk) in bytes.chunks(BLKSIZE).enumerate() {
            self.write_one_block(ino, i as u64, 0, chunk)?;
        }
        // A tree that grew put blocks PAST the inode's recorded length, and a
        // read of the file stops at that length: the header would hand back
        // more blocks than the file has, and the next mount would refuse its
        // own quota file as corrupt. The block count moves with it, because a
        // file that occupies blocks it does not admit to is what a check
        // reports as a leak.
        let len = bytes.len() as u64;
        if self.read_inode(ino)?.size < len {
            let blocks = self.count_blocks(ino)?;
            self.stamp_inode(ino, |b| {
                put64(b, I_SIZE, len);
                Self::set_iblocks(b, blocks);
            })?;
        }
        // Placed here rather than left to the next flush point: this is called
        // from inside the checkpoint, PAST the point that would have placed
        // it, and the checkpoint that records these counts is the same one
        // that has to be able to find the blocks holding them.
        self.flush_data_pages(ino)
    }
}

#[cfg(test)]
#[path = "../tests/quotawire.rs"]
mod tests;
