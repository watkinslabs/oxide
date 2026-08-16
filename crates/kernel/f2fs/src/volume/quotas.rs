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
use crate::uapi::{BLKSIZE, MAX_QUOTAS};

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

impl<S: SectorSource> Volume<S> {
    /// Who an inode's allocations are charged to. # C: O(1 block)
    pub(crate) fn owners_of(&self, ino: u32) -> Result<Owners, Errno> {
        let i = self.read_inode(ino)?;
        Ok(Owners::new(i.uid, i.gid, i.projid))
    }

    /// Whether `ino` is one of the volume's own quota files. # C: O(1)
    pub(crate) fn is_quota_file(&self, ino: u32) -> bool {
        quota::types::is_quota_inode(&self.sb.qf_ino, self.sb.feature, ino)
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
        if let Some(d) = self.dquots.get(&(kind, id)) { return Ok(d.clone()); }
        let info = self.dq_info(kind)?;
        let file = self.read_quota_file(self.quota_setup[kind].ino)?;
        let d = quota::tree::read(&file, &info, id).map_err(|_| Errno::Eio)?.unwrap_or_default();
        self.dquots.insert((kind, id), d.clone());
        Ok(d)
    }

    /// What the decision is made against, for one kind. # C: O(1)
    fn ask_for(&self, kind: usize, info: &Info, space: bool) -> Ask {
        Ask {
            now: self.clock,
            grace: if space { u64::from(info.bgrace) } else { u64::from(info.igrace) },
            // Nothing here runs as a privileged caller: the interface above
            // decides who may exceed a hard limit, and it does not tell us.
            exempt: false,
            enforced: quota::types::enforced(&self.quota_setup[kind]),
            allocating: true,
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
        self.charge(ino, bytes, 0)
    }

    /// Charge one inode to `ino`'s owners. # C: O(kinds)
    pub(crate) fn charge_inode(&mut self, ino: u32) -> Result<(), Errno> {
        self.charge(ino, 0, 1)
    }

    /// The one charging path. # C: O(kinds)
    fn charge(&mut self, ino: u32, bytes: u64, inodes: u64) -> Result<(), Errno> {
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
                quota::limit::space(&d, bytes, &self.ask_for(kind, &info, true))
            } else {
                Verdict::Allow
            };
            let iv = if inodes > 0 {
                quota::limit::inodes(&d, inodes, &self.ask_for(kind, &info, false))
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
            if bytes > 0 { quota::limit::apply_space(&mut d, bytes, sv); }
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

    /// Write every changed record back into its file.
    ///
    /// Runs at checkpoint, with the rest of the volume's counts. A record the
    /// tree has no slot for is DROPPED rather than failing the checkpoint:
    /// the tree cannot grow yet, and losing one identity's accounting is a
    /// smaller wrong than refusing to make the filesystem durable.
    /// # C: O(dirty ids * file bytes)
    pub(crate) fn flush_quotas(&mut self) -> Result<(), Errno> {
        if self.dq_dirty.is_empty() { return Ok(()); }
        let dirty: Vec<(usize, u32)> = self.dq_dirty.iter().copied().collect();
        for kind in 0..MAX_QUOTAS {
            let ids: Vec<u32> = dirty.iter().filter(|(k, _)| *k == kind).map(|(_, i)| *i).collect();
            if ids.is_empty() { continue; }
            let ino = self.quota_setup[kind].ino;
            if ino == 0 { continue; }
            let info = self.dq_info(kind)?;
            let mut file = self.read_quota_file(ino)?;
            let mut touched = false;
            for id in ids {
                let Some(d) = self.dquots.get(&(kind, id)).cloned() else { continue };
                if quota::tree::write(&mut file, &info, id, &d).is_ok() { touched = true; }
            }
            if touched { self.write_quota_file(ino, &file)?; }
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
        Ok(())
    }
}

#[cfg(test)]
#[path = "../tests/quotawire.rs"]
mod tests;
