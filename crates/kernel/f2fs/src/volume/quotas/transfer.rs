//! Moving accumulated usage when an inode changes identity.

use crate::quota::{self, Verdict};
use crate::uapi::{BLKSIZE, MAX_QUOTAS};

use sectors::SectorSource;
use syscall::errno::Errno;

use crate::volume::Volume;

use super::{Owners, PRJQUOTA};

impl<S: SectorSource> Volume<S> {
    /// Move one inode and all space it holds between quota identities.
    /// Every destination is checked before any record or inode is changed.
    /// # C: O(blocks the file has + kinds)
    pub(crate) fn dquot_transfer(&mut self, ino: u32, to: Owners) -> Result<(), Errno> {
        if !self.quota_active() || self.is_quota_file(ino) { return Ok(()); }
        let Some(from) = self.dquot_owners_of(ino) else { return Ok(()); };
        if from == to { return Ok(()); }
        let occupied = self.quota_blocks(ino)?.saturating_mul(BLKSIZE as u64);
        let mut plans = [(0usize, 0u32, 0u32, Verdict::Allow, Verdict::Allow); MAX_QUOTAS];
        let mut n = 0usize;

        for kind in 0..MAX_QUOTAS {
            if kind == PRJQUOTA || from.id(kind) == to.id(kind) { continue; }
            if !quota::types::accounted(&self.quota_setup[kind]) { continue; }
            let Some(d) = self.dq_held(kind, to.id(kind)) else { continue; };
            let Some(info) = self.dq_info_held(kind) else { continue; };
            let iv = quota::limit::inodes(&d, 1, &self.ask_for(kind, &info, false, false));
            let sv = quota::limit::space(
                &d,
                occupied,
                &self.ask_for(kind, &info, true, false),
            );
            if !iv.allowed() || !sv.allowed() { return Err(Errno::Edquot); }
            plans[n] = (kind, from.id(kind), to.id(kind), sv, iv);
            n += 1;
        }

        for &(kind, from_id, to_id, sv, iv) in plans.iter().take(n) {
            let Some(mut target) = self.dq_held(kind, to_id) else { continue; };
            quota::limit::apply_inodes(&mut target, 1, iv);
            quota::limit::apply_space(&mut target, occupied, sv);
            self.dquots.insert((kind, to_id), target);
            self.dq_dirty.insert((kind, to_id));

            if let Some(mut source) = self.dq_held(kind, from_id) {
                quota::limit::free_inodes(&mut source, 1);
                quota::limit::free_space(&mut source, occupied);
                self.dquots.insert((kind, from_id), source);
                self.dq_dirty.insert((kind, from_id));
            }
        }
        if n > 0 { self.dirty = true; }
        Ok(())
    }
}
