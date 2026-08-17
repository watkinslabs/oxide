//! What a caller asking about limits, rather than allocating, sees.

use crate::quota::{self, Dqblk};
use crate::uapi::MAX_QUOTAS;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::volume::Volume;

impl<S: SectorSource> Volume<S> {
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
}
