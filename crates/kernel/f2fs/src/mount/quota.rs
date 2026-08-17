//! The quota hooks `quotactl(2)` reaches this filesystem through.
//!
//! Everything below this file already knows how to find, decode and write a
//! record: the tree walk, the limit decision and the per-identity cache are
//! the volume's. What was missing is the other end — the interface's quota
//! control path resolves a record through the hooks a filesystem installs on
//! its superblock, and a filesystem that installs none answers every
//! `quotactl` with "no such process" however complete its own machinery is.
//!
//! The space axis is BYTES on both sides. The stored form counts units and
//! the decode turns them into bytes, so nothing here converts: a conversion
//! that only one of the two ends applied is the shape a quota bug takes.

use alloc::sync::Arc;
use core::any::Any;

use vfs::{Dquot, DquotOperations, Kqid, MemDqblk, QuotaType};
use vfs::KResult;

use crate::quota::Dqblk;

use super::F2fs;

/// One mounted volume's quota hooks.
pub struct F2fsDquotOps {
    pub(crate) fs: Arc<F2fs>,
}

/// A stored record as the interface's record. # C: O(1)
pub fn to_mem(d: &Dqblk) -> MemDqblk {
    MemDqblk {
        dqb_bhardlimit: d.bhardlimit,
        dqb_bsoftlimit: d.bsoftlimit,
        dqb_curspace: d.curspace,
        dqb_rsvspace: d.rsvspace,
        dqb_ihardlimit: d.ihardlimit,
        dqb_isoftlimit: d.isoftlimit,
        dqb_curinodes: d.curinodes,
        dqb_btime: d.btime as i64,
        dqb_itime: d.itime as i64,
        ..MemDqblk::default()
    }
}

/// The interface's record as a stored one.
///
/// A negative expiry cannot be stored — the medium's field is unsigned — and
/// it cannot arise from a clock either, so it reads as "no grace running"
/// rather than wrapping into an expiry billions of seconds away.
/// # C: O(1)
pub fn from_mem(m: &MemDqblk) -> Dqblk {
    Dqblk {
        bhardlimit: m.dqb_bhardlimit,
        bsoftlimit: m.dqb_bsoftlimit,
        curspace: m.dqb_curspace,
        rsvspace: m.dqb_rsvspace,
        ihardlimit: m.dqb_ihardlimit,
        isoftlimit: m.dqb_isoftlimit,
        curinodes: m.dqb_curinodes,
        btime: m.dqb_btime.max(0) as u64,
        itime: m.dqb_itime.max(0) as u64,
    }
}

impl DquotOperations for F2fsDquotOps {
    /// # C: O(1)
    fn as_any(&self) -> &dyn Any { self }

    /// Load one identity's record off the medium into the record the
    /// interface hands out.
    ///
    /// An identity the file holds no slot for reads as an empty record rather
    /// than an error, the same way the volume's own reader does: it has never
    /// allocated anything, and refusing would make the first `quotactl` for
    /// every new identity fail.
    /// # C: O(quota file bytes) on the first touch
    fn acquire_dquot(&self, dq: &Dquot) -> KResult<()> {
        let qid = dq.id();
        let d = self
            .fs
            .volume
            .lock()
            .quota_record(qid.kind.slot(), qid.id)
            .map_err(super::errno_to_vfs)?;
        dq.set_dqblk(to_mem(&d));
        Ok(())
    }

    /// The lowest identity at or after `qid` this kind holds a record for.
    ///
    /// Walking the identity space one number at a time is not an option — it
    /// is the whole of a four-byte number — so the answer comes off the
    /// tree's own shape.
    /// # C: O(quota file bytes)
    fn get_next_id(&self, qid: Kqid) -> KResult<Option<Kqid>> {
        let found = self
            .fs
            .volume
            .lock()
            .quota_next_record(qid.kind.slot(), qid.id)
            .map_err(super::errno_to_vfs)?;
        Ok(found.map(|(id, _)| Kqid { kind: qid.kind, id }))
    }

    /// Take a changed record back into the volume's cache.
    ///
    /// The write reaches the MEDIUM at the next checkpoint, with the rest of
    /// the counts it describes — the same window the volume's own accounting
    /// is made durable in, so a crash loses the same amount of both.
    /// # C: O(kinds)
    fn write_dquot(&self, dq: &Dquot) -> KResult<()> {
        let qid = dq.id();
        self.fs
            .volume_now()
            .set_quota_record(qid.kind.slot(), qid.id, from_mem(&dq.dqblk()))
            .map_err(super::errno_to_vfs)
    }

    /// A changed record is written at the next checkpoint rather than now, so
    /// marking one dirty is the same work as writing it. # C: O(kinds)
    fn mark_dirty(&self, dq: &Dquot) -> KResult<()> { self.write_dquot(dq) }
}

/// Which kinds a volume's setup says to enable, and in what format.
///
/// The decision half of [`install`], apart from it because installing needs a
/// mounted filesystem and this does not: a kind the volume does not account
/// is deliberately left disabled rather than enabled-and-empty, and that rule
/// is worth a check that can fail. The interface tells "this filesystem does
/// not account that kind" from "that identity has no record" by exactly this,
/// and a kind enabled with no file behind it answers every query with zeroes
/// that read as a real answer.
/// # C: O(kinds)
pub fn enable_plan(setups: &[crate::quota::Setup]) -> [Option<u32>; crate::uapi::MAX_QUOTAS] {
    core::array::from_fn(|slot| match setups.get(slot) {
        Some(s) if crate::quota::types::accounted(s) => Some(s.fmt),
        _ => None,
    })
}

/// Install the hooks and enable every kind this volume accounts.
///
/// Called once, where the superblock is built.
/// # C: O(kinds)
pub fn install(sb: &Arc<vfs::superblock::SuperBlock>, fs: &Arc<F2fs>) {
    let ops: Arc<dyn DquotOperations> = Arc::new(F2fsDquotOps { fs: Arc::clone(fs) });
    let plan = enable_plan(fs.volume.lock().quota_setup());
    for (slot, fmt) in plan.iter().enumerate() {
        let Some(fmt) = *fmt else { continue };
        let kind = QuotaType::from_slot(slot);
        sb.s_dquot.set_operations(kind, Arc::clone(&ops));
        sb.s_dquot.enable(kind, fmt);
    }
}

/// Whether this mount accounts `kind` at all, for the superblock's own
/// `s_quota_types` answer. # C: O(1)
pub fn accounts(fs: &F2fs, kind: QuotaType) -> bool {
    crate::quota::types::accounted(&fs.volume.lock().quota_setup()[kind.slot()])
}

#[cfg(test)]
#[path = "../tests/quotaops.rs"]
mod tests;
