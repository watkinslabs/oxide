// The writeback PASS: `__writeback_single_inode` plus the per-superblock and
// whole-system sweeps built on it. This is the path that actually calls
// `s_op->write_inode`; before it existed the dirty bits were dropped on the
// floor by the sync path, which is why a deferred timestamp could not be
// deferred at all.

extern crate alloc;
use alloc::vec::Vec;

use crate::inode::InodeRef;
use crate::superblock::SuperBlock;
use crate::types::VfsError;
use crate::KResult;

use super::dirty::sync_lazytime_on;
use super::policy::{forces_lazytime, harvest_dirty, needs_write_inode, DIRTYTIME_EXPIRE_SECS};

/// The ONE place a writeback failure with nobody to return it to is recorded.
///
/// A background pass, an eviction and a whole-system `sync` all discover errors
/// that no caller is waiting on. `mapping_set_error` is the latch that makes
/// them reportable later: it records into the inode's own `wb_err` — so a
/// subsequent `fsync` on that file reports it exactly once — AND into the
/// filesystem-wide latch, so `syncfs` still reports it after the inode itself
/// has been evicted. Writing only the filesystem-wide half leaves the per-inode
/// `fsync` blind, which is the asymmetry this exists to prevent.
///
/// An inode not yet bound to its instance cannot reach the filesystem-wide latch
/// on its own, so the superblock the pass is running over records it directly;
/// otherwise a failure on such an inode would be reportable only for as long as
/// the inode survived. # C: O(1)
pub(crate) fn wb_set_error(sb: &SuperBlock, inode: &InodeRef, e: VfsError) {
    inode.mapping_set_error(e as i32);
    if inode.i_sb().is_none() { sb.s_wb_err.set(e as u32); }
}

impl SuperBlock {
    /// Resolve one inode's metadata debt.
    ///
    /// Order is the contract, not a preference:
    /// 1. Convert a pending lazy timestamp FIRST, because that conversion is
    ///    itself a dirtying — harvesting the dirty bits before it would clear
    ///    the very state it creates.
    /// 2. Harvest and clear `I_DIRTY`, so a backend that re-dirties the inode
    ///    while writing it keeps the new bits rather than having them wiped.
    /// 3. Call `s_op->write_inode` only when the INODE (not merely its pages)
    ///    was dirty.
    ///
    /// `sync_all` is Linux's `WB_SYNC_ALL`: a data-integrity pass (`sync`,
    /// `syncfs`, `fsync`, unmount) which forces every deferred stamp out
    /// regardless of age. A background pass (`sync_all == false`) converts only
    /// deferrals older than [`DIRTYTIME_EXPIRE_SECS`].
    /// # C: O(1) + one backend inode write
    pub fn writeback_single_inode(&self, inode: &InodeRef, sync_all: bool, now_ns: u64)
        -> KResult<()>
    {
        if forces_lazytime(sync_all, inode.dirtied_time_when(), now_ns, DIRTYTIME_EXPIRE_SECS) {
            sync_lazytime_on(Some(self), inode, now_ns);
        }
        let dirty = harvest_dirty(inode.i_state());
        inode.set_state(0, dirty);
        let r = if needs_write_inode(dirty) { self.s_op.write_inode(inode, sync_all) } else { Ok(()) };
        self.wb_reconcile_inode(inode);
        r
    }

    /// One writeback pass over every inode this superblock has pinned dirty
    /// (Linux `writeback_sb_inodes` over `b_dirty` + `b_dirty_time`). Returns
    /// the FIRST backend error, having still attempted every other inode — a
    /// single unwritable inode must not strand the rest of the filesystem.
    /// Snapshots the pinned set first so a per-inode unpin cannot mutate the map
    /// under its own iterator.
    ///
    /// EVERY per-inode failure — not only the one returned — is latched through
    /// [`wb_set_error`]. The returned error reaches at most the caller that
    /// happens to be waiting; the latch is what makes a failure on the second or
    /// tenth inode visible to a later `fsync` on THAT file and to a later
    /// `syncfs` on this filesystem. # C: O(N_wb)
    pub fn wb_writeback_pass(&self, sync_all: bool, now_ns: u64) -> KResult<()> {
        let mut first_err = Ok(());
        for inode in self.wb_dirty_inodes() {
            let r = self.writeback_single_inode(&inode, sync_all, now_ns);
            if let Err(e) = r { wb_set_error(self, &inode, e); }
            if first_err.is_ok() { first_err = r; }
        }
        first_err
    }

    /// Background dirtytime pass for THIS superblock (Linux's
    /// `wakeup_dirtytime_writeback` reaching `b_dirty_time`): flush only the
    /// deferrals that have outlived the expire interval, leaving fresh ones
    /// deferred — which is the entire point of the option. # C: O(N_wb)
    pub fn wb_flush_expired_dirtytime(&self, now_ns: u64) -> KResult<()> {
        self.wb_writeback_pass(false, now_ns)
    }
}

/// The periodic work
/// that keeps a lazily-deferred timestamp from living in memory forever: sweep
/// every mounted filesystem forcing out the deferrals older than
/// [`DIRTYTIME_EXPIRE_SECS`]. Bind mounts share a superblock, so the sweep
/// dedups by `Arc` identity. Returns the number of superblocks visited.
///
/// Every failure the sweep discovers is latched by the pass itself
/// ([`wb_set_error`]), against BOTH the inode that failed and its filesystem, so
/// the next `fsync` on that file and the next `syncfs` on that filesystem each
/// report it exactly once instead of it vanishing into a background pass nobody
/// is waiting on. Recording only the filesystem-wide half here — which is what
/// this did — left the per-inode `fsync` blind to its own failure.
/// # C: O(N_sb x N_wb)
pub fn dirtytime_expire_pass(now_ns: u64) -> usize {
    let mut seen: Vec<*const ()> = Vec::new();
    for m in crate::mount::all_mounts().iter() {
        let sb = m.sb();
        let key = alloc::sync::Arc::as_ptr(sb) as *const ();
        if seen.contains(&key) { continue; }
        seen.push(key);
        let _ = sb.wb_flush_expired_dirtytime(now_ns);
    }
    seen.len()
}
