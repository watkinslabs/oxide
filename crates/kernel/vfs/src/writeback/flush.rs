// The writeback PASS: `__writeback_single_inode` plus the per-superblock and
// whole-system sweeps built on it. This is the path that actually calls
// `s_op->write_inode`; before it existed the dirty bits were dropped on the
// floor by the sync path, which is why a deferred timestamp could not be
// deferred at all.

extern crate alloc;
use alloc::vec::Vec;

use crate::inode::InodeRef;
use crate::superblock::SuperBlock;
use crate::KResult;

use super::dirty::sync_lazytime_on;
use super::policy::{forces_lazytime, harvest_dirty, needs_write_inode, DIRTYTIME_EXPIRE_SECS};

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
    /// under its own iterator. # C: O(N_wb)
    pub fn wb_writeback_pass(&self, sync_all: bool, now_ns: u64) -> KResult<()> {
        let mut first_err = Ok(());
        for inode in self.wb_dirty_inodes() {
            let r = self.writeback_single_inode(&inode, sync_all, now_ns);
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
/// A per-superblock failure is recorded in that filesystem's `s_wb_err` latch so
/// the next `syncfs`/`fsync` on it reports the error exactly once, rather than
/// vanishing into a background pass nobody is waiting on. # C: O(N_sb x N_wb)
pub fn dirtytime_expire_pass(now_ns: u64) -> usize {
    let mut seen: Vec<*const ()> = Vec::new();
    for m in crate::mount::all_mounts().iter() {
        let sb = m.sb();
        let key = alloc::sync::Arc::as_ptr(sb) as *const ();
        if seen.contains(&key) { continue; }
        seen.push(key);
        if let Err(e) = sb.wb_flush_expired_dirtytime(now_ns) { sb.s_wb_err.set(e as u32); }
    }
    seen.len()
}
