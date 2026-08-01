// `__mark_inode_dirty` / `sync_lazytime` / the timestamp-stamping entry point —
// the half of the writeback contract that operates on a live inode. The rules
// themselves live in [`super::policy`]; this file only applies them.

use crate::inode::{generic_update_time, InodeRef, I_DIRTY_SYNC, I_DIRTY_TIME};
use crate::timespec::Timespec64;
use crate::KResult;

use super::policy::{is_eager_timestamp, mark_dirty_transition, time_dirty_flag};

/// `__mark_inode_dirty(inode, flags)` (Linux fs/fs-writeback.c). Applies the
/// [`mark_dirty_transition`] result: supersede a pending lazy stamp, notify the
/// backend through `s_op->dirty_inode`, latch the new bits, start the expiry
/// clock, and reconcile the superblock's writeback pin so a dirty inode cannot
/// be evicted out from under the data it still owes the disk.
///
/// `now_ns` is the caller's wall clock (the vfs crate is clock-free); it is only
/// read when a deferral BEGINS.
/// # C: O(log N_wb)
pub fn mark_inode_dirty(inode: &InodeRef, flags: u32, now_ns: u64) {
    let sb = inode.i_sb();
    mark_inode_dirty_on(sb.as_deref(), inode, flags, now_ns);
}

/// [`mark_inode_dirty`] against an EXPLICIT superblock — the form the
/// superblock's own cache-keyed entry point uses. An inode built without an
/// `i_sb` back-pointer (every ad-hoc pseudo/anon inode) still belongs to the
/// superblock that cached it, and resolving the owner from the inode alone would
/// silently skip both the backend notification and the writeback pin for it.
/// `None` is the genuinely superblock-less case (an anon inode): the state bits
/// are latched, and there is no list to pin it on. # C: O(log N_wb)
pub fn mark_inode_dirty_on(sb: Option<&crate::superblock::SuperBlock>, inode: &InodeRef,
    flags: u32, now_ns: u64)
{
    let t = mark_dirty_transition(inode.i_state(), flags);
    if t.clear != 0 { inode.set_state(0, t.clear); inode.set_dirtied_time_when(0); }
    if t.notify != 0 {
        if let Some(sb) = sb { sb.dirty_inode(inode, t.notify); }
    }
    if t.changed {
        if t.stamp { inode.set_dirtied_time_when(now_ns); }
        inode.set_state(t.set, 0);
    }
    // Dirtying can only ever ADD a pin — every path here leaves at least one
    // `I_DIRTY_ALL` bit set — so this is the insert half, not a reconcile.
    if let Some(sb) = sb { sb.wb_pin(inode.ino(), inode); }
}

/// `sync_lazytime(inode)` (Linux fs/fs-writeback.c) — force a deferred timestamp
/// out of the lazy state, against the superblock that owns the inode (see
/// [`mark_inode_dirty_on`] for why the owner is passed rather than read off the
/// inode). Returns false when nothing was pending.
///
/// The conversion runs through [`mark_inode_dirty`] with `I_DIRTY_SYNC` so it
/// takes exactly the supersede path a real metadata change would: the backend's
/// `dirty_inode` notification carries `I_DIRTY_TIME`, telling it to write the
/// timestamps out with this change. `i_op->sync_lazytime` then gives a backend
/// that persists timestamps directly (rather than through `s_op->write_inode`)
/// its write-through, and the residual `I_DIRTY_SYNC` makes the following
/// writeback pass call `s_op->write_inode` for one that does not. Both routes
/// end with the stamp on disk, which is the only property lazytime may not
/// trade away.
/// # C: O(1) + one backend inode write
pub fn sync_lazytime_on(sb: Option<&crate::superblock::SuperBlock>, inode: &InodeRef, now_ns: u64)
    -> bool
{
    if inode.i_state() & I_DIRTY_TIME == 0 { return false; }
    mark_inode_dirty_on(sb, inode, I_DIRTY_SYNC, now_ns);
    let _ = inode.sync_lazytime();
    true
}

/// The VFS timestamp-update entry point every stamping site converges on
/// (Linux `generic_update_time` → `inode_update_time` + `__mark_inode_dirty`).
///
/// `s_flags` selects which of `S_ATIME`/`S_MTIME`/`S_CTIME`/`S_VERSION` move.
/// The mount decides how the change is recorded:
///
/// * NOT lazytime — write THROUGH `i_op->update_time`, which is what a backend
///   with on-disk inodes (ext4) hooks to journal the stamp immediately. Byte for
///   byte the behaviour that existed before the deferral, and the reason no
///   `I_DIRTY_SYNC` is latched afterwards: the value is already durable, so
///   pinning the inode on the writeback list would buy nothing and would keep
///   every read-stamped inode unevictable until the next `sync`.
/// * lazytime — update the IN-CORE fields only and record the debt as
///   `I_DIRTY_TIME`, with the superblock's writeback pin holding the inode alive
///   until a forcing point pays it.
/// # C: O(1) [+ one backend inode write when eager]
pub fn inode_update_time(inode: &InodeRef, now: Timespec64, s_flags: u32, now_ns: u64)
    -> KResult<()>
{
    let lazytime = inode.i_sb().is_some_and(|sb| sb.is_lazytime());
    if is_eager_timestamp(lazytime) {
        inode.update_time(now, s_flags)?;
        // A deferral outstanding from before the mount was remounted
        // `nolazytime` is PAID by that write-through — the backend just wrote
        // the whole timestamp set. Clearing it through `mark_inode_dirty` is
        // Linux's `I_DIRTY_INODE` supersede, and keeps the flip from leaving a
        // debt bit that no forcing point owes anything for.
        if inode.i_state() & crate::inode::I_DIRTY_TIME != 0 {
            mark_inode_dirty(inode, I_DIRTY_SYNC, now_ns);
        }
        return Ok(());
    }
    generic_update_time(inode, now, s_flags)?;
    mark_inode_dirty(inode, time_dirty_flag(lazytime), now_ns);
    Ok(())
}
