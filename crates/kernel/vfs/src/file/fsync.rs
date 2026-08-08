// Durability primitives: `vfs_fsync_range`, `generic_write_sync`, and the
// per-description writeback-error harvest.
//
// These live in `vfs` rather than in `fs` because every part they touch —
// `i_mapping`, `f_op->fsync`, the `errseq` latches on the inode/superblock —
// is a `vfs` object, and because `File::write`/`pwrite`/`write_iter` must be
// able to call `generic_write_sync` at exactly the point Linux does — the
// tail of the generic write path, after the bytes are accounted but before
// the call returns. Routing that through `fs` would need an upward
// dependency or a hook registry, and a hook is the wrong shape for a
// mandatory step of the write contract.

use core::sync::atomic::Ordering;

use crate::errseq::ErrseqVal;
use crate::file::File;
use crate::types::{FileType, KResult, OpenFlags, VfsError};

/// Linux's "to EOF" inclusive end byte for a whole-file sync — the signed
/// `loff_t` maximum, not `u64::MAX`.
pub const SYNC_TO_EOF: u64 = i64::MAX as u64;

/// Which `file_operations` install an `fsync` slot — `fsync(2)` returns
/// `EINVAL` for the ones that do not.
///
/// Byte-addressable descriptions — regular file, directory, block device — do.
/// Every stream or anon description does NOT: pipe and FIFO (`pipefifo_fops`),
/// socket (`socket_file_ops`), character device (`memory_fops`, `tty_fops`),
/// and the anon inodes (eventfd / epoll / timerfd / signalfd / inotify /
/// userfaultfd).
///
/// ONE source of truth for two questions Linux answers with one pointer test:
/// "is `fsync(2)` legal here" (the `EINVAL` gate) and "is this a filesystem
/// write path" (whether `generic_write_sync` applies at all). Both callers
/// below read it; [`crate::file_ops::FileOps::fsync`]'s default does too.
/// # C: O(1)
pub const fn fsync_slot_present(ft: FileType) -> bool {
    matches!(ft, FileType::Regular | FileType::Directory | FileType::BlockDev)
}

/// Effective `IOCB_DSYNC` / `IOCB_SYNC` for one write.
///
/// Seeded from the open description's sync flags, then OR-ed with the
/// per-operation `RWF_*` bits for that one write.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct SyncMode {
    /// `IOCB_DSYNC` — sync the data (and the metadata needed to read it).
    pub dsync: bool,
    /// `IOCB_SYNC` — full file-integrity sync, i.e. `datasync = 0`.
    pub sync: bool,
}

impl SyncMode {
    /// Union of two sources of sync-ness — the description's own flags and a
    /// per-operation `RWF_SYNC`/`RWF_DSYNC`. # C: O(1)
    pub const fn union(self, other: SyncMode) -> SyncMode {
        SyncMode { dsync: self.dsync || other.dsync, sync: self.sync || other.sync }
    }

    /// The `datasync` argument `generic_write_sync` passes down: full-sync
    /// mode yields `datasync == false`, data-sync-only mode yields `true`.
    ///
    /// Note the direction — `O_SYNC` asks for MORE than `O_DSYNC`, so it is
    /// the one that yields `datasync == false`. Getting this backwards makes
    /// `O_SYNC` the weaker of the two. # C: O(1)
    pub const fn datasync(self) -> bool { !self.sync }
}

/// A description's effective sync flags: the open-time `O_SYNC`/`O_DSYNC`
/// bits, plus whether the inode itself is marked always-sync.
///
/// `O_SYNC` is `__O_SYNC | O_DSYNC` in the uapi, so an `O_SYNC` open sets BOTH
/// bits and a plain `O_DSYNC` open sets only `dsync` — which is precisely how
/// the two differ in strength. A `chattr +S` inode (`S_SYNC`) is treated as
/// `O_SYNC` on every description, matching `iocb_is_dsync`'s `IS_SYNC` test.
/// # C: O(1)
pub fn iocb_sync_mode(file: &File) -> SyncMode {
    let f = file.flags();
    // `__O_SYNC` is the bit that distinguishes O_SYNC from O_DSYNC; our
    // `OpenFlags::O_SYNC` is the full `__O_SYNC | O_DSYNC` pair, so testing
    // `contains(O_SYNC)` is the `__O_SYNC` test.
    let inode_sync = file.inode().is_sync();
    SyncMode {
        dsync: inode_sync || f.contains(OpenFlags::O_DSYNC) || f.contains(OpenFlags::O_SYNC),
        sync:  inode_sync || f.contains(OpenFlags::O_SYNC),
    }
}

/// THE durability ordering, in one place. Both entry points below — the
/// fd-based `vfs_fsync_range` and the VMA-based [`Inode::mapping_fsync_range`]
/// — route through here so the order can never drift between them.
///
/// The journaling-filesystem `fsync` contract, in order:
/// 1. push dirty page-cache data out and wait for it to land.
/// 2. commit the transaction carrying this inode's metadata.
/// 3. issue the device write barrier.
///
/// Steps 2+3 are `backend`. They are SKIPPED when step 1 failed, exactly as
/// Linux's `goto out` does: committing metadata that claims data landed, when
/// it did not, is worse than not committing.
///
/// Every failure is recorded with `mapping_set_error` before being returned, so
/// a caller that discards the result still cannot make the error disappear from
/// the next `fsync`/`syncfs`. # C: O(N_dirty in range) + O(journal tx)
fn fsync_ordered(
    inode: &crate::inode::Inode,
    start: u64,
    end_incl: u64,
    backend: impl FnOnce() -> KResult<()>,
) -> KResult<()> {
    // An inverted range (end before start) is a no-op, not an error.
    if end_incl >= start {
        if let Some(mapping) = inode.i_mapping() {
            // Half-open [start, end) from Linux's INCLUSIVE endbyte.
            let end_excl = if end_incl >= SYNC_TO_EOF { u64::MAX } else { end_incl + 1 };
            if mapping.writeback_range(start, end_excl).is_err() {
                // The writeback surface reports failure without an errno; `EIO`
                // is the generic writeback failure Linux records when a
                // filesystem has nothing more specific.
                inode.mapping_set_error(VfsError::Eio as i32);
                return Err(VfsError::Eio);
            }
        }
    }
    match backend() {
        Ok(()) => Ok(()),
        Err(e) => { inode.mapping_set_error(e as i32); Err(e) }
    }
}

impl crate::inode::Inode {
    /// `vfs_fsync_range` reached through a VMA instead of an fd — the
    /// `msync(MS_SYNC)` path.
    ///
    /// `msync` holds the VMA's backing file and syncs the mapped range with
    /// `datasync = true` unconditionally. Our VMA carries the address_space
    /// rather than the description, so the backend half comes from
    /// [`crate::AddressSpaceOps::sync_backing`] instead of `f_op->fsync`. The
    /// ORDER is identical because both go through [`fsync_ordered`].
    ///
    /// Note `datasync` is implicit and always true here, so `msync` is an
    /// `fdatasync` over the range, never a full `fsync`.
    /// # C: O(N_dirty in range) + O(journal tx)
    pub fn mapping_fsync_range(&self, start: u64, end_incl: u64) -> KResult<()> {
        let Some(mapping) = self.i_mapping() else { return Ok(()) };
        fsync_ordered(self, start, end_incl,
            || mapping.sync_backing().map_err(|()| VfsError::Eio))
    }
}

impl File {
    /// Report the writeback error recorded on this inode's address_space since THIS
    /// description last looked, and advance the snapshot past it.
    ///
    /// The report-once-per-fd rule is the whole contract: a database that gets
    /// `EIO` from `fsync`, retries the write and calls `fsync` again must not
    /// be told about the same old failure forever, and two processes with
    /// separate fds must EACH be told once. # C: O(1)
    pub fn check_and_advance_wb_err(&self) -> KResult<()> {
        let mut since: ErrseqVal = self.f_wb_err.load(Ordering::Acquire);
        let res = self.inode().wb_err().check_and_advance(&mut since);
        self.f_wb_err.store(since, Ordering::Release);
        match res {
            None => Ok(()),
            Some(e) => Err(VfsError::from_errno(e as i32)),
        }
    }

    /// The superblock-level errseq check-and-advance — the
    /// `syncfs(2)` half. Separate snapshot from
    /// [`Self::check_and_advance_wb_err`] because `fsync` and `syncfs` advance
    /// independently: reporting an error to one must not hide it from the
    /// other. # C: O(1)
    pub fn check_and_advance_sb_err(&self) -> KResult<()> {
        let Some(sb) = self.inode().i_sb() else { return Ok(()) };
        let mut since: ErrseqVal = self.f_sb_err.load(Ordering::Acquire);
        let res = sb.s_wb_err.check_and_advance(&mut since);
        self.f_sb_err.store(since, Ordering::Release);
        match res {
            None => Ok(()),
            Some(e) => Err(VfsError::from_errno(e as i32)),
        }
    }

    /// `vfs_fsync_range(file, start, end_incl, datasync)` — the fd-based
    /// full fsync/fdatasync entry point, composed with the ordered contract a
    /// journaling filesystem's `f_op->fsync` owes it.
    ///
    /// ORDER IS THE POINT, and it is the reverse of what this function used to
    /// do. The steps run:
    ///
    /// 1. push the dirty page-cache data out and wait for it. This is what
    ///    allocates the extents and settles `i_size`, i.e. it CREATES the
    ///    metadata the next step has to commit.
    /// 2. commit the transaction carrying this inode's metadata.
    /// 3. issue the device write barrier.
    /// 4. harvest a deferred writeback error.
    ///
    /// Steps 2 and 3 are the backend's `f_op->fsync` here (a journal commit
    /// then a device flush). Committing BEFORE the data is written back
    /// commits a transaction that does not yet describe the data — the
    /// bytes and their extents land after the barrier, so `fsync` returns 0
    /// having fenced nothing that matters. That is not a weaker guarantee, it
    /// is no guarantee.
    ///
    /// A writeback failure is recorded via `mapping_set_error` before it is
    /// returned, so a caller that ignores this return still cannot make the
    /// error vanish for the next `fsync`/`syncfs` — the error is latched
    /// inside writeback state for the same reason.
    ///
    /// `end_incl` is INCLUSIVE, like Linux's `endbyte`; [`SYNC_TO_EOF`] means
    /// "to the end of the file". # C: O(N_dirty in range)
    pub fn vfs_fsync_range(&self, start: u64, end_incl: u64, datasync: bool) -> KResult<()> {
        // Whether there is a page cache to write back first is a property of
        // the description; whether `fsync` is legal at all is `f_op->fsync`'s
        // own answer (`EINVAL` from the generic default for a pipe / socket /
        // eventfd). Keeping those two questions apart is
        // what lets a backend install a real `fsync` slot on a type the generic
        // table calls streaming without a second list contradicting it.
        let ret = if self.f_op().fsync_needs_writeback(self) {
            fsync_ordered(self.inode(), start, end_incl, || {
                self.fsync_metadata(datasync)?;
                self.f_op().fsync(self, datasync)
            })
        } else {
            // Nothing cached to flush: the backend's answer IS the result. Not
            // recorded in `wb_err` — that latch reports WRITEBACK failures, and
            // the `EINVAL` for a missing slot is not one (Linux returns from
            // `vfs_fsync_range` before any `mapping_set_error`).
            self.f_op().fsync(self, datasync)
        };
        // A deferred writeback error is reported only when this call had
        // nothing worse of its own.
        let deferred = self.check_and_advance_wb_err();
        match ret {
            Err(e) => Err(e),
            Ok(()) => deferred,
        }
    }

    /// `sync_inode_metadata(inode, 1)` — the inode-metadata half of a generic
    /// `->fsync`, run between the data writeback and the backend's commit so the
    /// commit covers the inode write rather than following it.
    ///
    /// Two gates, both Linux's:
    /// * nothing dirty at all (including a deferred timestamp) — nothing to do;
    /// * `fdatasync` on an inode with no `I_DIRTY_DATASYNC` — the caller asked
    ///   for the DATA to be durable and explicitly not to pay for metadata, so a
    ///   pending timestamp stays deferred. `fsync` has no such gate, which is
    ///   why it is a lazytime forcing point and `fdatasync` is not.
    /// # C: O(1) + one backend inode write
    fn fsync_metadata(&self, datasync: bool) -> KResult<()> {
        use crate::inode::{I_DIRTY_ALL, I_DIRTY_DATASYNC};
        let inode = self.inode();
        let st = inode.i_state();
        if st & I_DIRTY_ALL == 0 { return Ok(()); }
        if datasync && st & I_DIRTY_DATASYNC == 0 { return Ok(()); }
        match inode.i_sb() {
            Some(sb) => sb.writeback_single_inode(inode, true, crate::inode_times::realtime_now_ns()),
            None     => Ok(()),
        }
    }

    /// `vfs_fsync(file, datasync)` = the whole file.
    /// # C: O(N_dirty)
    pub fn vfs_fsync(&self, datasync: bool) -> KResult<()> {
        self.vfs_fsync_range(0, SYNC_TO_EOF, datasync)
    }

    /// `generic_write_sync(iocb, count)` — the step that makes
    /// `O_SYNC`/`O_DSYNC`/`RWF_SYNC`/`RWF_DSYNC` mean anything.
    ///
    /// Called at the tail of every successful write with `end_pos` = the file
    /// offset just past the bytes written (the iocb's file position, already
    /// advanced) and `count` = how many bytes those were. Syncs exactly
    /// `[ki_pos - count, ki_pos - 1]` rather than the whole file, so an
    /// `O_SYNC` append to a huge log does not rewrite the log.
    ///
    /// `extra` folds in the per-operation `RWF_*` bits; pass
    /// `SyncMode::default()` for the plain write paths.
    ///
    /// Non-filesystem descriptions are skipped: Linux never reaches
    /// `generic_write_sync` from `pipe_write`/`sock_sendmsg`, so an `O_SYNC`
    /// pipe must not start returning `EINVAL` from `write(2)`.
    ///
    /// The Linux return convention is preserved by the caller: on error the
    /// write reports `-errno`, NOT the byte count, because a synchronous write
    /// that could not be made durable did not do what was asked.
    /// # C: O(N_dirty in range) when syncing, O(1) otherwise
    pub fn generic_write_sync(&self, end_pos: u64, count: usize, extra: SyncMode) -> KResult<()> {
        let mode = iocb_sync_mode(self).union(extra);
        if !mode.dsync { return Ok(()); }
        if !fsync_slot_present(self.inode().file_type()) { return Ok(()); }
        if count == 0 { return Ok(()); }
        let start = end_pos.saturating_sub(count as u64);
        self.vfs_fsync_range(start, end_pos.saturating_sub(1), mode.datasync())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `O_SYNC` is strictly stronger than `O_DSYNC`: it is the one that yields
    /// `datasync == false`. Inverting this is a
    /// silent downgrade of the stronger flag.
    /// # C: O(1)
    #[test]
    fn sync_is_stronger_than_dsync() {
        let dsync_only = SyncMode { dsync: true, sync: false };
        let full_sync  = SyncMode { dsync: true, sync: true };
        assert!(dsync_only.datasync(), "O_DSYNC → fdatasync semantics");
        assert!(!full_sync.datasync(), "O_SYNC → full fsync semantics");
    }

    /// `RWF_SYNC` on a plain fd must upgrade the operation, and it must not be
    /// possible for the union to LOSE sync-ness that either side had.
    /// # C: O(1)
    #[test]
    fn union_only_strengthens() {
        let none = SyncMode::default();
        let d = SyncMode { dsync: true, sync: false };
        let s = SyncMode { dsync: true, sync: true };
        assert_eq!(none.union(none), none);
        assert_eq!(none.union(d), d);
        assert_eq!(d.union(none), d);
        assert_eq!(d.union(s), s, "RWF_SYNC on an O_DSYNC fd is a full sync");
        assert_eq!(s.union(d), s, "RWF_DSYNC must not weaken an O_SYNC fd");
        for a in [none, d, s] {
            for b in [none, d, s] {
                let u = a.union(b);
                assert!(u.dsync >= a.dsync && u.dsync >= b.dsync);
                assert!(u.sync >= a.sync && u.sync >= b.sync);
            }
        }
    }

    /// The `fsync` slot exists exactly for the byte-addressable file types.
    /// This one predicate answers both "is `fsync(2)` legal" and "is this a
    /// filesystem write path `generic_write_sync` applies to" — an `O_SYNC`
    /// pipe must keep working, not start returning `EINVAL` from `write`.
    /// # C: O(1)
    #[test]
    fn fsync_slot_only_for_byte_addressable_types() {
        assert!(fsync_slot_present(FileType::Regular));
        assert!(fsync_slot_present(FileType::Directory));
        assert!(fsync_slot_present(FileType::BlockDev));
        assert!(!fsync_slot_present(FileType::Fifo));
        assert!(!fsync_slot_present(FileType::Socket));
        assert!(!fsync_slot_present(FileType::CharDev));
        assert!(!fsync_slot_present(FileType::Symlink));
    }

    /// `SYNC_TO_EOF` is the signed `loff_t` maximum, not `u64::MAX` —
    /// the range arithmetic is signed `loff_t` on the kernel side.
    /// # C: O(1)
    #[test]
    fn sync_to_eof_is_llong_max() {
        assert_eq!(SYNC_TO_EOF, i64::MAX as u64);
    }
}
