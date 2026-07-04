use core::sync::atomic::Ordering;
use crate::types::KResult;
use super::{SuperBlock, SB_ACTIVE, SB_FREEZE_COMPLETE, SB_FREEZE_FS, SB_FREEZE_PAGEFAULT, SB_FREEZE_WRITE, SB_UNFROZEN};

impl SuperBlock {
    /// `s_op->sync_fs` one pass (Linux `__sync_filesystem` inner call).
    /// # C: O(dirty)
    pub fn sync_fs(&self, wait: bool) -> KResult<()> { self.s_op.sync_fs(wait) }

    /// `sync_filesystem` (Linux fs/sync.c): flush this superblock's dirty state
    /// to the backend in the canonical two-phase order — an async kick
    /// (`sync_fs(wait=0)`, Linux `writeback_inodes_sb` + `sync_fs(0)`) followed by
    /// the blocking pass (`sync_fs(wait=1)`, Linux `sync_inodes_sb` + `sync_fs(1)`)
    /// that waits for the queued writeback to reach stable storage. A read-only
    /// superblock has nothing to flush (Linux `if (sb_rdonly(sb)) return 0`), so
    /// the call short-circuits `Ok`. An async-pass error aborts before the wait
    /// pass (Linux returns the first error). Run by `generic_shutdown_super`
    /// before `put_super` and by `freeze_super`/`sync(2)`. # C: O(dirty)
    pub fn sync_filesystem(&self) -> KResult<()> {
        if self.is_readonly() { return Ok(()); }
        self.sync_fs(false)?;
        self.sync_fs(true)?;
        self.wb_writeback(); // wait pass cleaned the inodes → clear I_DIRTY + unpin
        Ok(())
    }

    /// Current `s_writers.frozen` level (`SB_UNFROZEN`..`SB_FREEZE_COMPLETE`).
    /// # C: O(1)
    pub fn sb_freeze_level(&self) -> u32 { self.s_writers_frozen.load(Ordering::Acquire) }

    /// True iff a freeze is in progress or complete (no writers admitted).
    /// # C: O(1)
    pub fn is_frozen(&self) -> bool { self.sb_freeze_level() != SB_UNFROZEN }

    /// `sb_start_write` (trylock variant, Linux `__sb_start_write_trylock`):
    /// admit a write(2)/page-fault writer iff the sb is both writable and
    /// unfrozen. On success the caller MUST pair with [`sb_end_write`]. Returns
    /// `false` if `SB_RDONLY` (Linux `mnt_want_write` → `-EROFS`) or frozen so
    /// the syscall layer can fail `EROFS`/block-retry. The post-increment
    /// re-check mirrors the percpu_rwsem reader/writer barrier: a freeze racing
    /// in between backs the writer out so `freeze_super` never proceeds with a
    /// leaked writer. # C: O(1)
    pub fn sb_start_write(&self) -> bool {
        if self.is_readonly() { return false; }
        if self.is_frozen() { return false; }
        self.s_writers_count.fetch_add(1, Ordering::AcqRel);
        if self.is_frozen() {
            self.s_writers_count.fetch_sub(1, Ordering::AcqRel);
            return false;
        }
        true
    }

    /// `sb_end_write`: release a writer admitted by [`sb_start_write`].
    /// # C: O(1)
    pub fn sb_end_write(&self) { self.s_writers_count.fetch_sub(1, Ordering::AcqRel); }

    /// Live `sb_start_write` holder count (the freeze drain target). # C: O(1)
    pub fn sb_writers(&self) -> u32 { self.s_writers_count.load(Ordering::Acquire) }

    /// `freeze_super` (Linux fs/super.c): quiesce the fs for a consistent
    /// snapshot. Ratchets UNFROZEN → WRITE (block new writers) → sync → FS
    /// (`s_op->freeze_fs`) → COMPLETE. `Ebusy` if already frozen. On a
    /// `freeze_fs` error the level is unwound to UNFROZEN (writers resume).
    /// The caller is responsible for draining in-flight writers (the level
    /// gate stops NEW ones; existing holders drop on their syscall return).
    /// # C: O(dirty)
    pub fn freeze_super(&self) -> KResult<()> {
        if self.s_writers_frozen.compare_exchange(
            SB_UNFROZEN, SB_FREEZE_WRITE, Ordering::AcqRel, Ordering::Acquire).is_err() {
            return Err(crate::types::VfsError::Ebusy);
        }
        // New writers now rejected; flush dirty state before sealing on-disk.
        self.s_writers_frozen.store(SB_FREEZE_PAGEFAULT, Ordering::Release);
        if let Err(e) = self.sync_fs(true) {
            self.s_writers_frozen.store(SB_UNFROZEN, Ordering::Release);
            return Err(e);
        }
        self.s_writers_frozen.store(SB_FREEZE_FS, Ordering::Release);
        match self.s_op.freeze_fs() {
            Ok(()) => { self.s_writers_frozen.store(SB_FREEZE_COMPLETE, Ordering::Release); Ok(()) }
            Err(e) => { self.s_writers_frozen.store(SB_UNFROZEN, Ordering::Release); Err(e) }
        }
    }

    /// `thaw_super` (Linux fs/super.c): resume after a freeze. `s_op->thaw_fs`
    /// then drop the level back to UNFROZEN (writers re-admitted). `Einval` if
    /// not frozen. # C: O(1)
    pub fn thaw_super(&self) -> KResult<()> {
        if !self.is_frozen() { return Err(crate::types::VfsError::Einval); }
        self.s_op.thaw_fs()?;
        self.s_writers_frozen.store(SB_UNFROZEN, Ordering::Release);
        Ok(())
    }

    /// `generic_shutdown_super` (Linux fs/super.c): the last-`s_active`-drop
    /// teardown sequence. Flush dirty state (`sync_filesystem`), clear the live
    /// `SB_ACTIVE` flag bit so no operation treats the instance as mounted from
    /// here on (Linux `sb->s_flags &= ~SB_ACTIVE`), `evict_inodes` the now-idle
    /// inode cache, then run `put_super` (backend teardown + drop root dentry +
    /// clear icache). Returns the busy-inode count `evict_inodes` found — `0` on
    /// a clean unmount, nonzero is the "Busy inodes after unmount" leak the
    /// caller may WARN on. Invoked once by the final [`Self::deactivate_super`].
    /// # C: O(tree + N_ino)
    pub fn generic_shutdown_super(&self) -> u32 {
        let _ = self.sync_filesystem();
        self.set_s_flags(0, SB_ACTIVE);
        let busy = self.evict_inodes();
        self.put_super();
        busy
    }

    /// Umount teardown: `put_super` then drop the dentry tree. # C: O(tree)
    pub fn put_super(&self) {
        self.s_op.put_super();
        *self.s_root.write() = None;
        self.icache.lock().clear();
    }
}
