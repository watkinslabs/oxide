use core::sync::atomic::Ordering;
use crate::types::KResult;
use super::{freeze_wait_hooks, SuperBlock, FREEZE_WAIT_LOCK, SB_ACTIVE, SB_FREEZE_COMPLETE, SB_FREEZE_FS, SB_FREEZE_PAGEFAULT, SB_FREEZE_WRITE, SB_UNFROZEN};

impl SuperBlock {
    /// Hold `s_umount` shared while running `f`. # C: O(f)
    pub fn with_s_umount_read<R>(&self, f: impl FnOnce() -> R) -> R {
        let _g = self.s_umount.read();
        f()
    }

    /// Hold `s_umount` exclusive while running `f`. # C: O(f)
    pub fn with_s_umount_write<R>(&self, f: impl FnOnce() -> R) -> R {
        let _g = self.s_umount.write();
        f()
    }

    /// `s_op->sync_fs` one pass (Linux `__sync_filesystem` inner call).
    /// # C: O(dirty)
    pub fn sync_fs(&self, wait: bool) -> KResult<()> { self.s_op.sync_fs(wait) }

    /// `sync_filesystem`: flush this superblock's dirty state
    /// to the backend in the canonical two-phase order — an async kick
    /// (`sync_fs(wait=0)`, `writeback_inodes_sb` + `sync_fs(0)`) followed by
    /// the blocking pass (`sync_fs(wait=1)`, `sync_inodes_sb` + `sync_fs(1)`)
    /// that waits for the queued writeback to reach stable storage. A read-only
    /// superblock has nothing to flush, so
    /// the call short-circuits `Ok`. An async-pass error aborts before the wait
    /// pass (the first error wins). Run by `generic_shutdown_super`
    /// before `put_super` and by `freeze_super`/`sync(2)`. # C: O(dirty)
    pub fn sync_filesystem(&self) -> KResult<()> {
        if self.is_readonly() { return Ok(()); }
        // Inode metadata goes out BEFORE each `sync_fs`, not after: a backend's
        // `sync_fs` is what makes the preceding writes durable (a journaling fs
        // commits the running transaction), so an inode written after it sits
        // in a transaction nobody committed. Each pass is ordered the same way —
        // `writeback_inodes_sb` then `sync_fs(0)`, `sync_inodes_sb` then
        // `sync_fs(1)`. The second pass is `WB_SYNC_ALL`, which is what forces
        // every deferred lazy timestamp out regardless of its age.
        let now = crate::inode_times::realtime_now_ns();
        self.wb_writeback_pass(false, now)?;
        self.sync_fs(false)?;
        self.wb_writeback_pass(true, now)?;
        self.sync_fs(true)
    }

    /// Current `s_writers.frozen` level (`SB_UNFROZEN`..`SB_FREEZE_COMPLETE`).
    /// # C: O(1)
    pub fn sb_freeze_level(&self) -> u32 { self.s_writers_frozen.load(Ordering::Acquire) }

    /// True iff a freeze is in progress or complete (no writers admitted).
    /// # C: O(1)
    pub fn is_frozen(&self) -> bool { self.sb_freeze_level() != SB_UNFROZEN }

    /// `sb_start_write` (Linux `sb_start_write`): admit a write(2)/page-fault
    /// writer iff the sb is writable, sleeping while `s_writers.frozen` blocks
    /// new writers. On success the caller MUST pair with [`sb_end_write`].
    /// Returns `false` only for `SB_RDONLY` (`mnt_want_write` → `-EROFS`) or if
    /// no scheduler hook exists in hosted/pre-init code. # C: O(1) or sleeps
    pub fn sb_start_write(&self) -> bool {
        loop {
            let _g = FREEZE_WAIT_LOCK.lock();
            if self.is_readonly() { return false; }
            if !self.is_frozen() {
                self.s_writers_count.fetch_add(1, Ordering::AcqRel);
                return true;
            }
            let hooks = freeze_wait_hooks();
            match (hooks.park, hooks.schedule) {
                (Some(park), Some(schedule)) => {
                    park(self.freeze_wait_key());
                    drop(_g);
                    schedule();
                }
                _ => return false,
            }
        }
    }

    /// Wait for a frozen superblock without admitting a writer. # C: O(1) or sleeps
    pub fn wait_until_thawed(&self) -> bool {
        loop {
            let _g = FREEZE_WAIT_LOCK.lock();
            if !self.is_frozen() { return true; }
            let hooks = freeze_wait_hooks();
            match (hooks.park, hooks.schedule) {
                (Some(park), Some(schedule)) => {
                    park(self.freeze_wait_key());
                    drop(_g);
                    schedule();
                }
                _ => return false,
            }
        }
    }

    /// `sb_end_write`: release a writer admitted by [`sb_start_write`].
    /// # C: O(1)
    pub fn sb_end_write(&self) {
        let prev = self.s_writers_count.fetch_sub(1, Ordering::AcqRel);
        if prev == 1 {
            let _g = FREEZE_WAIT_LOCK.lock();
            if self.is_frozen() {
                if let Some(wake) = freeze_wait_hooks().wake {
                    wake(self.freeze_wait_key());
                }
            }
        }
    }

    /// Live `sb_start_write` holder count (the freeze drain target). # C: O(1)
    pub fn sb_writers(&self) -> u32 { self.s_writers_count.load(Ordering::Acquire) }

    /// `freeze_super`: quiesce the fs for a consistent
    /// snapshot. Ratchets UNFROZEN → WRITE (block new writers) → sync → FS
    /// (`s_op->freeze_fs`) → COMPLETE. `Ebusy` if already frozen. On a
    /// `freeze_fs` error the level is unwound to UNFROZEN (writers resume).
    /// The caller is responsible for draining in-flight writers (the level
    /// gate stops NEW ones; existing holders drop on their syscall return).
    /// # C: O(dirty)
    pub fn freeze_super(&self) -> KResult<()> {
        {
            let _g = FREEZE_WAIT_LOCK.lock();
            if self.s_writers_frozen.compare_exchange(
                SB_UNFROZEN, SB_FREEZE_WRITE, Ordering::AcqRel, Ordering::Acquire).is_err() {
                return Err(crate::types::VfsError::Ebusy);
            }
        }
        self.wait_for_writers_drained();
        // New writers now rejected; flush dirty state before sealing on-disk.
        self.s_writers_frozen.store(SB_FREEZE_PAGEFAULT, Ordering::Release);
        if let Err(e) = self.sync_fs(true) {
            self.unfreeze_and_wake();
            return Err(e);
        }
        self.s_writers_frozen.store(SB_FREEZE_FS, Ordering::Release);
        match self.s_op.freeze_fs() {
            Ok(()) => { self.s_writers_frozen.store(SB_FREEZE_COMPLETE, Ordering::Release); Ok(()) }
            Err(e) => { self.unfreeze_and_wake(); Err(e) }
        }
    }

    /// `thaw_super`: resume after a freeze. `s_op->thaw_fs`
    /// then drop the level back to UNFROZEN (writers re-admitted). `Einval` if
    /// not frozen. # C: O(1)
    pub fn thaw_super(&self) -> KResult<()> {
        if !self.is_frozen() { return Err(crate::types::VfsError::Einval); }
        self.s_op.thaw_fs()?;
        self.unfreeze_and_wake();
        Ok(())
    }

    fn unfreeze_and_wake(&self) {
        let _g = FREEZE_WAIT_LOCK.lock();
        self.s_writers_frozen.store(SB_UNFROZEN, Ordering::Release);
        if let Some(wake) = freeze_wait_hooks().wake {
            wake(self.freeze_wait_key());
        }
    }

    fn wait_for_writers_drained(&self) {
        loop {
            let _g = FREEZE_WAIT_LOCK.lock();
            if self.sb_writers() == 0 { return; }
            let hooks = freeze_wait_hooks();
            match (hooks.park, hooks.schedule) {
                (Some(park), Some(schedule)) => {
                    park(self.freeze_wait_key());
                    drop(_g);
                    schedule();
                }
                _ => {
                    drop(_g);
                    core::hint::spin_loop();
                }
            }
        }
    }

    /// Stable key for sched-owned sb-freeze wait queues. # C: O(1)
    fn freeze_wait_key(&self) -> usize {
        self as *const SuperBlock as usize
    }

    /// `generic_shutdown_super`: the last-`s_active`-drop
    /// teardown sequence. Flush dirty state (`sync_filesystem`), clear the live
    /// `SB_ACTIVE` flag bit so no operation treats the instance as mounted from
    /// here on (`sb->s_flags &= ~SB_ACTIVE`), `evict_inodes` the now-idle
    /// inode cache, then run `put_super` (backend teardown + drop root dentry +
    /// clear icache). Returns the busy-inode count `evict_inodes` found — `0` on
    /// a clean unmount, nonzero is the "Busy inodes after unmount" leak the
    /// caller may WARN on. Invoked once by the final [`Self::deactivate_super`].
    /// # C: O(tree + N_ino)
    pub fn generic_shutdown_super(&self) -> u32 {
        let _ = self.sync_filesystem();
        let _ = crate::quota::quota_shutdown(self);
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
