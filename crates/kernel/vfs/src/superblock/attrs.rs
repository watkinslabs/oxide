extern crate alloc;
use alloc::string::String;
use core::sync::atomic::Ordering;
use crate::timespec::Timespec64;
use crate::types::KResult;
use super::{SuperBlock, SB_ACTIVE, SB_BORN, SB_DIRSYNC, SB_I_NODEV, SB_I_NOEXEC, SB_I_RESTRICTED_VARIANT, SB_I_VERSION, SB_KERNMOUNT, SB_LAZYTIME, SB_MANDLOCK, SB_NOATIME, SB_NODEV, SB_NODIRATIME, SB_NOEXEC, SB_NOSUID, SB_POSIXACL, SB_RDONLY, SB_SYNCHRONOUS};

impl SuperBlock {
    /// `s_flags` snapshot (Linux `sb->s_flags`). # C: O(1)
    pub fn s_flags(&self) -> u64 { self.s_flags.load(Ordering::Acquire) }

    /// Set/clear `s_flags` bits (sb-level remount; `SB_RDONLY` toggle). # C: O(1)
    pub fn set_s_flags(&self, set: u64, clear: u64) {
        let mut cur = self.s_flags.load(Ordering::Acquire);
        loop {
            let new = (cur & !clear) | set;
            match self.s_flags.compare_exchange_weak(cur, new, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => break, Err(v) => cur = v,
            }
        }
    }

    /// `s_iflags` snapshot (Linux `sb->s_iflags`). # C: O(1)
    pub fn s_iflags(&self) -> u64 { self.s_iflags.load(Ordering::Acquire) }

    /// OR bits into `s_iflags` (Linux `fill_super`'s `s->s_iflags |= …`).
    /// Fill-super only: `s_iflags` is never user-settable, which is what lets
    /// `mount_too_revealing` trust it. # C: O(1)
    pub fn set_s_iflags(&self, set: u64) { self.s_iflags.fetch_or(set, Ordering::AcqRel); }

    /// True iff every bit of `flag` is set in `s_iflags`. # C: O(1)
    pub fn sb_has_iflag(&self, flag: u64) -> bool { (self.s_iflags() & flag) == flag }

    /// `SB_I_NOEXEC` — the superblock half of the noexec check: exec always
    /// refuses when this filesystem's superblock has the bit set. # C: O(1)
    pub fn is_sb_i_noexec(&self) -> bool { (self.s_iflags() & SB_I_NOEXEC) != 0 }

    /// `SB_I_NODEV` — the superblock half of the device-open check: device
    /// nodes never function when this filesystem's superblock has the bit set.
    /// # C: O(1)
    pub fn is_sb_i_nodev(&self) -> bool { (self.s_iflags() & SB_I_NODEV) != 0 }

    /// `SB_I_RESTRICTED_VARIANT` — this instance shows only a subset of the
    /// filesystem (procfs sets it for `-o subset=pid`). # C: O(1)
    pub fn is_restricted_variant(&self) -> bool {
        (self.s_iflags() & SB_I_RESTRICTED_VARIANT) != 0
    }

    /// True iff this superblock is mounted read-only (`SB_RDONLY`). # C: O(1)
    pub fn is_readonly(&self) -> bool { (self.s_flags() & SB_RDONLY) != 0 }

    /// `sb_rdonly` — explicit-name alias of
    /// [`Self::is_readonly`] for call sites that read better as the kernel
    /// predicate. # C: O(1)
    pub fn sb_rdonly(&self) -> bool { self.is_readonly() }

    /// True iff `flag` (any `SB_*` bit, e.g. `SB_NOSUID`) is set in `s_flags`.
    /// The generic form behind the named `is_*` predicates. # C: O(1)
    pub fn sb_has_flag(&self, flag: u64) -> bool { (self.s_flags() & flag) != 0 }

    /// `SB_NOSUID` — setuid/setgid bits ignored on this mount (Linux `IS_NOSUID`,
    /// consulted by exec credential elevation). # C: O(1)
    pub fn is_nosuid(&self) -> bool { self.sb_has_flag(SB_NOSUID) }

    /// `SB_NODEV` — device-special files do not function on this mount
    /// (Linux `may_open` rejects opening a dev node). # C: O(1)
    pub fn is_nodev(&self) -> bool { self.sb_has_flag(SB_NODEV) }

    /// `SB_NOEXEC` — no `execve` from this mount (Linux `path_noexec`). # C: O(1)
    pub fn is_noexec(&self) -> bool { self.sb_has_flag(SB_NOEXEC) }

    /// `SB_SYNCHRONOUS` — writes commit synchronously (Linux `IS_SYNC`). # C: O(1)
    pub fn is_synchronous(&self) -> bool { self.sb_has_flag(SB_SYNCHRONOUS) }

    /// `SB_MANDLOCK` — mandatory locking permitted (Linux `IS_MANDLOCK`). # C: O(1)
    pub fn is_mandlock(&self) -> bool { self.sb_has_flag(SB_MANDLOCK) }

    /// `SB_DIRSYNC` — directory updates commit synchronously (Linux `IS_DIRSYNC`).
    /// # C: O(1)
    pub fn is_dirsync(&self) -> bool { self.sb_has_flag(SB_DIRSYNC) }

    /// `SB_NOATIME` — never update access times on this mount (Linux the
    /// `MNT_NOATIME`/`SB_NOATIME` half of `atime_needs_update`). # C: O(1)
    pub fn is_noatime(&self) -> bool { self.sb_has_flag(SB_NOATIME) }

    /// `SB_NODIRATIME` — never update directory access times. # C: O(1)
    pub fn is_nodiratime(&self) -> bool { self.sb_has_flag(SB_NODIRATIME) }

    /// `SB_POSIXACL` — backend honours POSIX ACLs (Linux `IS_POSIXACL`, gates
    /// the `acl`-aware permission path). # C: O(1)
    pub fn is_posixacl(&self) -> bool { self.sb_has_flag(SB_POSIXACL) }

    /// `SB_I_VERSION` — auto-maintain the inode change cookie (Linux
    /// `IS_I_VERSION`, gates `inode_maybe_inc_iversion`). # C: O(1)
    pub fn is_i_version(&self) -> bool { self.sb_has_flag(SB_I_VERSION) }

    /// `SB_LAZYTIME` — defer on-disk timestamp writeback (Linux `IS_LAZYTIME`).
    /// # C: O(1)
    pub fn is_lazytime(&self) -> bool { self.sb_has_flag(SB_LAZYTIME) }

    /// `SB_KERNMOUNT` — internal kernel mount, not user-initiated (Linux
    /// `kern_mount`); excluded from user umount accounting. # C: O(1)
    pub fn is_kernmount(&self) -> bool { self.sb_has_flag(SB_KERNMOUNT) }

    /// `SB_BORN` — `fill_super` has completed; the instance is fully built and
    /// safe to publish (Linux `super_block.SB_BORN`). # C: O(1)
    pub fn is_born(&self) -> bool { self.sb_has_flag(SB_BORN) }

    /// `SB_ACTIVE` — the instance is mounted/live; cleared by
    /// `generic_shutdown_super` at last-umount so no operation treats a tearing-
    /// down SB as mounted (Linux `super_block.SB_ACTIVE`). Distinct from the
    /// `s_active` REFCOUNT ([`Self::s_active`]): this is the published mounted
    /// FLAG. # C: O(1)
    pub fn is_mounted(&self) -> bool { self.sb_has_flag(SB_ACTIVE) }

    /// Flip the `SB_RDONLY` bit (sb-level `remount` RO↔RW toggle, Linux
    /// `reconfigure_super` rewriting `sb->s_flags`). Once set, [`sb_start_write`]
    /// refuses every new writer so a write(2)/page-fault path cannot dirty a
    /// read-only mount. # C: O(1)
    pub fn set_readonly(&self, ro: bool) {
        if ro { self.set_s_flags(SB_RDONLY, 0); } else { self.set_s_flags(0, SB_RDONLY); }
    }

    /// `reconfigure_super` — apply a flag-delta remount to
    /// this LIVE superblock in place, without rebuilding it (`mount(2) MS_REMOUNT`
    /// / `fsconfig(CMD_RECONFIGURE)` sb-flag half). `set`/`clear` are the
    /// `s_flags` bits to add/remove; the proposed result is
    /// `(s_flags & !clear) | set`. When the remount turns the fs READ-ONLY
    /// (RW→RO) the dirty state is flushed FIRST ([`Self::sync_filesystem`], Linux
    /// syncs before sealing RO so no buffered write is lost). The backend hook
    /// `s_op->remount_fs(proposed_flags, data)` then runs and ONLY on its success are
    /// `s_flags` rewritten — a hook error leaves the SB untouched (Linux returns
    /// the error with the old flags intact), so a backend that refuses (e.g.
    /// RW on a fs needing recovery) cleanly aborts. Re-applying the current flags
    /// is idempotent. The per-MOUNT `MNT_*` bits and `fs_context` param parse
    /// live at their own layers ([`crate::fs::reconfigure_super`]); this is the
    /// sb-flag + classic-backend-hook core. `data` is the remount's option
    /// string, which backends with per-mount options (quota files, journal
    /// mode) need in order to reject a change the live filesystem cannot make
    /// — dropping it made every such option silently accepted-and-ignored. # C: O(dirty) on RW→RO, else O(1)
    pub fn reconfigure_super(&self, set: u64, clear: u64, data: &str) -> KResult<()> {
        let cur = self.s_flags();
        let proposed = (cur & !clear) | set;
        let going_ro = (proposed & SB_RDONLY) != 0 && (cur & SB_RDONLY) == 0;
        // Sealing RW→RO evicts every kernel-side writer first (process
        // accounting), so no in-kernel file keeps writing to a filesystem
        // userspace has been told is read-only.
        if going_ro { crate::sb_pin::kill_sb_pins(crate::sb_pin::sb_key_ref(self)); }
        if going_ro { self.sync_filesystem()?; }
        self.s_op.remount_fs(proposed, data)?;
        self.set_s_flags(set, clear);
        Ok(())
    }

    /// `s_active` snapshot — live active references (Linux `s->s_active`).
    /// `0` ⇒ the SB is being / has been torn down. # C: O(1)
    pub fn s_active(&self) -> u32 { self.s_active.load(Ordering::Acquire) }

    /// `s_count` snapshot — existence/lookup references (Linux `s->s_count`).
    /// # C: O(1)
    pub fn s_count(&self) -> u32 { self.s_count.load(Ordering::Acquire) }

    /// Take one extra `s_count` (Linux `grab_super`/`__put_super` pairing).
    /// Bumped by an [`sget`] hit; the matching drop is the SB's own teardown.
    /// # C: O(1)
    pub fn s_count_inc(&self) { self.s_count.fetch_add(1, Ordering::AcqRel); }

    /// `grab_super` (Linux `atomic_inc_not_zero(&s->s_active)`): take one extra
    /// active reference IFF the SB is still live (count != 0). Returns `false`
    /// once teardown has begun so an sget-style lookup never resurrects a dying
    /// instance and callers build a fresh filled superblock instead.
    /// Each `true` MUST be paired with a [`SuperBlock::deactivate_super`].
    /// # C: O(1)
    pub fn grab_active(&self) -> bool {
        let mut cur = self.s_active.load(Ordering::Acquire);
        loop {
            if cur == 0 { return false; }
            match self.s_active.compare_exchange_weak(
                cur, cur + 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return true, Err(v) => cur = v,
            }
        }
    }

    /// `deactivate_super` (Linux `atomic_dec_and_test(&s->s_active)`): drop one
    /// active reference. The LAST drop (1 → 0) runs `generic_shutdown_super`
    /// (`sync_filesystem` then `put_super`, clearing `s_root`+icache) and returns
    /// `true`; a non-last drop returns `false`. Idempotent at 0 (a redundant
    /// deactivate is a no-op returning `false`, never an unsigned underflow), so
    /// the teardown body fires exactly once. # C: O(tree) on last, else O(1)
    pub fn deactivate_super(&self) -> bool {
        let mut cur = self.s_active.load(Ordering::Acquire);
        loop {
            if cur == 0 { return false; }
            match self.s_active.compare_exchange_weak(
                cur, cur - 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => break, Err(v) => cur = v,
            }
        }
        if cur == 1 { let _ = self.generic_shutdown_super(); true } else { false }
    }

    /// `s_maxbytes` — largest representable file size. # C: O(1)
    pub fn s_maxbytes(&self) -> u64 { self.s_maxbytes }

    /// `s_blocksize_bits` (Linux `super_block.s_blocksize_bits`) —
    /// `log2(s_blocksize)`, the shift for byte↔block conversion. Derived from
    /// `s_blocksize` (always a power of two) rather than stored, so it cannot
    /// drift from it. # C: O(1)
    pub fn s_blocksize_bits(&self) -> u32 { self.s_blocksize.trailing_zeros() }

    /// `generic_write_check_limits`, the `s_maxbytes`
    /// half: bound a write of `count` bytes starting at byte offset `pos`
    /// against the largest file size this filesystem can represent.
    /// - `Some(n)` ⇒ the write is admissible; `n` is `count` CLAMPED so
    ///   `pos + n <= s_maxbytes` (a write that would straddle the cap is
    ///   shortened, exactly like Linux clamps `iov_iter` to `max_size - pos`).
    /// - `None` ⇒ `pos >= s_maxbytes`: there is no room at or beyond the cap,
    ///   which the write(2) shim maps to `EFBIG` (+ `SIGXFSZ`). A zero-length
    ///   write short-circuits to `Some(0)` (Linux returns `0` before the cap
    ///   check), so an empty write at the cap is not spuriously rejected.
    /// The per-task `RLIMIT_FSIZE` half of `generic_write_check_limits` lives at
    /// the syscall layer (it needs the caller's rlimits); this is the SB-level
    /// physical-size cap only. # C: O(1)
    pub fn generic_write_check_limits(&self, pos: u64, count: usize) -> Option<usize> {
        if count == 0 { return Some(0); }
        let max = self.s_maxbytes;
        if pos >= max { return None; }
        let room = max - pos; // > 0
        Some(core::cmp::min(count as u64, room) as usize)
    }

    /// True iff a write STARTING at byte offset `pos` must fail `EFBIG` —
    /// `pos >= s_maxbytes`, no representable room remains (Linux the
    /// `pos >= max_size` arm of `generic_write_check_limits`). # C: O(1)
    pub fn write_exceeds_maxbytes(&self, pos: u64) -> bool { pos >= self.s_maxbytes }

    /// `s_uuid` snapshot (Linux `super_block.s_uuid`). All-zero when the fs has
    /// no UUID; pair with [`Self::has_uuid`] to distinguish "no UUID" from the
    /// (legitimate but vanishingly rare) all-zero UUID. # C: O(1)
    pub fn s_uuid(&self) -> [u8; 16] { self.s_uuid.lock().0 }

    /// `s_uuid_len` — the significant byte length of `s_uuid` (`16` for a v4
    /// UUID, `0` when unset). Linux `super_block.s_uuid_len`. # C: O(1)
    pub fn s_uuid_len(&self) -> u8 { self.s_uuid.lock().1 }

    /// True iff a non-empty UUID has been published (`s_uuid_len != 0`). # C: O(1)
    pub fn has_uuid(&self) -> bool { self.s_uuid.lock().1 != 0 }

    /// `s_sysfs_name` snapshot (Linux `super_block.s_sysfs_name`). Empty means
    /// no `/sys/fs/<fstype>/...` programmatic path exists. # C: O(len name)
    pub fn s_sysfs_name(&self) -> String { self.s_sysfs_name.lock().clone() }

    /// True iff a non-empty sysfs handle has been published. # C: O(1)
    pub fn has_sysfs_name(&self) -> bool { !self.s_sysfs_name.lock().is_empty() }

    /// Publish Linux `super_block.s_sysfs_name`. Linux storage is
    /// `UUID_STRING_LEN + 1`; keep at most 36 visible bytes and never synthesize
    /// this from `s_id`. # C: O(len name)
    pub fn set_sysfs_name(&self, name: &str) {
        let mut out = String::new();
        for b in name.bytes().take(36) { out.push(b as char); }
        *self.s_sysfs_name.lock() = out;
    }

    /// Publish the filesystem UUID (Linux `super_set_uuid` / a `fill_super`
    /// writing `sb->s_uuid` from the on-disk superblock). `len` is clamped to
    /// the 16-byte `uuid_t` width; the unused tail is zero-filled so a short
    /// UUID never leaks stale bytes. # C: O(1)
    pub fn set_uuid(&self, uuid: [u8; 16], len: u8) {
        let len = if len > 16 { 16 } else { len };
        let mut g = self.s_uuid.lock();
        g.0 = [0u8; 16];
        g.0[..len as usize].copy_from_slice(&uuid[..len as usize]);
        g.1 = len;
    }

    /// `s_time_gran` — timestamp granularity (ns). # C: O(1)
    pub fn s_time_gran(&self) -> u32 { self.s_time_gran.load(Ordering::Acquire) }

    /// Publish the fs timestamp granularity (Linux `fill_super` writing
    /// `sb->s_time_gran`). A backend that persists coarser-than-ns times calls
    /// this once after fill-super so [`Self::timestamp_truncate`]
    /// floors to it. `0` is normalized to `1` (ns precision) so the truncation
    /// math never divides by zero. # C: O(1)
    pub fn set_time_gran(&self, gran: u32) {
        self.s_time_gran.store(if gran == 0 { 1 } else { gran }, Ordering::Release);
    }

    /// `s_time_min` — earliest representable seconds-since-epoch. # C: O(1)
    pub fn s_time_min(&self) -> i64 { self.s_time_min.load(Ordering::Acquire) }

    /// `s_time_max` — latest representable seconds-since-epoch. # C: O(1)
    pub fn s_time_max(&self) -> i64 { self.s_time_max.load(Ordering::Acquire) }

    /// Publish the fs timestamp range (Linux `fill_super` writing
    /// `sb->s_time_min`/`sb->s_time_max` from the on-disk timestamp field width).
    /// A backend whose epoch window is narrower than `time64_t` calls this once
    /// after fill-super so [`Self::timestamp_truncate`] clamps
    /// out-of-range setattr times. `min > max` is normalized by swapping so the
    /// clamp window is never inverted. # C: O(1)
    pub fn set_time_range(&self, min: i64, max: i64) {
        let (min, max) = if min > max { (max, min) } else { (min, max) };
        self.s_time_min.store(min, Ordering::Release);
        self.s_time_max.store(max, Ordering::Release);
    }

    /// `timestamp_truncate`: clamp a wall-clock timestamp's
    /// SIGNED seconds field to `[s_time_min, s_time_max]`, then floor its
    /// sub-second field to this superblock's `s_time_gran`, so a setattr never
    /// records either an out-of-window instant the backend cannot persist or
    /// sub-granularity precision it cannot express.
    ///
    /// The range rule is a CLAMP, never an error: Linux caps at the filesystem
    /// boundary (`clamp(t.tv_sec, sb->s_time_min, sb->s_time_max)`) and lets the
    /// syscall succeed, which is why `utimensat` has no seconds-range check at
    /// all. A clamp that bites pins to the boundary SECOND with a zeroed
    /// sub-second field, matching Linux's `t.tv_nsec = 0` on the boundary. With
    /// the default [`TIME64_MIN`]/[`TIME64_MAX`] window the clamp is a no-op, so
    /// a pre-epoch time survives it untouched. # C: O(1)
    pub fn timestamp_truncate(&self, t: Timespec64) -> Timespec64 {
        t.clamp_secs(self.s_time_min(), self.s_time_max()).floor_gran(self.s_time_gran())
    }
}
