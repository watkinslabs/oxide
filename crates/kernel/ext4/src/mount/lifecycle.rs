use crate::mount::{Mount, MountError};
use crate::superblock::{
    EXT4_ERROR_FS, EXT4_VALID_FS, INCOMPAT_RECOVER, SB_OFF_FEATURE_INCOMPAT, SB_OFF_MNT_COUNT,
    SB_OFF_MTIME, SB_OFF_STATE, SB_OFF_WTIME, SUPERBLOCK_LEN, SUPERBLOCK_OFFSET,
};

/// Rewrite `s_state` (preserving `EXT4_ERROR_FS`) plus, optionally, the mount
/// count and the two timestamps, then re-stamp the superblock checksum and
/// write block 0 back (journaled). `now_secs` = wall clock in seconds since the
/// epoch (0 pre-timesync — matches Linux writing an unset RTC). # C: O(SB rw)
impl Mount {
    fn write_state(&self, set_valid: bool, bump_mnt: bool, now_secs: u32)
        -> Result<(), MountError>
    {
        self.run_journaled(|m| {
            let mut sb = m.read_meta_byte_range(SUPERBLOCK_OFFSET, SUPERBLOCK_LEN)?;
            let cur = u16::from_le_bytes([sb[SB_OFF_STATE], sb[SB_OFF_STATE + 1]]);
            // Keep EXT4_ERROR_FS; flip only the clean/dirty bit.
            let keep = cur & EXT4_ERROR_FS;
            let state = if set_valid { keep | EXT4_VALID_FS } else { keep };
            sb[SB_OFF_STATE..SB_OFF_STATE + 2].copy_from_slice(&state.to_le_bytes());
            // A journalled fs additionally advertises "needs recovery" for the
            // whole rw-mounted window: without it a crashed fs is re-mounted with
            // its committed-but-not-checkpointed transactions skipped, and the
            // journal is a write-ahead log nothing ever reads. The clean unmount
            // stamp clears it again.
            if m.sb.journal_inum != 0 {
                let cur_incompat = u32::from_le_bytes([
                    sb[SB_OFF_FEATURE_INCOMPAT],     sb[SB_OFF_FEATURE_INCOMPAT + 1],
                    sb[SB_OFF_FEATURE_INCOMPAT + 2], sb[SB_OFF_FEATURE_INCOMPAT + 3]]);
                let incompat = if set_valid { cur_incompat & !INCOMPAT_RECOVER }
                               else         { cur_incompat |  INCOMPAT_RECOVER };
                sb[SB_OFF_FEATURE_INCOMPAT..SB_OFF_FEATURE_INCOMPAT + 4]
                    .copy_from_slice(&incompat.to_le_bytes());
            }
            if bump_mnt {
                let mc = u16::from_le_bytes([sb[SB_OFF_MNT_COUNT], sb[SB_OFF_MNT_COUNT + 1]]);
                sb[SB_OFF_MNT_COUNT..SB_OFF_MNT_COUNT + 2]
                    .copy_from_slice(&mc.saturating_add(1).to_le_bytes());
                sb[SB_OFF_MTIME..SB_OFF_MTIME + 4].copy_from_slice(&now_secs.to_le_bytes());
            }
            sb[SB_OFF_WTIME..SB_OFF_WTIME + 4].copy_from_slice(&now_secs.to_le_bytes());
            crate::csum::stamp_superblock_csum(&m.sb, &mut sb);
            m.metadata_write(SUPERBLOCK_OFFSET, &sb)
        })
    }

    /// Mount-time superblock stamp (Linux `ext4_setup_super` for a rw mount):
    /// clear `EXT4_VALID_FS` so a crash before a clean unmount leaves the fs
    /// flagged "not cleanly unmounted" (e2fsck then forces a check), set
    /// `INCOMPAT_RECOVER` when the fs carries a journal so the next mount (or
    /// e2fsck) replays it, bump `s_mnt_count`, and record `s_mtime`.
    /// # C: O(SB rw)
    pub fn mark_state_dirty(&self) -> Result<(), MountError> {
        self.write_state(false, true, now_secs())
    }

    /// Unmount-time superblock stamp (Linux `ext4_put_super`): restore
    /// `EXT4_VALID_FS`, clear `INCOMPAT_RECOVER` (the journal has been
    /// checkpointed) and record `s_wtime`. Best-effort — a failing device on
    /// teardown must not panic. # C: O(SB rw)
    pub fn mark_state_clean(&self) -> Result<(), MountError> {
        self.write_state(true, false, now_secs())
    }
}

/// Wall-clock seconds since the Unix epoch via the VFS-installed provider, or 0
/// when unset (early boot, pre-timesync). # C: O(1)
fn now_secs() -> u32 {
    (vfs::inode_times::realtime_now_ns() / 1_000_000_000) as u32
}
