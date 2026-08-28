use alloc::vec::Vec;
use crate::gdt;
use crate::superblock::{SUPERBLOCK_LEN, SUPERBLOCK_OFFSET, Superblock};
use super::gdt_byte_offset_for;
use super::super::{Mount, MountError, MountState};
use super::super::io::read_byte_range;

impl Mount {
    /// Open the filesystem on `dev`. Reads + parses the
    /// superblock + group descriptor table.
    /// # C: O(N_groups * desc_size + 1024)
    pub fn open(dev: alloc::sync::Arc<dyn block::BlockDevice>) -> Result<Self, MountError> {
        Self::open_with_orphan_cleanup(dev, true)
    }

    /// Open the filesystem, optionally deferring orphan cleanup to the caller.
    /// # C: O(N_groups * desc_size + 1024)
    pub(crate) fn open_with_orphan_cleanup(dev: alloc::sync::Arc<dyn block::BlockDevice>, cleanup_orphans: bool) -> Result<Self, MountError> {
        let behaviour = Self::behaviour_from_device(&*dev)?;
        Self::open_with_behaviour(dev, cleanup_orphans, behaviour)
    }

    /// Read the on-disk ext4 error policy which supplies the default behaviour
    /// for this mount.  Linux's `ext4_fill_super()` seeds `s_mount_opt` from
    /// `es->s_errors` before it parses an explicit `errors=` override.
    ///
    /// Kept as a small pre-parse helper because options such as `noload` must
    /// be parsed before the full open/journal-recovery phase.  The full open
    /// parses and validates the same superblock again as its normal first step.
    /// # C: O(1024-byte read)
    pub(crate) fn behaviour_from_device(dev: &dyn block::BlockDevice)
        -> Result<crate::mount_opts::Ext4Behaviour, MountError>
    {
        let sb_bytes = read_byte_range(dev, SUPERBLOCK_OFFSET, SUPERBLOCK_LEN)?;
        let sb = Superblock::parse(&sb_bytes)?;
        Ok(crate::mount_opts::Ext4Behaviour::for_sb_errors(sb.errors))
    }

    /// Open the filesystem with its behavioural options ALREADY decided.
    ///
    /// The options have to arrive before the open rather than after it: journal
    /// replay happens in here, and `noload`/`norecovery` is the option that
    /// says not to do it. An open that parsed its options afterwards had
    /// already replayed the log by the time it read the option asking it not
    /// to, which is why the option is passed in rather than looked up.
    /// # C: O(N_groups * desc_size + 1024)
    // Linux keeps the mount construction phase out of its caller's stack
    // frame; this path builds the complete per-mount state and journal view.
    #[inline(never)]
    pub(crate) fn open_with_behaviour(
        dev: alloc::sync::Arc<dyn block::BlockDevice>,
        cleanup_orphans: bool,
        behaviour: crate::mount_opts::Ext4Behaviour,
    ) -> Result<Self, MountError> {
        let sb_bytes = read_byte_range(&*dev, SUPERBLOCK_OFFSET, SUPERBLOCK_LEN)?;
        let sb = Superblock::parse(&sb_bytes)?;
        // Feature gating (Linux EXT4_FEATURE_{INCOMPAT,RO_COMPAT}_SUPP): refuse a
        // fs whose INCOMPAT bits we don't implement (layout would be misread) or
        // whose RO_COMPAT bits we can't safely write (no RO-mount path yet).
        // Catches bigalloc/meta_bg/inline_data/encrypt/… instead of silently
        // misinterpreting them.
        if (sb.feature_incompat & !crate::superblock::SUPPORTED_INCOMPAT) != 0
            || (sb.feature_ro_compat & !crate::superblock::SUPPORTED_RO_COMPAT) != 0
        {
            return Err(MountError::UnsupportedFeature);
        }
        // ext4 casefold stores a compact encoding selector in the
        // superblock. This tree ships the same UTF-8 table used by VFS; an
        // unknown selector cannot safely participate in folded lookup.
        if sb.feature_incompat & crate::superblock::INCOMPAT_CASEFOLD != 0
            && sb.encoding != 1
        {
            return Err(MountError::UnsupportedFeature);
        }
        // metadata_csum verify on mount: refuse a superblock whose stored
        // s_checksum does not match (Linux ext4_superblock_csum_verify → EFSBADCRC).
        // No-op without metadata_csum.
        if !crate::csum::verify_superblock_csum(&sb, &sb_bytes) {
            super::super::first_csum_failure(b"superblock", SUPERBLOCK_OFFSET, 0);
            return Err(MountError::BadChecksum);
        }
        let groups = sb.group_count() as usize;
        let dsize = gdt::desc_size_for(&sb) as usize;
        let gdt_byte_offset = gdt_byte_offset_for(&sb);
        let gdt_len = groups * dsize;
        let gdt_buf = read_byte_range(&*dev, gdt_byte_offset, gdt_len)?;
        // Verify every group descriptor's bg_checksum (Linux
        // ext4_group_desc_csum_verify). A corrupt GDT slot is refused rather
        // than misinterpreted (wrong bitmap/inode-table blocks).
        if sb.has_metadata_csum() {
            for n in 0..groups {
                let off = n * dsize;
                if off + dsize > gdt_buf.len()
                    || !crate::csum::verify_group_desc_csum(&sb, n as u32, &gdt_buf[off..off + dsize]) {
                    super::super::first_csum_failure(b"group-desc", n as u64, gdt_byte_offset + off as u64);
                    return Err(MountError::BadChecksum);
                }
            }
        }
        let system_zones = super::super::validity::build_system_zones(&sb, &gdt_buf);
        let state = MountState {
            gdt_buf,
            sb_free_blocks: sb.free_blocks_count,
            sb_free_inodes: sb.free_inodes_count,
            shadow: None,
            pending_checkpoints: Vec::new(),
            journal_cursor: None,
            journal_used: 0,
            metadata_cache: alloc::collections::BTreeMap::new(),
            metadata_order: alloc::collections::VecDeque::new(),
            metadata_epoch: 0,
            metadata_reads: alloc::collections::BTreeMap::new(),
            metadata_prefetches: alloc::collections::BTreeSet::new(),
            block_bitmap_cache: alloc::collections::BTreeMap::new(),
            group_free_order: alloc::collections::BTreeMap::new(),
            group_free_order_index: alloc::collections::BTreeMap::new(),
            group_avg_fragment_order: alloc::collections::BTreeMap::new(),
            group_avg_fragment_index: alloc::collections::BTreeMap::new(),
            group_prealloc: alloc::collections::BTreeMap::new(),
            stream_last_groups: alloc::collections::BTreeMap::new(),
            inode_prealloc: alloc::collections::BTreeMap::new(),
            batch: false,
            undo: Vec::new(),
            next_generation: 0,
            running_generation: 0,
            committed_generation: 0,
            barrier_generation: 0,
            inode_generations: alloc::collections::BTreeMap::new(),
        };
        let err = sync::Spinlock::new(crate::errstat::ErrRecord::parse(&sb_bytes));
        let mut m = Self { dev, self_ref: sync::Spinlock::new(alloc::sync::Weak::new()), sb, system_zones, state: sync::Spinlock::new(state), quota_sb: sync::Spinlock::new(alloc::sync::Weak::new()), err,
                       #[cfg(not(target_os = "oxide-kernel"))]
                       faults: super::super::faults::HostedFaults::new(),
                       txn_owner: ::core::sync::atomic::AtomicU64::new(0),
                       txn_depth: ::core::sync::atomic::AtomicU32::new(0),
                       txn_wait: sched::live::WaitList::new(),
                       committing_batch: ::core::sync::atomic::AtomicBool::new(false),
                       batch_full: ::core::sync::atomic::AtomicBool::new(false),
                       batch_wait: sched::live::WaitList::new(),
                       creating: ::core::sync::atomic::AtomicBool::new(false),
                       opts: sync::Spinlock::new(crate::mount_opts::Ext4SbOpts {
                           behaviour, ..Default::default() }),
                       #[cfg(not(target_os = "oxide-kernel"))]
                       test_cred: sync::Spinlock::new(None) };
        if m.sb.journal_inum != 0 {
            // The advertised journal is a required metadata owner. Ignoring a
            // failed read/map here would omit its blocks from system_zones and
            // allow the allocator to hand journal storage to ordinary data.
            // Linux rejects the mount when the journal inode cannot be loaded.
            let journal = m.read_inode(m.sb.journal_inum)?;
            let runs = m.collect_phys_extents(&journal.i_block)?;
            for run in runs {
                m.system_zones.push((run.phys, run.phys.saturating_add(u64::from(run.len))));
            }
            m.system_zones.sort_unstable_by_key(|zone| zone.0);
        }
        // `noload`/`norecovery` decides this, and it decides it BEFORE the
        // replay rather than after. Every mount this code opens is writable, so
        // a dirty log plus the option is the combination that has no correct
        // answer and is refused here (Linux `ext4_fill_super`).
        let needs_recovery = (m.sb.feature_incompat & crate::superblock::INCOMPAT_RECOVER) != 0
            && m.sb.journal_inum != 0;
        const MOUNTED_READ_ONLY: bool = false;
        match crate::mount_opts::recovery_action(behaviour.noload, MOUNTED_READ_ONLY, needs_recovery) {
            Err(_) => return Err(MountError::UnsupportedFeature),
            Ok(crate::mount_opts::JournalRecovery::Replay) => { m.recover_journal()?; }
            Ok(crate::mount_opts::JournalRecovery::Skip) => {}
        }
        if behaviour.prefetch_block_bitmaps { m.prefetch_block_bitmaps()?; }
        m.configure_journal_checksum()?;
        if cleanup_orphans { let _ = m.orphan_cleanup(); }
        Ok(m)
    }


}
