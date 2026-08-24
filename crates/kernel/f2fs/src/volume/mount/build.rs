//! Constructing the complete heap-backed per-mount record.

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::checkpoint;
use crate::checksum;
use crate::features::{self, Access};
use crate::opts::Options;
use crate::sb;
use crate::uapi::*;
use crate::volume::Volume;
use crate::volume::segmap::SegState;

use super::{check_mount_options, read_checkpoint, read_cursegs, read_journals, zone_geometry};

impl<S: SectorSource> Volume<S> {
    /// Build the complete in-memory mount record before recovery can inspect
    /// or modify it.  The two phases are deliberately separate calls: once
    /// this returns, the setup locals are gone and recovery works only through
    /// the mounted record's pointer.
    #[inline(never)]
    pub(super) fn mount_devices_prepared(
        source: S,
        opts: Options,
        want_write: bool,
        reports: &[Option<crate::zoned::DevZones>],
    ) -> Result<alloc::boxed::Box<Self>, Errno> {
        let (sb_raw, sb) = crate::sbwrite::read_raw(&source)?;
        let access = sb::sanity::access(&sb).map_err(|_| Errno::Einval)?;
        let devs = crate::devices::DevTable::scan(&sb);
        let zoned = zone_geometry(&sb, &opts, reports)?;
        let writable = want_write && access == Access::ReadWrite && source.writable();
        // Whether the option set and THIS volume can both be true. Every mount
        // reaches here, including the ones handed an already-resolved set, so
        // this is the one place the pair is guaranteed to be checked — a caller
        // that assembled options itself cannot mount a volume that cannot
        // honour them.
        //
        // The spec is empty because nothing here knows what a line NAMED: the
        // clauses that silently correct a named value have already run on the
        // path that parsed one, and with nothing named they are vacuous. What
        // is left is exactly the checks over the resolved set.
        //
        // `mount_ro` is the SETTLED answer rather than the request: a volume
        // whose features permit only reads has already been downgraded above
        // rather than refused, so the read-only clauses read that downgrade.
        let mut opts = opts;
        check_mount_options(&sb, &mut opts, writable)?;
        let (cp, cp_raw) = read_checkpoint(&source, &sb)?;
        // The figures a formatter wrote have to add up before anything acts on
        // them. A volume with no reserve is the one that matters: substituting
        // a floor of one would mount it, report a reserve it does not have,
        // and leave the cleaner with nowhere to move live blocks the first
        // time the volume filled.
        checkpoint::sanity::check(&cp, &sb).map_err(|_| Errno::Einval)?;
        // Seeded from the checkpoint, then owned by the mount: the live flags
        // are what WRITE the checkpoint's, never the other way round, or a
        // clean checkpoint would retire a mark this mount is still raising.
        let mut sbi = crate::sbflags::SbFlags::at_mount(cp.flags);
        // Seeded from the medium, never cleared: the arrays are cumulative,
        // and a mount that started from zero would erase every kind an earlier
        // mount recorded the first time it wrote one of its own.
        let errrec = crate::errrec::ErrorRecord::from_super(sb_raw.bytes());
        if opts.checkpoint_disabled { sbi.disable_checkpoint(false); }
        let payload = sb.cp_payload;
        let nat_bitmap = checkpoint::nat_bitmap(&cp, &cp_raw, payload)
            .ok_or(Errno::Einval)?
            .to_vec();
        let sit_bitmap = checkpoint::sit_bitmap(&cp, &cp_raw, payload)
            .ok_or(Errno::Einval)?
            .to_vec();
        // A checkpoint that marked the quota files for repair suppresses all
        // three kinds: accounting against a file known to be inconsistent
        // writes the inconsistency deeper.
        let quota_setup = crate::quota::types::resolve(&sb.qf_ino, sb.feature, cp.flags, &opts)
            .map_err(|_| Errno::Einval)?;
        let (nat_journal, sit_journal) = read_journals(&source, &sb, &cp)?;
        let curseg = read_cursegs(&source, &sb, &cp)?;
        let inode_seed = checksum::inode_seed(&sb.uuid);
        // Refused above unless it loads, so a folding volume always has one.
        let casefold = if features::has_casefold(sb.feature) {
            crate::casefold::Casefold::load(sb.s_encoding, sb.s_encoding_flags).ok()
        } else {
            None
        };
        let (valid_block_count, valid_node_count, valid_inode_count, next_free_nid) = (
            cp.valid_block_count,
            cp.valid_node_count,
            cp.valid_inode_count,
            cp.next_free_nid.max(RESERVED_NODE_NUM),
        );
        // Read before the checkpoint is moved into the volume: it is the age
        // every segment timestamp this mount writes counts from.
        let segstate = SegState::at_mount(cp.elapsed_time);
        let (extent_read, extent_age) = (opts.extent_cache, opts.age_extent_cache);
        let compress_cache = opts.compress_cache;
        // Ids the table can name, less the ones the format reserves and the
        // ones already in use. Computed here rather than counted later: it is
        // what an allocation is refused against, and a count that started at
        // zero would refuse the first one.
        let max_nid = crate::nat::max_nid(sb.segment_count_nat, sb.blks_per_seg());
        let avail_nids = max_nid.saturating_sub(RESERVED_NODE_NUM)
                                .saturating_sub(valid_node_count);
        // Age-threshold cleaning needs the volume to have ages worth
        // comparing, so the option alone does not turn it on.
        let mut atgc = crate::atgc::Atgc::new();
        atgc.enable_at_mount(opts.atgc, cp.elapsed_time);
        // Built before the superblock is moved into the volume: the mapping's
        // inode number and its area bounds are the format's, so nothing here
        // picks either.
        let meta_cache = crate::checkpoint::cache::Cache::new(
            sb.meta_ino, sb.cp_blkaddr, sb.main_blkaddr);
        let node_ino = sb.node_ino;
        let reclaim_segments =
            crate::volume::gc::collect::default_reclaim_prefree_segments(sb.segment_count_main);
        // The armed in-place policy follows the volume's SIZE and the recycling
        // floor the reserve it was formatted with, so both are resolved from
        // the superblock and the checkpoint before either is moved in.
        let place = crate::place::Tunables::at_mount(
            opts.mode == crate::opts::Mode::Lfs,
            sb.segment_count_main,
            cp.rsvd_segment_count.div_ceil(sb.segs_per_sec.max(1)).max(1));
        // Allocate the per-mount record before initializing it. `Box::new(Self
        // { .. })` only looks heap-backed at the call site — Rust first
        // materializes the whole `Volume` in this frame, which made the
        // constructor a 3.5 KiB stack frame on the mount and recovery path.
        let mut uninit = alloc::boxed::Box::<Self>::new_uninit();
        let dst = uninit.as_mut_ptr();
        // SAFETY: `uninit` is a unique allocation of exactly one `Self`. Each
        // invocation writes a distinct field exactly once; no fallible work
        // remains after this point, and `assume_init` follows only after every
        // field has been initialized.
        macro_rules! init_field {
            ($field:ident: $value:expr) => {
                unsafe { core::ptr::addr_of_mut!((*dst).$field).write($value) };
            };
        }
        let migration_window_granularity = sb.segs_per_sec.max(1);
        let migration_granularity = migration_window_granularity;
        let reserved_pin_section = if features::has_blkzoned(sb.feature) {
            1
        } else {
            cp.rsvd_segment_count.div_ceil(sb.segs_per_sec.max(1))
        };
        let reserved_segments = cp.rsvd_segment_count;
        let allocate_section_hint = sb.section_count;
        init_field!(source: source);
        init_field!(sb: sb);
        init_field!(sb_raw: sb_raw);
        init_field!(sbi: sbi);
        init_field!(errrec: core::cell::Cell::new(errrec));
        init_field!(cp: cp);
        init_field!(cp_raw: cp_raw);
        init_field!(nat_bitmap: nat_bitmap);
        init_field!(sit_bitmap: sit_bitmap);
        init_field!(nat_journal: nat_journal);
        init_field!(sit_journal: sit_journal);
        init_field!(inode_seed: inode_seed);
        init_field!(casefold: casefold);
        init_field!(fscrypt_keys: alloc::collections::BTreeMap::new());
        init_field!(crypt_cache: core::cell::RefCell::new(alloc::collections::BTreeMap::new()));
        init_field!(opts: opts);
        init_field!(access: access);
        init_field!(writable: writable);
        init_field!(curseg: curseg);
        init_field!(nat_dirty: alloc::collections::BTreeMap::new());
        init_field!(nat_cache: core::cell::RefCell::new(alloc::collections::BTreeMap::new()));
        init_field!(nat_lru: core::cell::RefCell::new(alloc::collections::VecDeque::new()));
        init_field!(sit: None);
        init_field!(segstate: segstate);
        init_field!(sit_dirty: alloc::collections::BTreeSet::new());
        init_field!(valid_block_count: valid_block_count);
        init_field!(reserved_segments: reserved_segments);
        init_field!(allocate_section_hint: allocate_section_hint);
        init_field!(allocate_section_policy: crate::volume::zonewp::ALLOCATE_FORWARD_NOHINT);
        init_field!(reserved_blocks: 0);
        init_field!(current_reserved_blocks: 0);
        init_field!(carve_out: false);
        init_field!(peak_atomic_write: 0);
        init_field!(valid_node_count: valid_node_count);
        init_field!(valid_inode_count: valid_inode_count);
        init_field!(next_free_nid: next_free_nid);
        init_field!(dirty: false);
        init_field!(ino_lists: crate::checkpoint::InoLists::new());
        init_field!(quota_setup: quota_setup);
        init_field!(quota_info: [const { None }; MAX_QUOTAS]);
        init_field!(dquot_owners: alloc::collections::BTreeMap::new());
        init_field!(dquots: alloc::collections::BTreeMap::new());
        init_field!(dq_dirty: alloc::collections::BTreeSet::new());
        init_field!(clock: 0);
        init_field!(recovering: false);
        init_field!(orphans: alloc::collections::BTreeSet::new());
        init_field!(pending_discard: alloc::vec::Vec::new());
        init_field!(verity_cache: core::cell::RefCell::new(crate::verity::info::Cache::new()));
        init_field!(verity_policy: crate::verity::Policy::new());
        init_field!(extents: core::cell::RefCell::new(
            crate::extent::Caches::new(extent_read, extent_age)));
        init_field!(free_nids: crate::freenid::FreeNids::new(next_free_nid, avail_nids));
        init_field!(atgc: atgc);
        init_field!(counters: core::cell::RefCell::new(crate::stats::Counters::new()));
        init_field!(gc_segment_mode: crate::stats::counters::gc_mode::NORMAL);
        init_field!(gc_pin_file_threshold: crate::pin::policy::GC_PIN_FILE_THRESHOLD);
        init_field!(reclaim_segments: reclaim_segments);
        init_field!(gc_valid_thresh_ratio: crate::bg::gc::DEF_GC_VALID_THRESH_RATIO);
        init_field!(migration_window_granularity: migration_window_granularity);
        init_field!(migration_granularity: migration_granularity);
        init_field!(dir_level: 0);
        init_field!(seq_file_ra_mul: 2);
        init_field!(max_roll_forward_node_blocks: 0);
        init_field!(rf_node_block_count: 0);
        init_field!(max_io_bytes: 0);
        init_field!(max_fragment_chunk: 4);
        init_field!(max_fragment_hole: 4);
        init_field!(reserved_pin_section: reserved_pin_section);
        init_field!(atomic: alloc::collections::BTreeMap::new());
        init_field!(ioprio_hint: alloc::collections::BTreeMap::new());
        init_field!(compress_cache: crate::compress::cache::Cache::new(compress_cache, max_nid));
        init_field!(readdir_ra: true);
        init_field!(meta_cache: meta_cache);
        init_field!(data_cache: crate::filemap::Cache::new());
        init_field!(node_cache: crate::filemap::NodeCache::new(node_ino));
        init_field!(fault: crate::fault::Info::new());
        init_field!(dirty_devs: core::cell::Cell::new(crate::devices::barrier::DirtyDevices::new()));
        init_field!(dirty_ino_devs: crate::devices::barrier::DirtyInoDevices::new());
        init_field!(update_writes: core::cell::RefCell::new(crate::devices::barrier::UpdateWrites::new()));
        init_field!(devs: devs);
        init_field!(zoned: zoned);
        init_field!(place: place);
        init_field!(bg: None);
        init_field!(need_ipu: None);
        init_field!(deferred_flush: None);
        init_field!(sync_writeback: false);
        // SAFETY: every `Volume` field was written exactly once above.
        let vol = unsafe { uninit.assume_init() };
        Ok(vol)
    }
}
