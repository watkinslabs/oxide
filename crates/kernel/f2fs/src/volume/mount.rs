//! Bringing a volume up: the superblock, the checkpoint, and the journals.
//!
//! Order is forced by the data. The superblock names where the checkpoint area
//! is; the checkpoint names where its own summary blocks are and how wide the
//! version bitmaps are; the summary blocks hold the journals that override
//! both tables. Nothing later can be read without everything earlier.

use alloc::vec;
use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::checkpoint::{self, Checkpoint, Pack};
use crate::checksum;
use crate::features::{self, Access};
use crate::flags::CP_COMPACT_SUM_FLAG;
use crate::volume::curseg::Curseg;
use crate::opts::Options;
use crate::sb::{self, SuperBlock};
use crate::summary::{self, at, NatJournal, SitJournal};
use crate::uapi::*;

use super::Volume;

impl<S: SectorSource> Volume<S> {
    /// Mount `source` under `opts`, writing only if `want_write` and the
    /// volume both allow it.
    ///
    /// A volume whose features permit only reads mounts READ-ONLY rather than
    /// failing: refusing would leave a user unable to read a filesystem that
    /// is perfectly readable, and the mount reports what it settled on.
    /// # C: O(checkpoint + journal bytes)
    pub fn mount_with(source: S, opts: Options, want_write: bool) -> Result<Self, Errno> {
        Self::mount_devices(source, opts, want_write, &[]).map(|v| *v)
    }

    /// Mount, with what each member device said about its zones.
    ///
    /// `reports` is one entry per member in the superblock's order, `None`
    /// where the member is not a zoned drive; an empty slice is "nothing was
    /// asked", which is the same answer a conventional drive gives and is
    /// what every medium that cannot be asked produces.
    ///
    /// The zone figures are settled HERE rather than left to whoever needs
    /// them, because a volume laid out for zones that cannot find them must
    /// not mount at all — reading it as though the zones were not there
    /// places blocks the drive will refuse.
    /// # C: O(checkpoint + journal bytes)
    #[inline(never)]
    pub fn mount_devices(
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
        let segstate = super::segmap::SegState::at_mount(cp.elapsed_time);
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
        // The armed in-place policy follows the volume's SIZE and the recycling
        // floor the reserve it was formatted with, so both are resolved from
        // the superblock and the checkpoint before either is moved in.
        let place = crate::place::Tunables::at_mount(
            opts.mode == crate::opts::Mode::Lfs,
            sb.segment_count_main,
            cp.rsvd_segment_count.div_ceil(sb.segs_per_sec.max(1)).max(1));
        // On the heap from the moment it exists, and it never has a by-value
        // life: the reference allocates its per-mount info and fills it
        // through the pointer, and a mount that built one by value instead
        // carries a copy of the whole thing in every frame between here and
        // the superblock it ends up in — more than a kernel stack holds.
        let mut vol = alloc::boxed::Box::new(Self {
            source,
            sb,
            sb_raw,
            sbi,
            errrec: core::cell::Cell::new(errrec),
            cp,
            cp_raw,
            nat_bitmap,
            sit_bitmap,
            nat_journal,
            sit_journal,
            inode_seed,
            casefold,
            fscrypt_keys: alloc::collections::BTreeMap::new(),
            opts,
            access,
            writable,
            curseg,
            nat_dirty: alloc::collections::BTreeMap::new(),
            sit: None,
            segstate,
            sit_dirty: alloc::collections::BTreeSet::new(),
            valid_block_count,
            valid_node_count,
            valid_inode_count,
            next_free_nid,
            dirty: false,
            ino_lists: crate::checkpoint::InoLists::new(),
            quota_setup,
            quota_info: [const { None }; MAX_QUOTAS],
            dquot_owners: alloc::collections::BTreeMap::new(),
            dquots: alloc::collections::BTreeMap::new(),
            dq_dirty: alloc::collections::BTreeSet::new(),
            clock: 0,
            recovering: false,
            opens: alloc::collections::BTreeMap::new(),
            orphans: alloc::collections::BTreeSet::new(),
            pending_discard: alloc::vec::Vec::new(),
            verity_cache: core::cell::RefCell::new(crate::verity::info::Cache::new()),
            verity_policy: crate::verity::Policy::new(),
            extents: core::cell::RefCell::new(
                crate::extent::Caches::new(extent_read, extent_age)),
            free_nids: crate::freenid::FreeNids::new(next_free_nid, avail_nids),
            atgc,
            counters: core::cell::RefCell::new(crate::stats::Counters::new()),
            atomic: alloc::collections::BTreeMap::new(),
            ioprio_hint: alloc::collections::BTreeMap::new(),
            // Filed under an inode number one past the last a node id can
            // take, which is where the reference puts the same mapping: no
            // file can collide with it, on any volume.
            compress_cache: crate::compress::cache::Cache::new(compress_cache, max_nid),
            // The volume's own metadata inode and its own area bounds: the
            // format says which inode number that is and where the metadata
            // ends, so nothing here picks either.
            readdir_ra: true,
            meta_cache,
            // Keyed by the file's own inode number and its own page index, so
            // an out-of-place rewrite or a cleaner relocation — both of which
            // move a file's bytes to a different address without changing
            // them — leaves the mapping alone.
            data_cache: crate::filemap::Cache::new(),
            // Filed under the volume's own NODE inode number, which the
            // format reserves and no file can take — where the reference
            // puts the same mapping.
            node_cache: crate::filemap::NodeCache::new(node_ino),
            fault: crate::fault::Info::new(),
            dirty_devs: core::cell::Cell::new(crate::devices::barrier::DirtyDevices::new()),
            dirty_ino_devs: crate::devices::barrier::DirtyInoDevices::new(),
            update_writes: core::cell::RefCell::new(crate::devices::barrier::UpdateWrites::new()),
            devs,
            zoned,
            place,
            bg: None,
            need_ipu: None,
            sync_writeback: false,
        });
        // What the mount asked to have failed, armed before anything reads or
        // writes: a mount that named sites and then replayed a log without
        // them would exercise the healthy path and report the error path
        // covered.
        crate::fault::apply(&vol.fault, &vol.opts.fault);
        // Replay whatever an `fsync` promised since the last checkpoint,
        // before the mount is handed out — nothing may read the volume in the
        // state a crash left it in.
        // A quota file the MOUNT named, rather than the superblock, is an
        // ordinary entry in the volume's root and is resolved by a lookup
        // like any other name — which is why it cannot happen until there is
        // a volume to look it up in. A name that does not resolve leaves its
        // kind unaccounted instead of failing the mount: refusing to mount
        // over a missing quota file leaves nobody able to put one there.
        vol.open_named_quota_files();
        // A mount asked for read-only still finishes a repair a crash left,
        // over a medium that will take the writes. Both halves below write —
        // to the tree and to the quota files that account for it — so the
        // window is opened around BOTH of them and closed on every exit,
        // including the failing one: a mount that returned an error with the
        // read-only still lifted would leave a volume nobody asked to be
        // writable.
        vol.begin_repair_write();
        // Before anything can allocate: a node id still owned by an
        // unreclaimed orphan handed to a new file would give two inodes one
        // number.
        let mut outcome = vol.recover_orphans();
        if outcome.is_ok() {
            vol.recovering = true;
            // A replay is the one change a mount makes that nobody asked for,
            // so what it did is said out loud rather than dropped. The two
            // cases that matter are a chain put back and a chain FOUND AND
            // NOT put back; a mount that came up clean says nothing.
            outcome = vol.recover_at_mount().map(|r| {
                crate::volume::recover::report::emit(
                    crate::volume::recover::report::announce_for(r));
            });
            vol.recovering = false;
        }
        vol.end_repair_write();
        outcome?;
        Ok(vol)
    }

    /// Mount `source` from an option LINE rather than a resolved option set.
    ///
    /// The order is the whole point and is the reference's. The superblock is
    /// read first, the volume's own defaults are derived from it, the line is
    /// parsed on top of those, and the pair is checked. A caller that parsed
    /// the line against a build-wide default instead would mount a read-only
    /// volume with six logs, a zoned volume in adaptive mode, and a small
    /// volume that reports `ENOSPC` with most of the medium free — each of
    /// them silently.
    ///
    /// `hw_support_discard` is the DEVICE's answer and cannot be read from
    /// here: the medium this mounts through exposes reads and writes and
    /// nothing else, deliberately.
    /// # C: O(checkpoint + journal bytes)
    pub fn mount_line(source: S, data: &str, want_write: bool, hw_support_discard: bool)
        -> Result<Self, Errno> {
        let sb = mount_facts(&source, want_write, hw_support_discard)?;
        let (opts, _) = crate::consistency::resolve(&sb, data)?;
        Self::mount_with(source, opts, want_write)
    }

    /// Take a reconfigured option set as this mount's own.
    ///
    /// The option set is read on every allocation, every placement decision
    /// and every `show_options`, so a remount that changed the copy the mount
    /// reports without changing the one it acts on would leave the two
    /// disagreeing with nothing to notice it.
    /// # C: O(1)
    pub fn adopt_options(&mut self, opts: Options) { self.opts = opts; }

    /// Say whether this mount may write from now on.
    ///
    /// Bounded by what the VOLUME permits: a mount cannot be made writable by
    /// asking, only by the volume's own features and the medium allowing it.
    /// # C: O(1)
    pub fn set_writable(&mut self, want: bool) {
        self.writable = want && self.access == Access::ReadWrite && self.source.writable();
    }
}

/// Whether an option set and a volume can both be true, at the point every
/// mount passes through.
///
/// `hw_support_discard` is the DEVICE's answer and is not reachable from a
/// medium that exposes reads and writes only. It is read by one clause, and
/// that clause is gated on the line having NAMED discard — which nothing has
/// here — so the value below cannot change an answer.
/// # C: O(1)
#[inline(never)]
fn check_mount_options(sb: &SuperBlock, opts: &mut Options, writable: bool)
    -> Result<(), Errno> {
    let facts = crate::opts::Facts {
        feature: sb.feature,
        segment_count_main: sb.segment_count_main,
        hw_support_discard: opts.discard,
        mount_ro: !writable,
    };
    // Adjusted in place, over one copy of the set the caller arrived with:
    // the clauses compare the request against what is running, so the two have
    // to be separate values, and returning a third by value put a whole option
    // set in this frame and again in the caller's.
    let cur = opts.clone();
    let mut spec = crate::opts::Spec::default();
    let sbi = crate::consistency::Sbi::at_mount(facts, &cur);
    crate::consistency::check_opt_consistency(&sbi, opts, &mut spec)
}

/// What a volume's shape says about the defaults a mount of it should take.
/// # C: O(2 blocks)
#[inline(never)]
pub fn mount_facts<S: SectorSource>(source: &S, want_write: bool, hw_support_discard: bool)
    -> Result<crate::opts::Facts, Errno> {
    let sb = read_super(source)?;
    Ok(crate::opts::Facts {
        feature: sb.feature,
        segment_count_main: sb.segment_count_main,
        hw_support_discard,
        mount_ro: !want_write || !source.writable(),
    })
}

/// Read whichever superblock copy validates, trying them in order.
///
/// A copy that fails does not fail the mount: that is the whole reason there
/// are two. Only a volume where NEITHER validates is refused, and the error
/// reported is the first copy's, because it is the one a checker will look at.
/// # C: O(2 blocks)
#[inline(never)]
pub fn read_super<S: SectorSource>(source: &S) -> Result<SuperBlock, Errno> {
    let mut first_err = None;
    for block in 0..SUPER_COPIES {
        let mut buf = vec![0u8; BLKSIZE];
        if source.read_sectors(block, &mut buf).is_err() { continue; }
        let Some(raw) = buf.get(SUPER_OFFSET..SUPER_OFFSET + SUPER_SIZE) else { continue };
        let Some(parsed) = sb::parse(raw) else {
            first_err.get_or_insert(Errno::Einval);
            continue;
        };
        match sb::check(&parsed, raw) {
            Ok(()) => return Ok(parsed),
            Err(_) => { first_err.get_or_insert(Errno::Einval); }
        }
    }
    Err(first_err.unwrap_or(Errno::Einval))
}

/// Read both checkpoint packs and keep the newer valid one, with its payload.
/// # C: O(payload blocks)
#[inline(never)]
pub fn read_checkpoint<S: SectorSource>(source: &S, sb: &SuperBlock)
    -> Result<(Checkpoint, Vec<u8>), Errno> {
    let blks = sb.blks_per_seg();
    let first = try_pack(source, sb.cp_blkaddr, blks, Pack::First);
    let second = try_pack(source, sb.cp_blkaddr + blks, blks, Pack::Second);
    let cp = checkpoint::choose(first, second).ok_or(Errno::Einval)?;
    let start = cp.start(sb.cp_blkaddr, blks);
    let head = read_one(source, start)?;
    let mut payload = Vec::new();
    for i in 1..=sb.cp_payload {
        payload.push(read_one(source, start + i)?);
    }
    let raw = checkpoint::joined(&head, &payload);
    Ok((cp, raw))
}

/// One pack, or `None` when it does not validate. # C: O(2 blocks)
#[inline(never)]
fn try_pack<S: SectorSource>(source: &S, start: u32, blks_per_seg: u32, pack: Pack)
    -> Option<Checkpoint> {
    let head = read_one(source, start).ok()?;
    // The tail's position comes from the head, so the head's claim is bounded
    // before it is used as an address.
    let total = le32(&head, CP_PACK_TOTAL_BLOCK_COUNT)?;
    if total > blks_per_seg || total <= CP_PACKS { return None; }
    let tail = read_one(source, start + total - 1).ok()?;
    checkpoint::validate(&head, &tail, blks_per_seg, pack).ok()
}

/// One block, straight off the medium. # C: O(BLKSIZE)
fn read_one<S: SectorSource>(source: &S, addr: u32) -> Result<Vec<u8>, Errno> {
    let mut buf = vec![0u8; BLKSIZE];
    source.read_sectors(u64::from(addr), &mut buf)?;
    Ok(buf)
}

/// The two journals the current checkpoint parked in the summary area.
///
/// Which blocks hold them depends on two checkpoint flags: whether the
/// summaries were written compacted, and whether the node summaries were
/// written at all. Reading the wrong block yields a journal of plausible
/// nonsense whose entries then override correct table entries.
/// # C: O(2 blocks)
#[inline(never)]
pub fn read_journals<S: SectorSource>(source: &S, sb: &SuperBlock, cp: &Checkpoint)
    -> Result<(NatJournal, SitJournal), Errno> {
    let start = cp.start(sb.cp_blkaddr, sb.blks_per_seg());
    if cp.has(CP_COMPACT_SUM_FLAG) {
        let block = read_one(source, start + cp.pack_start_sum)?;
        let nat = summary::nat_journal(&block, at::COMPACT_NAT).ok_or(Errno::Einval)?;
        let sit = summary::sit_journal(&block, at::COMPACT_SIT).ok_or(Errno::Einval)?;
        return Ok((nat, sit));
    }
    let base = if cp.node_summaries_present() { NR_CURSEG_PERSIST_TYPE } else { NR_CURSEG_DATA_TYPE };
    let total = cp.pack_total_block_count;
    let nat_blk = summary::normal_sum_addr(start, total, base, CURSEG_HOT_DATA);
    let sit_blk = summary::normal_sum_addr(start, total, base, CURSEG_COLD_DATA);
    let nat = summary::nat_journal(&read_one(source, nat_blk)?, at::NORMAL).ok_or(Errno::Einval)?;
    let sit = summary::sit_journal(&read_one(source, sit_blk)?, at::NORMAL).ok_or(Errno::Einval)?;
    if nat.len() > NAT_JOURNAL_ENTRIES || sit.len() > SIT_JOURNAL_ENTRIES {
        return Err(Errno::Einval);
    }
    Ok((nat, sit))
}

/// The six open logs, as the checkpoint left them.
///
/// A pack written compactly holds no per-log summary block, so those logs
/// start with an empty entry array; the next checkpoint writes them out in
/// full, which is what the reference does whenever the compact form no longer
/// fits. The segment numbers and offsets come from the checkpoint either way —
/// losing those would make the next write land in a segment already in use.
/// # C: O(6 blocks)
#[inline(never)]
pub fn read_cursegs<S: SectorSource>(source: &S, sb: &SuperBlock, cp: &Checkpoint)
    -> Result<[Curseg; crate::uapi::NR_CURSEG_TYPE], Errno> {
    let start = cp.start(sb.cp_blkaddr, sb.blks_per_seg());
    let compact = cp.has(CP_COMPACT_SUM_FLAG);
    // Only a clean unmount puts the node logs' summaries in the pack. After an
    // ordinary checkpoint they are in the summary area instead, and counting
    // back from the pack's end for them would read past its tail.
    let in_pack =
        if cp.node_summaries_present() { NR_CURSEG_PERSIST_TYPE } else { NR_CURSEG_DATA_TYPE };
    let mut out: [Curseg; crate::uapi::NR_CURSEG_TYPE] =
        core::array::from_fn(|_| Curseg::empty());
    // Only the persisted logs are read back. The pinned log is not in the
    // checkpoint at all — it opens a section on demand and is handed back at
    // the next checkpoint — so reading a segment number for it would read the
    // node array past its end.
    for (log, seg) in out.iter_mut().enumerate().take(NR_CURSEG_PERSIST_TYPE) {
        let (node, i) = crate::volume::curseg::cp_slot(log);
        seg.segno = if node { cp.cur_node_segno[i] } else { cp.cur_data_segno[i] };
        seg.next_blkoff = if node { cp.cur_node_blkoff[i] } else { cp.cur_data_blkoff[i] };
        seg.alloc_type = cp.alloc_type[log];
        if compact && log < NR_CURSEG_DATA_TYPE { continue; }
        let addr = if log < in_pack {
            summary::normal_sum_addr(start, cp.pack_total_block_count, in_pack, log)
        } else if seg.segno != NULL_SEGNO {
            sum_block_addr(sb.ssa_blkaddr, seg.segno)
        } else {
            continue;
        };
        if let Ok(block) = read_one(source, addr) { seg.sum = block; }
    }
    Ok(out)
}

/// What a volume's features permit, without mounting it. # C: O(1)
pub fn probe_access(sb: &SuperBlock) -> Result<Access, features::Refusal> {
    features::access(sb.feature)
}

/// The zone figures for this volume, or `None` when it is not laid out for
/// zones.
///
/// Three refusals live here and each is a wrong-placement bug if skipped: a
/// zoned layout nothing can locate, a zoned drive under a conventional
/// layout, and reports that do not agree with one another.
/// # C: O(zones)
#[inline(never)]
fn zone_geometry(
    sb: &SuperBlock,
    opts: &Options,
    reports: &[Option<crate::zoned::DevZones>],
) -> Result<Option<crate::zoned::Geometry>, Errno> {
    let mounted_zoned = matches!(reports.first(), Some(Some(_)));
    crate::zoned::geom::paths_ok(sb.feature, !sb.devices.is_empty(), mounted_zoned)
        .map_err(|_| Errno::Einval)?;
    let geom = crate::zoned::Geometry::build(sb.feature, reports, u32::from(opts.active_logs))
        .map_err(|_| Errno::Einval)?;
    if !features::has_blkzoned(sb.feature) { return Ok(None); }
    Ok(Some(geom))
}
