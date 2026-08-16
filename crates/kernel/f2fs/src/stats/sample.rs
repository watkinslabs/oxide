//! One instant's picture of a mount, taken fresh for every read.
//!
//! Two kinds of number meet here. A COUNTER is carried by the mount because
//! nothing can recompute it — how many checkpoints were written, how many
//! blocks the cleaner moved. Everything else is DERIVED, recomputed from the
//! live volume at the moment of the read, because the volume already holds
//! the truth and a cached copy of it is a second source that can go stale.
//!
//! The segment walk is the expensive part and is done once, filling the
//! per-log occupancy rows, the dirty and free counts and the bimodality
//! figure from a single pass — the reference makes two passes over the same
//! table for the same numbers, and one pass cannot disagree with itself.

use sectors::SectorSource;
use syscall::errno::Errno;

use crate::uapi::{BLKSIZE, NR_CURSEG_PERSIST_TYPE, NR_CURSEG_TYPE};
use crate::volume::Volume;

use super::counters::{alloc_of, call, dirty_of, extent_of, gc_mode, gc_of, gc_when, meta, Counters};
use super::iostat::Iostat;

/// Percent, as the denominator of a ratio reported as one.
const PERCENT: u64 = 100;

/// The picture. Field names follow the report's own vocabulary because the
/// report is the only consumer and the mapping has to be readable both ways.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct General {
    pub all_area_segs: u32,
    pub sit_area_segs: u32,
    pub nat_area_segs: u32,
    pub ssa_area_segs: u32,
    pub main_area_segs: u32,
    pub main_area_sections: u32,
    pub main_area_zones: u32,

    pub total_count: u64,
    pub rsvd_segs: u32,
    pub overp_segs: u32,
    pub valid_count: u64,
    pub discard_blks: u32,
    pub valid_node_count: u32,
    pub valid_inode_count: u32,
    pub utilization: u64,

    pub free_segs: u32,
    pub free_secs: u32,
    pub prefree_count: u32,
    pub dirty_count: u32,

    pub nats: u32,
    pub dirty_nats: u32,
    pub sits: u32,
    pub dirty_sits: u32,
    pub free_nids: u32,
    pub avail_nids: u32,
    pub alloc_nids: u32,

    pub util_free: i64,
    pub util_valid: i64,
    pub util_invalid: i64,

    pub blkoff: [u32; NR_CURSEG_TYPE],
    pub curseg: [u32; NR_CURSEG_TYPE],
    pub cursec: [u32; NR_CURSEG_TYPE],
    pub curzone: [u32; NR_CURSEG_TYPE],
    pub dirty_seg: [u32; NR_CURSEG_TYPE],
    pub full_seg: [u32; NR_CURSEG_TYPE],
    pub valid_blks: [u32; NR_CURSEG_TYPE],

    /// The squared spread of section occupancy about half-full, scaled so a
    /// volume whose sections are all half-used reads near a hundred. A
    /// log-structured volume wants its sections either full or empty, and
    /// this is the one number that says whether they are.
    pub bimodal: u64,
    /// Mean live blocks across the sections that are neither.
    pub avg_vblocks: u64,

    pub inline_xattr: i64,
    pub inline_inode: i64,
    pub inline_dir: i64,
    pub compr_inode: i64,
    pub compr_blocks: i64,
    pub swapfile_inode: i64,
    pub ndonate_files: u32,
    pub nquota_files: u32,
    pub orphans: u32,
    pub append: u32,
    pub update: u32,
    pub aw_cnt: i64,
    pub max_aw_cnt: i64,

    pub ndirty_dirs: u32,
    pub ndirty_files: u32,
    pub ndirty_all: u32,

    pub cp_call_count: [u32; call::MAX],
    pub cp_count: u32,
    pub meta_count: [u32; meta::MAX],
    pub segment_count: [u32; alloc_of::MAX],
    pub block_count: [u32; alloc_of::MAX],
    pub inplace_count: u32,

    pub gc_call_count: [u32; call::MAX],
    pub gc_segs: [[u32; gc_when::MAX]; gc_of::MAX],
    pub gc_secs: [[u32; gc_when::MAX]; gc_of::MAX],
    pub gc_reclaimed_segs: [u32; gc_mode::MAX],
    pub tot_blks: u32,
    pub data_blks: u32,
    pub node_blks: u32,
    pub bg_data_blks: u32,
    pub bg_node_blks: u32,
    pub io_skip_bggc: u32,
    pub other_skip_bggc: u32,
    pub defrag_blks: u32,

    pub hit_largest: u64,
    pub hit_cached: [u64; extent_of::MAX],
    pub hit_rbtree: [u64; extent_of::MAX],
    pub hit_total: [u64; extent_of::MAX],
    pub total_ext: [u64; extent_of::MAX],
    pub allocated_data_blocks: u64,
    /// What each cache is holding: trees, of which zombies, and nodes.
    pub ext_tree: [u64; extent_of::MAX],
    pub ext_zombie: [u64; extent_of::MAX],
    pub ext_node: [u64; extent_of::MAX],

    pub undiscard_blks: u32,
    pub iostat: Iostat,
    pub mem: super::mem::Footprint,

    /// Whether the mount may write, whether a replay is in progress, and the
    /// flag word the checkpoint on the medium carries — what the header line
    /// and the status list are rendered from.
    pub writable: bool,
    pub recovering: bool,
    pub cp_disabled: bool,
    pub cp_flags: u32,
    pub sbi_flags: u64,
    /// Seconds this volume has been accumulating, as the checkpoint records.
    pub mounted_time: u64,
    /// Which in-place-update policies this mount will use, as a bit set.
    pub ipu_policy: u32,
    /// Whether the mount announces freed blocks to the device.
    pub discard: bool,
    /// Whether a section is more than one segment, which is what makes the
    /// section rows of the cleaning report meaningful.
    pub large_section: bool,
}

/// One pass of the segment table, which is where most of the picture is.
struct Walk {
    dirty_seg: [u32; NR_CURSEG_TYPE],
    full_seg: [u32; NR_CURSEG_TYPE],
    valid_blks: [u32; NR_CURSEG_TYPE],
    dirty_count: u32,
    written: u64,
}

/// # C: O(main segments)
fn walk<S: SectorSource>(v: &Volume<S>) -> Walk {
    let per = v.super_block().blks_per_seg() as u16;
    let n = v.super_block().segment_count_main;
    let mut w = Walk {
        dirty_seg: [0; NR_CURSEG_TYPE], full_seg: [0; NR_CURSEG_TYPE],
        valid_blks: [0; NR_CURSEG_TYPE], dirty_count: 0, written: 0,
    };
    for segno in 0..n {
        let live = v.seg_valid(segno);
        w.written += u64::from(live);
        if live > 0 && live < per && !v.is_current(segno) { w.dirty_count += 1; }
        if live == 0 { continue; }
        let t = v.segments().get(segno as usize).map_or(0, |e| e.seg_type() as usize);
        let t = t.min(NR_CURSEG_PERSIST_TYPE - 1);
        if live >= per { w.full_seg[t] += 1; } else { w.dirty_seg[t] += 1; }
        w.valid_blks[t] += u32::from(live);
    }
    w
}

/// Sections with no live block and no log inside them. # C: O(main segments)
fn free_sections<S: SectorSource>(v: &Volume<S>) -> u32 {
    let per_sec = v.super_block().segs_per_sec.max(1);
    let n = v.super_block().segment_count_main;
    let mut free = 0u32;
    let mut first = 0u32;
    while first < n {
        let last = (first + per_sec).min(n);
        if (first..last).all(|s| v.seg_is_free(s)) { free += 1; }
        first = last;
    }
    free
}

impl General {
    /// Take the picture.
    ///
    /// Takes the counters separately rather than reading them off the volume
    /// so the volume can be borrowed mutably for the table load this needs:
    /// a mount that has never written has never had reason to read the
    /// segment table, and reporting a pristine volume because nothing loaded
    /// it would be a lie the reader could not detect.
    /// # C: O(main segments)
    pub fn sample<S: SectorSource>(v: &mut Volume<S>, c: &Counters) -> Result<General, Errno> {
        v.load_segments()?;
        let w = walk(v);
        let sb = v.super_block();
        let cp = v.checkpoint();
        let per_seg = u64::from(sb.blks_per_seg().max(1));
        let user = cp.user_block_count.max(1);
        let main_area_sections = sb.section_count;
        let secs_per_zone = sb.secs_per_zone.max(1);
        let main_area_segs = sb.segment_count_main;
        let (sit_area_segs, nat_area_segs, ssa_area_segs, all_area_segs) =
            (sb.segment_count_sit, sb.segment_count_nat, sb.segment_count_ssa, sb.segment_count);
        let segs_per_sec = sb.segs_per_sec.max(1);
        let valid_count = v.valid_block_count;
        let free_segs = v.free_segment_count();
        let overp_segs = cp.overprov_segment_count;
        let rsvd_segs = cp.rsvd_segment_count;
        let mounted_time = cp.elapsed_time;
        let cp_flags = cp.flags;
        // Straight off the cache that owns them. The remaining count is the
        // cache's own rather than recomputed here: the cache is what refuses
        // an allocation when it reaches zero, and a second derivation of the
        // same number could report room the allocator would not give.
        let (free_nids, alloc_nids, avail_nids) = v.free_nid_counts();
        let (ext_tree, ext_zombie, ext_node) = v.extent_cache_counts();

        // Halves rather than percents: the distribution bar is drawn in
        // fiftieths so that the three parts fit one line, which is why each
        // share is halved and the invalid share is what the other two leave.
        let free_blks = u64::from(free_segs) * per_seg;
        let ovp_blks = u64::from(overp_segs) * per_seg;
        let free_user = free_blks.saturating_sub(ovp_blks);
        let denom = (user / per_seg).max(1) as i64;
        let util_free = (free_user / per_seg) as i64 * PERCENT as i64 / denom / 2;
        let util_valid = (w.written / per_seg) as i64 * PERCENT as i64 / denom / 2;
        let util_invalid = 50 - util_free - util_valid;

        let mut g = General {
            all_area_segs, sit_area_segs, nat_area_segs, ssa_area_segs, main_area_segs,
            main_area_sections, main_area_zones: main_area_sections / secs_per_zone,
            total_count: user / per_seg,
            rsvd_segs, overp_segs,
            valid_count,
            discard_blks: v.pending_discard.len() as u32,
            valid_node_count: v.valid_node_count,
            valid_inode_count: v.valid_inode_count,
            utilization: valid_count * PERCENT / user,
            free_segs, free_secs: free_sections(v),
            prefree_count: v.prefree_count(),
            dirty_count: w.dirty_count,
            nats: (v.nat_dirty.len() + v.nat_journal.len()) as u32,
            dirty_nats: v.nat_dirty.len() as u32,
            sits: main_area_segs,
            dirty_sits: v.sit_dirty.len() as u32,
            free_nids, avail_nids, alloc_nids,
            util_free, util_valid, util_invalid,
            blkoff: [0; NR_CURSEG_TYPE], curseg: [0; NR_CURSEG_TYPE],
            cursec: [0; NR_CURSEG_TYPE], curzone: [0; NR_CURSEG_TYPE],
            dirty_seg: w.dirty_seg, full_seg: w.full_seg, valid_blks: w.valid_blks,
            bimodal: 0, avg_vblocks: 0,
            inline_xattr: c.inline_xattr, inline_inode: c.inline_inode,
            inline_dir: c.inline_dir, compr_inode: c.compr_inode,
            compr_blocks: c.compr_blocks, swapfile_inode: c.swapfile_inode,
            ndonate_files: c.donate_files,
            nquota_files: c.nquota_files,
            orphans: v.orphans.len() as u32,
            append: c.append_ino, update: c.update_ino,
            aw_cnt: c.atomic_files, max_aw_cnt: c.max_aw_cnt,
            ndirty_dirs: c.ndirty_inode[dirty_of::DIR],
            ndirty_files: c.ndirty_inode[dirty_of::FILE],
            ndirty_all: c.ndirty_inode[dirty_of::META],
            cp_call_count: c.cp_call_count, cp_count: c.cp_count,
            meta_count: c.meta_count,
            segment_count: c.segment_count, block_count: c.block_count,
            inplace_count: c.inplace_count,
            gc_call_count: c.gc_call_count, gc_segs: c.gc_segs, gc_secs: c.gc_secs,
            gc_reclaimed_segs: c.gc_reclaimed_segs,
            tot_blks: c.tot_blks, data_blks: c.data_blks, node_blks: c.node_blks,
            bg_data_blks: c.bg_data_blks, bg_node_blks: c.bg_node_blks,
            io_skip_bggc: c.io_skip_bggc, other_skip_bggc: c.other_skip_bggc,
            defrag_blks: c.defrag_blks,
            hit_largest: c.read_hit_largest,
            hit_cached: c.read_hit_cached, hit_rbtree: c.read_hit_rbtree,
            hit_total: [c.hit_total(extent_of::READ), c.hit_total(extent_of::BLOCK_AGE)],
            total_ext: c.total_hit_ext,
            allocated_data_blocks: c.allocated_data_blocks,
            ext_tree, ext_zombie, ext_node,
            undiscard_blks: v.pending_discard.len() as u32,
            iostat: c.iostat,
            mem: super::mem::Footprint::of(v, c),
            writable: v.writable(),
            recovering: v.recovering,
            cp_disabled: v.options().checkpoint_disabled,
            cp_flags,
            sbi_flags: 0,
            mounted_time,
            ipu_policy: super::policy::ipu_policy(v.options()),
            discard: v.options().discard,
            large_section: segs_per_sec > 1,
        };
        g.sbi_flags = crate::sysfs::status_word(v.is_dirty(), v.recovering, v.writable(),
                                                v.options().checkpoint_disabled, cp_flags);
        for (i, log) in v.logs().iter().enumerate().take(NR_CURSEG_TYPE) {
            g.blkoff[i] = u32::from(log.next_blkoff);
            g.curseg[i] = log.segno;
            g.cursec[i] = log.segno / segs_per_sec;
            g.curzone[i] = g.cursec[i] / secs_per_zone;
        }
        let (bimodal, avg) = super::bimodal::of(v);
        g.bimodal = bimodal;
        g.avg_vblocks = if g.dirty_count == 0 { 0 } else { avg };
        Ok(g)
    }

    /// Blocks that are neither a node nor an inode. # C: O(1)
    pub fn other_nodes(&self) -> u32 { self.valid_node_count.saturating_sub(self.valid_inode_count) }

    /// Blocks holding file contents. # C: O(1)
    pub fn data_blocks(&self) -> u64 { self.valid_count.saturating_sub(u64::from(self.valid_node_count)) }

    /// Segments holding live blocks and not yet dirty, free or held. # C: O(1)
    pub fn valid_segs(&self) -> i64 {
        i64::from(self.main_area_segs) - i64::from(self.dirty_count)
            - i64::from(self.prefree_count) - i64::from(self.free_segs)
    }

    /// The share of lookups a cache answered, in percent. # C: O(1)
    pub fn hit_ratio(&self, of: usize) -> u64 {
        if self.total_ext[of] == 0 { 0 } else { self.hit_total[of] * PERCENT / self.total_ext[of] }
    }

    /// Bytes the mount is holding, in kibibytes — the unit the report uses
    /// because the figures are large and the byte is never the question.
    /// # C: O(1)
    pub fn mem_total_kb(&self) -> u64 { self.mem.total() >> 10 }
}

/// The block size the footprint figures are computed in. # C: O(1)
pub const fn block_bytes() -> u64 { BLKSIZE as u64 }
