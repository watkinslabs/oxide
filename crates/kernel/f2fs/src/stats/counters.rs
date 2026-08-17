//! The counters a mount accumulates, and the sites' vocabulary for changing
//! them.
//!
//! Everything here is a running total that only the mount itself can know:
//! how many checkpoints it has written, how many blocks the cleaner moved,
//! how many of its open logs recycled rather than appended. Nothing in this
//! file samples anything — a number that can be recomputed from the volume is
//! not a counter and does not belong here, because a counter that duplicates
//! derivable state is a second source of truth that can disagree with the
//! first.
//!
//! Held by the mount and changed under the mount's own lock, so plain
//! integers rather than atomics: an increment and the read that follows it
//! are already ordered by the lock that both take.
//!
//! Signed rather than unsigned for the paired counts. A decrement without its
//! increment is a defect in the wiring, and the honest report of one is a
//! negative number a reader can see, not a wrap to four billion.

use super::iostat::Iostat;

/// Call kinds a checkpoint or a clean is attributed to.
///
/// The kind is the ABI of two reported figures — the totals line and its
/// background parenthesis — so the two positions are named rather than
/// written as literals at every site.
pub mod call {
    /// A call made by the volume's own ahead-of-demand work.
    pub const BACKGROUND: usize = 0;
    /// A call made because something asked for the result now.
    pub const FOREGROUND: usize = 1;
    /// The slot the demand path reports into, which is the foreground one:
    /// the reported "total" is every call that was not ahead-of-demand.
    pub const TOTAL: usize = FOREGROUND;
    /// How many kinds there are.
    pub const MAX: usize = 2;
}

/// Which area of the volume a metadata block write landed in.
pub mod meta {
    pub const CP: usize = 0;
    pub const NAT: usize = 1;
    pub const SIT: usize = 2;
    pub const SSA: usize = 3;
    pub const MAX: usize = 4;
}

/// Whether a cleaned block was data or a node — the two rows the cleaning
/// report breaks its figures down by.
pub mod gc_of {
    pub const DATA: usize = 0;
    pub const NODE: usize = 1;
    pub const MAX: usize = 2;
}

/// Whether cleaning ran ahead of demand or because space was wanted now.
pub mod gc_when {
    pub const BG: usize = 0;
    pub const FG: usize = 1;
    pub const MAX: usize = 2;
}

/// The policies a clean can run under, in the order the report lists them.
pub mod gc_mode {
    pub const NORMAL: usize = 0;
    pub const IDLE_CB: usize = 1;
    pub const IDLE_GREEDY: usize = 2;
    pub const IDLE_AT: usize = 3;
    pub const URGENT_HIGH: usize = 4;
    pub const URGENT_LOW: usize = 5;
    pub const URGENT_MID: usize = 6;
    pub const MAX: usize = 7;
}

/// Which dirty-inode list an inode is on.
pub mod dirty_of {
    pub const DIR: usize = 0;
    pub const FILE: usize = 1;
    /// Every inode whose stored metadata is dirty, whatever kind it is.
    pub const META: usize = 2;
    pub const DONATE: usize = 3;
    pub const MAX: usize = 4;
}

/// The two extent caches a volume can keep.
pub mod extent_of {
    pub const READ: usize = 0;
    pub const BLOCK_AGE: usize = 1;
    pub const MAX: usize = 2;
}

/// How a log took the block it handed out: appended to the tail of a fresh
/// segment, or reused a hole in a partly-used one.
pub mod alloc_of {
    pub const LFS: usize = 0;
    pub const SSR: usize = 1;
    pub const MAX: usize = 2;
}

/// What a mount has done since it was mounted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Counters {
    /// Live inodes carrying an inline attribute region.
    pub inline_xattr: i64,
    /// Live inodes whose contents are inside the inode.
    pub inline_inode: i64,
    /// Live directories whose entries are inside the inode.
    pub inline_dir: i64,
    /// Live inodes marked compressed.
    pub compr_inode: i64,
    /// Blocks those inodes hold in compressed form.
    pub compr_blocks: i64,
    /// Live inodes a swap area is on.
    pub swapfile_inode: i64,
    /// Files with an atomic write open on them.
    pub atomic_files: i64,
    /// The most that were ever open at once.
    pub max_aw_cnt: i64,
    /// Live inodes whose pages have been donated for reclaim.
    pub donate_files: u32,
    /// Inodes on each dirty list.
    pub ndirty_inode: [u32; dirty_of::MAX],
    /// Quota files this mount has open.
    pub nquota_files: u32,
    /// Checkpoints asked for, by the kind of caller that asked.
    pub cp_call_count: [u32; call::MAX],
    /// Checkpoints actually written.
    pub cp_count: u32,
    /// Metadata blocks written, by the area they landed in.
    pub meta_count: [u32; meta::MAX],
    /// Segments opened, by how the log that opened them takes blocks.
    pub segment_count: [u32; alloc_of::MAX],
    /// Blocks handed out, by the same split.
    pub block_count: [u32; alloc_of::MAX],
    /// Blocks rewritten where they sat rather than moved.
    pub inplace_count: u32,
    /// Cleans asked for, by the kind of caller that asked.
    pub gc_call_count: [u32; call::MAX],
    /// Segments cleaned, by content and by urgency.
    pub gc_segs: [[u32; gc_when::MAX]; gc_of::MAX],
    /// Sections cleaned, by the same split.
    pub gc_secs: [[u32; gc_when::MAX]; gc_of::MAX],
    /// Segments emptied, by the policy that chose them.
    pub gc_reclaimed_segs: [u32; gc_mode::MAX],
    /// Blocks the cleaner moved.
    pub tot_blks: u32,
    pub data_blks: u32,
    pub node_blks: u32,
    pub bg_data_blks: u32,
    pub bg_node_blks: u32,
    /// Ahead-of-demand cleans declined because the device was busy.
    pub io_skip_bggc: u32,
    /// Ahead-of-demand cleans declined for any other reason.
    pub other_skip_bggc: u32,
    /// Blocks moved to make a file contiguous.
    pub defrag_blks: u32,
    /// Extent-cache lookups, and the three ways one can be answered.
    pub total_hit_ext: [u64; extent_of::MAX],
    pub read_hit_rbtree: [u64; extent_of::MAX],
    pub read_hit_cached: [u64; extent_of::MAX],
    /// Lookups answered by the one extent kept on the inode itself.
    pub read_hit_largest: u64,
    /// Data blocks allocated, which is what the age cache ages against.
    pub allocated_data_blocks: u64,
    /// Bytes and requests, by what asked for them.
    pub iostat: Iostat,
}

impl Default for Counters {
    fn default() -> Self { Self::new() }
}

impl Counters {
    /// A mount that has done nothing yet. # C: O(1)
    pub const fn new() -> Self {
        Counters {
            inline_xattr: 0, inline_inode: 0, inline_dir: 0,
            compr_inode: 0, compr_blocks: 0, swapfile_inode: 0,
            atomic_files: 0, max_aw_cnt: 0, donate_files: 0,
            ndirty_inode: [0; dirty_of::MAX], nquota_files: 0,
            cp_call_count: [0; call::MAX], cp_count: 0,
            meta_count: [0; meta::MAX],
            segment_count: [0; alloc_of::MAX], block_count: [0; alloc_of::MAX],
            inplace_count: 0,
            gc_call_count: [0; call::MAX],
            gc_segs: [[0; gc_when::MAX]; gc_of::MAX],
            gc_secs: [[0; gc_when::MAX]; gc_of::MAX],
            gc_reclaimed_segs: [0; gc_mode::MAX],
            tot_blks: 0, data_blks: 0, node_blks: 0,
            bg_data_blks: 0, bg_node_blks: 0,
            io_skip_bggc: 0, other_skip_bggc: 0, defrag_blks: 0,
            total_hit_ext: [0; extent_of::MAX],
            read_hit_rbtree: [0; extent_of::MAX],
            read_hit_cached: [0; extent_of::MAX],
            read_hit_largest: 0, allocated_data_blocks: 0,
            iostat: Iostat::new(),
        }
    }

    /// Count the shapes an inode just brought into memory.
    ///
    /// One call rather than four, because the four are read off the same
    /// stored inode at the same instant and every one of them has to be
    /// undone together when the inode goes. The returned record is what undoes
    /// them: an inode's shape can change while it is live, and decrementing
    /// from the shape it has at eviction would leave whichever counter the
    /// change already adjusted permanently wrong.
    /// # C: O(1)
    pub fn inode_in(&mut self, s: Shape) -> Shape {
        if s.inline_xattr { self.inline_xattr += 1; }
        if s.inline_data { self.inline_inode += 1; }
        if s.inline_dentry { self.inline_dir += 1; }
        if s.compressed { self.compr_inode += 1; self.compr_blocks += s.compr_blocks as i64; }
        s
    }

    /// Undo exactly what `inode_in` counted for this inode. # C: O(1)
    pub fn inode_out(&mut self, s: Shape) {
        if s.inline_xattr { self.inline_xattr -= 1; }
        if s.inline_data { self.inline_inode -= 1; }
        if s.inline_dentry { self.inline_dir -= 1; }
        if s.compressed { self.compr_inode -= 1; self.compr_blocks -= s.compr_blocks as i64; }
    }

    /// An inline attribute region appeared on a live inode. # C: O(1)
    pub fn inc_inline_xattr(&mut self) { self.inline_xattr += 1; }
    /// # C: O(1)
    pub fn dec_inline_xattr(&mut self) { self.inline_xattr -= 1; }
    /// # C: O(1)
    pub fn inc_inline_data(&mut self) { self.inline_inode += 1; }
    /// A live inode's contents moved out of the inode. # C: O(1)
    pub fn dec_inline_data(&mut self) { self.inline_inode -= 1; }
    /// # C: O(1)
    pub fn inc_inline_dentry(&mut self) { self.inline_dir += 1; }
    /// A live directory's entries moved out of the inode. # C: O(1)
    pub fn dec_inline_dentry(&mut self) { self.inline_dir -= 1; }
    /// # C: O(1)
    pub fn inc_compr_inode(&mut self) { self.compr_inode += 1; }
    /// # C: O(1)
    pub fn dec_compr_inode(&mut self) { self.compr_inode -= 1; }
    /// # C: O(1)
    pub fn add_compr_blocks(&mut self, n: u64) { self.compr_blocks += n as i64; }
    /// # C: O(1)
    pub fn sub_compr_blocks(&mut self, n: u64) { self.compr_blocks -= n as i64; }
    /// # C: O(1)
    pub fn inc_swapfile_inode(&mut self) { self.swapfile_inode += 1; }
    /// # C: O(1)
    pub fn dec_swapfile_inode(&mut self) { self.swapfile_inode -= 1; }
    /// # C: O(1)
    pub fn inc_donate_files(&mut self) { self.donate_files += 1; }
    /// # C: O(1)
    pub fn dec_donate_files(&mut self) { self.donate_files = self.donate_files.saturating_sub(1); }

    /// An atomic write opened. The peak is raised here rather than read back
    /// later: the peak is the whole point of the figure and a sample taken at
    /// report time would only ever see the count that survived.
    /// # C: O(1)
    pub fn inc_atomic_inode(&mut self) {
        self.atomic_files += 1;
        if self.atomic_files > self.max_aw_cnt { self.max_aw_cnt = self.atomic_files; }
    }

    /// # C: O(1)
    pub fn dec_atomic_inode(&mut self) { self.atomic_files -= 1; }

    /// # C: O(1)
    pub fn inc_dirty_inode(&mut self, kind: usize) { if kind < dirty_of::MAX { self.ndirty_inode[kind] += 1; } }
    /// # C: O(1)
    pub fn dec_dirty_inode(&mut self, kind: usize) {
        if kind < dirty_of::MAX { self.ndirty_inode[kind] = self.ndirty_inode[kind].saturating_sub(1); }
    }

    /// # C: O(1)
    pub fn inc_cp_call(&mut self, kind: usize) { if kind < call::MAX { self.cp_call_count[kind] += 1; } }
    /// A checkpoint was written, as against merely asked for. # C: O(1)
    pub fn inc_cp_count(&mut self) { self.cp_count += 1; }

    /// A metadata block was written; which area it landed in is decided from
    /// the address, because the writer knows the address and not the area.
    /// # C: O(1)
    pub fn inc_meta_count(&mut self, blkaddr: u32, sit: u32, nat: u32, ssa: u32, main: u32) {
        if let Some(k) = meta_kind(blkaddr, sit, nat, ssa, main) { self.meta_count[k] += 1; }
    }

    /// # C: O(1)
    pub fn inc_seg_type(&mut self, alloc_type: u8) {
        let i = alloc_type as usize;
        if i < alloc_of::MAX { self.segment_count[i] += 1; }
    }

    /// # C: O(1)
    pub fn inc_block_count(&mut self, alloc_type: u8) {
        let i = alloc_type as usize;
        if i < alloc_of::MAX { self.block_count[i] += 1; }
    }

    /// # C: O(1)
    pub fn inc_inplace_blocks(&mut self) { self.inplace_count += 1; }

    /// # C: O(1)
    pub fn inc_gc_call(&mut self, kind: usize) { if kind < call::MAX { self.gc_call_count[kind] += 1; } }
    /// # C: O(1)
    pub fn inc_gc_seg(&mut self, of: usize, when: usize) {
        if of < gc_of::MAX && when < gc_when::MAX { self.gc_segs[of][when] += 1; }
    }
    /// # C: O(1)
    pub fn inc_gc_sec(&mut self, of: usize, when: usize) {
        if of < gc_of::MAX && when < gc_when::MAX { self.gc_secs[of][when] += 1; }
    }
    /// # C: O(1)
    pub fn add_reclaimed_segs(&mut self, mode: usize, n: u32) {
        if mode < gc_mode::MAX { self.gc_reclaimed_segs[mode] += n; }
    }

    /// Data blocks the cleaner moved. The total is raised here rather than
    /// summed at report time so that a block counted in neither row is
    /// visible as a discrepancy instead of vanishing.
    /// # C: O(1)
    pub fn add_gc_data_blks(&mut self, n: u32, when: usize) {
        self.tot_blks += n;
        self.data_blks += n;
        if when == gc_when::BG { self.bg_data_blks += n; }
    }

    /// # C: O(1)
    pub fn add_gc_node_blks(&mut self, n: u32, when: usize) {
        self.tot_blks += n;
        self.node_blks += n;
        if when == gc_when::BG { self.bg_node_blks += n; }
    }

    /// # C: O(1)
    pub fn inc_io_skip_bggc(&mut self) { self.io_skip_bggc += 1; }
    /// # C: O(1)
    pub fn inc_other_skip_bggc(&mut self) { self.other_skip_bggc += 1; }
    /// # C: O(1)
    pub fn add_defrag_blks(&mut self, n: u32) { self.defrag_blks += n; }

    /// # C: O(1)
    pub fn inc_total_hit(&mut self, of: usize) { if of < extent_of::MAX { self.total_hit_ext[of] += 1; } }
    /// # C: O(1)
    pub fn inc_rbtree_hit(&mut self, of: usize) { if of < extent_of::MAX { self.read_hit_rbtree[of] += 1; } }
    /// # C: O(1)
    pub fn inc_cached_hit(&mut self, of: usize) { if of < extent_of::MAX { self.read_hit_cached[of] += 1; } }
    /// # C: O(1)
    pub fn inc_largest_hit(&mut self) { self.read_hit_largest += 1; }
    /// # C: O(1)
    pub fn add_allocated_data_blocks(&mut self, n: u64) { self.allocated_data_blocks += n; }

    /// Lookups answered from either structure, plus the one the inode carries
    /// for the read cache. # C: O(1)
    pub fn hit_total(&self, of: usize) -> u64 {
        let base = self.read_hit_cached[of] + self.read_hit_rbtree[of];
        if of == extent_of::READ { base + self.read_hit_largest } else { base }
    }
}

/// What an inode was counted as when it came into memory.
///
/// Carried by the live inode so eviction can undo exactly what instantiation
/// did, and updated in place by whatever changes the inode's shape — the
/// record is the memory of what was counted, not a second copy of the inode.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Shape {
    pub inline_xattr: bool,
    pub inline_data: bool,
    pub inline_dentry: bool,
    pub compressed: bool,
    pub compr_blocks: u64,
}

impl Shape {
    /// The shape of a stored inode. # C: O(1)
    pub fn of(i: &crate::node::Inode) -> Shape {
        Shape {
            inline_xattr: i.inline_xattr_span().is_some(),
            inline_data: i.inline_data(),
            inline_dentry: i.inline_dentry(),
            compressed: i.compressed(),
            compr_blocks: i.compr_blocks,
        }
    }
}

/// Which area an address falls in, given where each begins.
///
/// The areas are laid out in this order and are contiguous, so an address is
/// classified by the first boundary it is below. An address at or past the
/// main area is not metadata and is counted nowhere.
/// # C: O(1)
pub fn meta_kind(blkaddr: u32, sit: u32, nat: u32, ssa: u32, main: u32) -> Option<usize> {
    if blkaddr < sit { Some(meta::CP) }
    else if blkaddr < nat { Some(meta::SIT) }
    else if blkaddr < ssa { Some(meta::NAT) }
    else if blkaddr < main { Some(meta::SSA) }
    else { None }
}
