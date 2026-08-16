//! A volume built the way a formatter would.
//!
//! Independent of the reader: the layout here is written from the format's own
//! rules, so a passing test proves the two AGREE rather than that one function
//! is self-consistent. Every structure a real medium carries is present — both
//! superblock copies with their checksums, both checkpoint packs with theirs,
//! the node table in its two copies with the version bitmap that picks one,
//! the segment table, the summary blocks with their journals, and real node
//! and data blocks in the main area.
//!
//! Module manifest:
//! - `meta`:  the superblock, the checkpoint packs and the two tables.
//! - `nodes`: node blocks, inodes, directories and file data.

use alloc::vec;
use alloc::vec::Vec;

use sectors::MemImage;

use crate::flags::*;
use crate::opts::Options;
use crate::summary::NatEntry;
use crate::uapi::*;
use crate::volume::Volume;

#[path = "image/meta.rs"]
pub mod meta;
#[path = "image/nodes.rs"]
pub mod nodes;

/// The geometry every fixture uses. Small, but every area is a real area with
/// a real second copy: shrinking one to nothing would make the copy-selection
/// bugs untestable.
pub const CP_BLKADDR: u32 = 2;
pub const SEG_CKPT: u32 = 2;
pub const SEG_SIT: u32 = 2;
pub const SEG_NAT: u32 = 2;
pub const SEG_SSA: u32 = 1;
pub const SEG_MAIN: u32 = 8;
pub const SIT_BLKADDR: u32 = CP_BLKADDR + SEG_CKPT * BLKS_PER_SEG;
pub const NAT_BLKADDR: u32 = SIT_BLKADDR + SEG_SIT * BLKS_PER_SEG;
pub const SSA_BLKADDR: u32 = NAT_BLKADDR + SEG_NAT * BLKS_PER_SEG;
pub const MAIN_BLKADDR: u32 = SSA_BLKADDR + SEG_SSA * BLKS_PER_SEG;
pub const SEGMENT_COUNT: u32 = SEG_CKPT + SEG_SIT + SEG_NAT + SEG_SSA + SEG_MAIN;
pub const BLOCK_COUNT: u64 = CP_BLKADDR as u64 + (SEGMENT_COUNT as u64 * BLKS_PER_SEG as u64);
/// Blocks the image actually holds: the whole volume, because a write opens
/// segments a fixture never touched and a short image would fail the write
/// rather than the check it was written for.
pub const IMAGE_BLOCKS: u32 = MAIN_BLKADDR + SEG_MAIN * BLKS_PER_SEG;
/// Bytes of each version bitmap: one bit per block of one table copy.
pub const BITMAP_BYTES: u32 = (SEG_SIT / 2) * BLKS_PER_SEG / 8;
/// Blocks one checkpoint pack occupies: a head, six summaries, a tail.
pub const CP_PACK_BLOCKS: u32 = 8;
/// Where the summary blocks begin inside a pack.
pub const PACK_START_SUM: u32 = 1;

/// The three fixed inode numbers.
pub const NODE_INO: u32 = 1;
pub const META_INO: u32 = 2;
pub const ROOT_INO: u32 = 3;
/// The first node id a fixture hands out.
pub const FIRST_NID: u32 = 4;

/// The features a fixture volume carries unless a test says otherwise.
pub const DEFAULT_FEATURE: u32 = FEATURE_EXTRA_ATTR
    | FEATURE_INODE_CHKSUM
    | FEATURE_FLEXIBLE_INLINE_XATTR
    | FEATURE_INODE_CRTIME
    | FEATURE_SB_CHKSUM;

/// A volume under construction.
pub struct Builder {
    pub bytes: Vec<u8>,
    pub feature: u32,
    pub cp_flags: u32,
    pub cp_version: u64,
    /// The second pack's version, when a test wants the two to differ.
    pub cp2_version: Option<u64>,
    pub uuid: [u8; SB_UUID_LEN],
    pub cp_payload: u32,
    /// Where the next main-area block comes from.
    pub next_main: u32,
    /// Where the next node id comes from.
    pub next_nid: u32,
    /// The node table this fixture will write out.
    pub nat: Vec<(u32, NatEntry)>,
    /// Entries put in the JOURNAL instead of the table, which override it.
    pub nat_journal: Vec<(u32, NatEntry)>,
    /// Which copy of each node-table block is current.
    pub nat_bitmap: Vec<u8>,
    pub sit_bitmap: Vec<u8>,
    /// Live block counts per main segment.
    pub sit_valid: Vec<u16>,
    pub valid_block_count: u64,
    pub valid_node_count: u32,
    pub valid_inode_count: u32,
    pub root_ino: u32,
    pub node_ino: u32,
    pub meta_ino: u32,
    /// Whether the superblock's first copy is deliberately left broken.
    pub break_super0: bool,
}

impl Builder {
    /// An empty formatted volume. # C: O(image bytes)
    pub fn new() -> Self {
        Self {
            bytes: vec![0u8; IMAGE_BLOCKS as usize * BLKSIZE],
            feature: DEFAULT_FEATURE,
            cp_flags: CP_UMOUNT_FLAG,
            cp_version: 7,
            cp2_version: None,
            uuid: [0x5A; SB_UUID_LEN],
            cp_payload: 0,
            next_main: MAIN_BLKADDR,
            next_nid: FIRST_NID,
            nat: Vec::new(),
            nat_journal: Vec::new(),
            nat_bitmap: vec![0u8; BITMAP_BYTES as usize],
            sit_bitmap: vec![0u8; BITMAP_BYTES as usize],
            sit_valid: vec![0u16; SEG_MAIN as usize],
            valid_block_count: 0,
            valid_node_count: 0,
            valid_inode_count: 0,
            root_ino: ROOT_INO,
            node_ino: NODE_INO,
            meta_ino: META_INO,
            break_super0: false,
        }
    }

    /// Set the checkpoint flag word. # C: O(1)
    pub fn cp_flags(mut self, f: u32) -> Self { self.cp_flags = f; self }

    /// Take the next free main-area block.
    ///
    /// Fixtures allocate out of the FIRST main segment only; the rest are the
    /// open logs' and the allocator's, and a fixture straying into one would
    /// hand the same block out twice.
    /// # C: O(1)
    pub fn alloc_block(&mut self) -> u32 {
        assert!(self.next_main < MAIN_BLKADDR + BLKS_PER_SEG, "fixture overflows segment zero");
        let addr = self.next_main;
        self.next_main += 1;
        let segno = (addr - MAIN_BLKADDR) / BLKS_PER_SEG;
        if let Some(v) = self.sit_valid.get_mut(segno as usize) { *v += 1; }
        self.valid_block_count += 1;
        addr
    }

    /// Reserve a node id a caller chose, so no later allocation collides with
    /// it. A fixture that let an inode's own number be handed out again would
    /// have two table entries for one id, and the second would win.
    /// # C: O(1)
    pub fn use_ino(&mut self, ino: u32) {
        if self.next_nid <= ino { self.next_nid = ino + 1; }
    }

    /// Blocks the fixture has put in the first main segment, which is where
    /// the hot-data log resumes from. # C: O(1)
    pub fn used_in_seg0(&self) -> u16 { (self.next_main - MAIN_BLKADDR) as u16 }

    /// Take the next free node id. # C: O(1)
    pub fn alloc_nid(&mut self) -> u32 {
        let nid = self.next_nid;
        self.next_nid += 1;
        nid
    }

    /// Write `data` at block `addr`. # C: O(BLKSIZE)
    pub fn put_block(&mut self, addr: u32, data: &[u8]) {
        let at = addr as usize * BLKSIZE;
        self.bytes[at..at + data.len()].copy_from_slice(data);
    }

    /// Read a block back, to assert on what a fixture laid down.
    /// # C: O(BLKSIZE)
    pub fn block(&self, addr: u32) -> &[u8] {
        let at = addr as usize * BLKSIZE;
        &self.bytes[at..at + BLKSIZE]
    }

    /// Record a node id as living at `addr` in the TABLE. # C: O(1)
    pub fn map_nid(&mut self, nid: u32, ino: u32, addr: u32) {
        self.nat.push((nid, NatEntry { version: 0, ino, block_addr: addr }));
        self.valid_node_count += 1;
    }

    /// Record a node id in the JOURNAL, which overrides the table. # C: O(1)
    pub fn journal_nid(&mut self, nid: u32, ino: u32, addr: u32) {
        self.nat_journal.push((nid, NatEntry { version: 0, ino, block_addr: addr }));
    }

    /// The finished image. # C: O(image bytes)
    pub fn finish(mut self) -> Vec<u8> {
        meta::write_all(&mut self);
        self.bytes
    }

    /// The finished image as a medium. # C: O(image bytes)
    pub fn image(self) -> MemImage { MemImage::from_bytes(BLKSIZE as u32, self.finish()) }

    /// The finished image, mounted read-only. # C: O(image bytes)
    pub fn mount(self) -> Result<Volume<MemImage>, syscall::errno::Errno> {
        Volume::mount_with(self.image(), Options::defaults(), false)
    }

    /// The finished image, mounted read-WRITE. # C: O(image bytes)
    pub fn mount_rw(self) -> Result<Volume<MemImage>, syscall::errno::Errno> {
        Volume::mount_with(self.image(), Options::defaults(), true)
    }

    /// The finished image, mounted read-write under `opts`. # C: O(image bytes)
    pub fn mount_opts(self, opts: Options) -> Result<Volume<MemImage>, syscall::errno::Errno> {
        Volume::mount_with(self.image(), opts, true)
    }
}

impl Default for Builder {
    fn default() -> Self { Self::new() }
}

/// A builder holding an empty root directory, which is what nearly every
/// volume-level test starts from. # C: O(image bytes)
pub fn with_root() -> Builder {
    let mut b = Builder::new();
    nodes::add_inline_dir(&mut b, ROOT_INO, &[]);
    b
}
