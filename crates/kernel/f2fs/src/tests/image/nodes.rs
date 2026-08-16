//! Node blocks: inodes, the node tree under them, and file data.
//!
//! Module manifest:
//! - `dir`: directories, inline and blocked, and attribute regions.

use alloc::vec;
use alloc::vec::Vec;

use crate::checksum;
use crate::flags::*;
use crate::mode;
use crate::node::path;
use crate::node::Step;
use crate::uapi::*;

use super::meta::{put16, put32, put64};
use super::Builder;

#[path = "nodes/dir.rs"]
pub mod dir;

#[allow(unused_imports)]
pub use dir::{add_block_dir, add_inline_dir, add_xattr_block, dentry_area, ent, Ent};

/// How much extra attribute a fixture inode carries, and how much of its
/// address array it reserves for inline attributes.
pub const EXTRA_ISIZE: usize = TOTAL_EXTRA_ATTR_SIZE;
pub const INLINE_XATTR_ADDRS: usize = DEFAULT_INLINE_XATTR_ADDRS;

/// What a fixture inode is made of.
#[derive(Clone)]
pub struct Spec {
    pub ino: u32,
    pub mode: u16,
    pub links: u32,
    pub size: u64,
    pub inline: u8,
    pub flags: u32,
    pub current_depth: u32,
    pub dir_level: u8,
    pub xattr_nid: u32,
    pub extra_isize: usize,
    pub inline_xattr_addrs: usize,
    pub generation: u32,
}

impl Spec {
    /// A regular file. # C: O(1)
    pub fn file(ino: u32) -> Self {
        Self {
            ino,
            mode: mode::S_IFREG | 0o644,
            links: 1,
            size: 0,
            inline: EXTRA_ATTR,
            flags: 0,
            current_depth: 0,
            dir_level: 0,
            xattr_nid: 0,
            extra_isize: EXTRA_ISIZE,
            inline_xattr_addrs: INLINE_XATTR_ADDRS,
            generation: 1,
        }
    }

    /// A directory. # C: O(1)
    pub fn dir(ino: u32) -> Self {
        Self { mode: mode::S_IFDIR | 0o755, links: 2, ..Self::file(ino) }
    }

    /// Usable address slots, the same arithmetic the reader does. # C: O(1)
    pub fn addrs_per_inode(&self) -> usize {
        (DEF_ADDRS_PER_INODE - self.extra_isize / 4).saturating_sub(self.inline_xattr_addrs)
    }

    /// Byte offset of the address array's first usable slot. # C: O(1)
    pub fn addr_base(&self) -> usize { OFFSET_OF_END_OF_I_EXT + self.extra_isize }
}

/// Lay the fixed fields of an inode block down. # C: O(BLKSIZE)
pub fn inode_block(s: &Spec) -> Vec<u8> {
    let mut b = vec![0u8; BLKSIZE];
    put16(&mut b, I_MODE, s.mode);
    b[I_INLINE] = s.inline;
    put32(&mut b, I_UID, 1000);
    put32(&mut b, I_GID, 1000);
    put32(&mut b, I_LINKS, s.links);
    put64(&mut b, I_SIZE, s.size);
    put64(&mut b, I_BLOCKS, 1);
    put64(&mut b, I_ATIME, 1_700_000_001);
    put32(&mut b, I_ATIME_NSEC, 11);
    put64(&mut b, I_CTIME, 1_700_000_002);
    put32(&mut b, I_CTIME_NSEC, 22);
    put64(&mut b, I_MTIME, 1_700_000_003);
    put32(&mut b, I_MTIME_NSEC, 33);
    put32(&mut b, I_GENERATION, s.generation);
    put32(&mut b, I_CURRENT_DEPTH, s.current_depth);
    put32(&mut b, I_XATTR_NID, s.xattr_nid);
    put32(&mut b, I_FLAGS, s.flags);
    put32(&mut b, I_PINO, 3);
    b[I_DIR_LEVEL] = s.dir_level;
    if s.extra_isize > 0 {
        put16(&mut b, I_EXTRA_ISIZE, s.extra_isize as u16);
        put16(&mut b, I_INLINE_XATTR_SIZE, s.inline_xattr_addrs as u16);
        put64(&mut b, I_CRTIME, 1_700_000_000);
        put32(&mut b, I_CRTIME_NSEC, 44);
    }
    b
}

/// Write a node block's footer. # C: O(1)
pub fn set_footer(b: &mut [u8], nid: u32, ino: u32, ofs: u32) {
    let f = NODE_FOOTER_OFF;
    put32(b, f + FOOTER_NID, nid);
    put32(b, f + FOOTER_INO, ino);
    put32(b, f + FOOTER_FLAG, ofs << OFFSET_BIT_SHIFT);
    put64(b, f + FOOTER_CP_VER, 7);
}

/// Seal an inode block, place it, and record it in the node table.
///
/// The checksum is computed last, over the finished block, because every
/// field it covers must already be in place.
/// # C: O(BLKSIZE)
pub fn place_inode(b: &mut Builder, s: &Spec, mut block: Vec<u8>, blocks_used: u64) {
    put64(&mut block, I_BLOCKS, blocks_used.max(1));
    set_footer(&mut block, s.ino, s.ino, 0);
    if b.feature & FEATURE_INODE_CHKSUM != 0 && s.inline & EXTRA_ATTR != 0 {
        let seed = checksum::inode_seed(&b.uuid);
        put32(&mut block, I_INODE_CHECKSUM, 0);
        let c = checksum::inode_chksum(seed, &block).unwrap();
        put32(&mut block, I_INODE_CHECKSUM, c);
    }
    let addr = b.alloc_block();
    b.put_block(addr, &block);
    b.map_nid(s.ino, s.ino, addr);
    b.valid_inode_count += 1;
}

/// A file whose data lives inside its own inode block. # C: O(len)
pub fn add_inline_file(b: &mut Builder, ino: u32, data: &[u8]) -> Spec {
    b.use_ino(ino);
    let mut s = Spec::file(ino);
    s.size = data.len() as u64;
    s.inline |= INLINE_DATA | DATA_EXIST;
    let mut block = inode_block(&s);
    let (at, len) = (s.addr_base() + INLINE_RESERVED_SIZE * 4, data.len());
    assert!(len <= (s.addrs_per_inode() - INLINE_RESERVED_SIZE) * 4);
    block[at..at + len].copy_from_slice(data);
    place_inode(b, &s, block, 1);
    s
}

/// A file whose data lives in main-area blocks, possibly sparsely.
///
/// Only the named indices are allocated; every other block of the file is a
/// hole, which is what makes a file spanning an indirect node testable inside
/// an image small enough to build in a test.
/// # C: O(blocks)
pub fn add_sparse_file(b: &mut Builder, ino: u32, size: u64, blocks: &[(u64, Vec<u8>)]) -> Spec {
    b.use_ino(ino);
    let mut s = Spec::file(ino);
    s.size = size;
    add_sparse_with(b, s, blocks)
}

/// The same, under a caller-supplied spec. # C: O(blocks)
pub fn add_sparse_with(b: &mut Builder, s: Spec, blocks: &[(u64, Vec<u8>)]) -> Spec {
    b.use_ino(s.ino);
    let mut inode = inode_block(&s);
    let mut tree = Tree::new();
    let mut used = 1u64;
    for (index, data) in blocks {
        let addr = b.alloc_block();
        let mut blk = vec![0u8; BLKSIZE];
        blk[..data.len()].copy_from_slice(data);
        b.put_block(addr, &blk);
        used += 1;
        let p = path::node_path(s.addrs_per_inode(), *index).expect("index within range");
        match p.step() {
            Step::InInode { index } => put32(&mut inode, s.addr_base() + index * 4, addr),
            Step::Direct { nid_slot, index } => {
                let dn = tree.direct(b, &mut inode, &s, nid_slot, p.noffset[1] as u32);
                put32(&mut tree.blocks[dn].data, index * 4, addr);
            }
            Step::Indirect { nid_slot, dnode, index } => {
                let ind = tree.indirect(b, &mut inode, &s, nid_slot, p.noffset[1] as u32);
                let dn = tree.child(b, ind, dnode, p.noffset[2] as u32, s.ino);
                put32(&mut tree.blocks[dn].data, index * 4, addr);
            }
            Step::DoubleIndirect { nid_slot, indirect, dnode, index } => {
                let outer = tree.indirect(b, &mut inode, &s, nid_slot, p.noffset[1] as u32);
                let mid = tree.child(b, outer, indirect, p.noffset[2] as u32, s.ino);
                let dn = tree.child(b, mid, dnode, p.noffset[3] as u32, s.ino);
                put32(&mut tree.blocks[dn].data, index * 4, addr);
            }
        }
    }
    used += tree.blocks.len() as u64;
    tree.flush(b, s.ino);
    place_inode(b, &s, inode, used);
    s
}

/// Rewrite an inode block in place and reseal its checksum.
///
/// A fixture that pokes an inode after it is placed would break the checksum
/// and get a refusal rather than the behaviour it meant to test.
/// # C: O(BLKSIZE)
pub fn patch_inode(b: &mut Builder, ino: u32, f: impl FnOnce(&mut [u8])) {
    let addr = b.nat.iter().find(|(n, _)| *n == ino).expect("inode placed").1.block_addr;
    let mut block = b.block(addr).to_vec();
    f(&mut block);
    if b.feature & FEATURE_INODE_CHKSUM != 0 && block[I_INLINE] & EXTRA_ATTR != 0 {
        let seed = checksum::inode_seed(&b.uuid);
        put32(&mut block, I_INODE_CHECKSUM, 0);
        let c = checksum::inode_chksum(seed, &block).unwrap();
        put32(&mut block, I_INODE_CHECKSUM, c);
    }
    b.put_block(addr, &block);
}

/// A symbolic link, whose target is its file content. # C: O(len)
pub fn add_symlink(b: &mut Builder, ino: u32, target: &[u8]) -> Spec {
    b.use_ino(ino);
    let mut s = Spec::file(ino);
    s.mode = mode::S_IFLNK | 0o777;
    s.size = target.len() as u64;
    s.inline |= INLINE_DATA | DATA_EXIST;
    let mut block = inode_block(&s);
    let at = s.addr_base() + INLINE_RESERVED_SIZE * 4;
    block[at..at + target.len()].copy_from_slice(target);
    place_inode(b, &s, block, 1);
    s
}

/// A device, socket or pipe, whose device number lives in the address array.
/// # C: O(1)
pub fn add_special(b: &mut Builder, ino: u32, mode_word: u16, wide: u32) -> Spec {
    b.use_ino(ino);
    let mut s = Spec::file(ino);
    s.mode = mode_word;
    let mut block = inode_block(&s);
    // The narrow slot stays zero, which is what sends a reader to the wide one.
    put32(&mut block, s.addr_base() + 4, wide);
    place_inode(b, &s, block, 1);
    s
}

/// The node blocks a file's tree needs, held until they can be written.
pub struct Tree {
    pub blocks: Vec<Node>,
}

/// One node block under construction.
pub struct Node {
    pub nid: u32,
    pub ofs: u32,
    pub data: Vec<u8>,
}

impl Tree {
    /// # C: O(1)
    pub fn new() -> Self { Self { blocks: Vec::new() } }

    /// The direct node under one of the inode's own node-id slots. # C: O(n)
    pub fn direct(&mut self, b: &mut Builder, inode: &mut [u8], s: &Spec, slot: usize, ofs: u32)
        -> usize {
        self.at_slot(b, inode, s, slot, ofs)
    }

    /// The indirect node under one of the inode's own node-id slots.
    /// # C: O(n)
    pub fn indirect(&mut self, b: &mut Builder, inode: &mut [u8], s: &Spec, slot: usize, ofs: u32)
        -> usize {
        self.at_slot(b, inode, s, slot, ofs)
    }

    /// # C: O(n)
    fn at_slot(&mut self, b: &mut Builder, inode: &mut [u8], s: &Spec, slot: usize, ofs: u32)
        -> usize {
        let existing = crate::uapi::le32(inode, I_NID_OFF + slot * 4).unwrap_or(0);
        if existing != 0 {
            return self.blocks.iter().position(|n| n.nid == existing).expect("node present");
        }
        let nid = b.alloc_nid();
        put32(inode, I_NID_OFF + slot * 4, nid);
        self.blocks.push(Node { nid, ofs, data: vec![0u8; BLKSIZE] });
        let _ = s;
        self.blocks.len() - 1
    }

    /// The node one slot of another node points at. # C: O(n)
    pub fn child(&mut self, b: &mut Builder, parent: usize, slot: usize, ofs: u32, _ino: u32)
        -> usize {
        let existing = crate::uapi::le32(&self.blocks[parent].data, slot * 4).unwrap_or(0);
        if existing != 0 {
            return self.blocks.iter().position(|n| n.nid == existing).expect("node present");
        }
        let nid = b.alloc_nid();
        put32(&mut self.blocks[parent].data, slot * 4, nid);
        self.blocks.push(Node { nid, ofs, data: vec![0u8; BLKSIZE] });
        self.blocks.len() - 1
    }

    /// Place every node block and record each in the node table. # C: O(nodes)
    pub fn flush(self, b: &mut Builder, ino: u32) {
        for mut n in self.blocks {
            set_footer(&mut n.data, n.nid, ino, n.ofs);
            let addr = b.alloc_block();
            b.put_block(addr, &n.data);
            b.map_nid(n.nid, ino, addr);
        }
    }
}

impl Default for Tree {
    fn default() -> Self { Self::new() }
}
