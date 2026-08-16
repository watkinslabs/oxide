//! Directories and attribute regions, laid out the way the format defines
//! them rather than the way the reader reads them.

use alloc::vec;
use alloc::vec::Vec;

use crate::dirent::{bucket, Layout};
use crate::flags::*;
use crate::hash;
use crate::uapi::*;

use super::super::meta::{put16, put32};
use super::super::Builder;
use super::{add_sparse_with, inode_block, place_inode, set_footer, Spec};

/// One entry a fixture directory carries.
#[derive(Clone)]
pub struct Ent {
    pub name: Vec<u8>,
    pub ino: u32,
    pub file_type: u8,
}

/// # C: O(len)
pub fn ent(name: &str, ino: u32, file_type: u8) -> Ent {
    Ent { name: name.as_bytes().to_vec(), ino, file_type }
}

/// The `.` and `..` pair every directory starts with. # C: O(1)
pub fn dots(ino: u32, parent: u32) -> Vec<Ent> {
    vec![ent(".", ino, FT_DIR), ent("..", parent, FT_DIR)]
}

/// Fill a dentry area with `entries`, packing them from slot zero.
///
/// Each name takes as many slots as it needs, and only the FIRST of those
/// slots carries a record — which is exactly what makes a reader that
/// advances one slot at a time go wrong.
/// # C: O(entries)
pub fn dentry_area(l: &Layout, entries: &[Ent]) -> Vec<u8> {
    let mut area = vec![0u8; l.len];
    let mut slot = 0usize;
    for e in entries {
        let slots = dentry_slots(e.name.len());
        assert!(slot + slots <= l.max, "fixture directory overflows its area");
        let at = l.dentry_off(slot);
        put32(&mut area, at + DE_HASH_CODE, hash::name_hash(&e.name));
        put32(&mut area, at + DE_INO, e.ino);
        put16(&mut area, at + DE_NAME_LEN, e.name.len() as u16);
        area[at + DE_FILE_TYPE] = e.file_type;
        let name_at = l.name_off(slot);
        area[name_at..name_at + e.name.len()].copy_from_slice(&e.name);
        for i in 0..slots { area[(slot + i) / 8] |= 1 << ((slot + i) % 8); }
        slot += slots;
    }
    area
}

/// A directory whose entries live inside its own inode block. # C: O(entries)
pub fn add_inline_dir(b: &mut Builder, ino: u32, entries: &[Ent]) -> Spec {
    let mut s = Spec::dir(ino);
    s.inline |= INLINE_DENTRY | INLINE_DATA | DATA_EXIST;
    let (at, len) = inline_span(&s);
    let layout = Layout::inline(len);
    let mut all = dots(ino, 3);
    all.extend_from_slice(entries);
    let area = dentry_area(&layout, &all);
    let mut block = inode_block(&s);
    block[at..at + len].copy_from_slice(&area);
    place_inode(b, &s, block, 1);
    s
}

/// A directory whose entries live in main-area blocks.
///
/// The entries are placed by HASH, into the bucket the format would put them
/// in, so a reader that computes a different hash or a different bucket finds
/// nothing — which is the point.
/// # C: O(entries)
pub fn add_block_dir(b: &mut Builder, ino: u32, dir_level: u8, depth: u32, entries: &[Ent])
    -> Spec {
    let mut s = Spec::dir(ino);
    s.current_depth = depth;
    s.dir_level = dir_level;
    let layout = Layout::block();
    let mut all = dots(ino, 3);
    all.extend_from_slice(entries);
    // Each entry goes to the first block of its bucket at level zero; the
    // fixture keeps to one level so the bucket arithmetic is what is under
    // test rather than the level walk.
    let mut per_block: Vec<(u64, Vec<Ent>)> = Vec::new();
    for e in all {
        let h = hash::name_hash(&e.name);
        let idx = bucket::search_range(h, 0, dir_level).start;
        match per_block.iter_mut().find(|(i, _)| *i == idx) {
            Some((_, v)) => v.push(e),
            None => per_block.push((idx, vec![e])),
        }
    }
    let highest = per_block.iter().map(|(i, _)| *i).max().unwrap_or(0);
    s.size = (highest + 1) * BLKSIZE as u64;
    let blocks: Vec<(u64, Vec<u8>)> =
        per_block.into_iter().map(|(i, v)| (i, dentry_area(&layout, &v))).collect();
    add_sparse_with(b, s, &blocks)
}

/// Where an inode's inline region is, and how long. # C: O(1)
pub fn inline_span(s: &Spec) -> (usize, usize) {
    (
        s.addr_base() + INLINE_RESERVED_SIZE * 4,
        (s.addrs_per_inode() - INLINE_RESERVED_SIZE) * 4,
    )
}

/// One attribute record's bytes. # C: O(len)
pub fn xattr_entry(index: u8, name: &[u8], value: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; xattr_align(XATTR_ENTRY_HEADER + name.len() + value.len())];
    out[XATTR_E_NAME_INDEX] = index;
    out[XATTR_E_NAME_LEN] = name.len() as u8;
    put16(&mut out, XATTR_E_VALUE_SIZE, value.len() as u16);
    let at = XATTR_ENTRY_HEADER;
    out[at..at + name.len()].copy_from_slice(name);
    out[at + name.len()..at + name.len() + value.len()].copy_from_slice(value);
    out
}

/// An attribute region of `len` bytes holding `attrs`. # C: O(bytes)
pub fn xattr_region(len: usize, attrs: &[(u8, Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut out = vec![0u8; len];
    put32(&mut out, XATTR_H_MAGIC, XATTR_MAGIC);
    put32(&mut out, XATTR_H_REFCOUNT, 1);
    let mut at = XATTR_HEADER_SIZE;
    for (index, name, value) in attrs {
        let e = xattr_entry(*index, name, value);
        out[at..at + e.len()].copy_from_slice(&e);
        at += e.len();
    }
    out
}

/// A file carrying attributes inline, and optionally continuing into a block.
///
/// The list is ONE list laid across the two halves: the writer packs records
/// contiguously, so a record may begin inline and end in the block. Encoding
/// the two halves as separate lists would leave a zero gap at the boundary
/// that terminates the walk, which is not what a real volume looks like.
/// # C: O(bytes)
pub fn add_file_with_xattrs(
    b: &mut Builder,
    ino: u32,
    attrs: &[(u8, Vec<u8>, Vec<u8>)],
    with_block: bool,
) -> Spec {
    b.use_ino(ino);
    let mut s = Spec::file(ino);
    s.inline |= INLINE_XATTR;
    if with_block { s.xattr_nid = b.alloc_nid(); }
    let inline_len = s.inline_xattr_addrs * 4;
    let total = if with_block { inline_len + VALID_XATTR_BLOCK_SIZE } else { inline_len };
    let mut region = xattr_region(total, attrs);
    let block_half = region.split_off(inline_len);
    let mut block = inode_block(&s);
    let at = OFFSET_OF_END_OF_I_EXT + (DEF_ADDRS_PER_INODE - s.inline_xattr_addrs) * 4;
    block[at..at + inline_len].copy_from_slice(&region);
    let mut used = 1u64;
    if with_block {
        let mut blk = vec![0u8; BLKSIZE];
        blk[..block_half.len()].copy_from_slice(&block_half);
        set_footer(&mut blk, s.xattr_nid, ino, 0);
        let addr = b.alloc_block();
        b.put_block(addr, &blk);
        b.map_nid(s.xattr_nid, ino, addr);
        used += 1;
    }
    place_inode(b, &s, block, used);
    s
}

/// An attribute block for an inode that has no inline region. # C: O(bytes)
pub fn add_xattr_block(b: &mut Builder, ino: u32, nid: u32, attrs: &[(u8, Vec<u8>, Vec<u8>)]) {
    let mut blk = vec![0u8; BLKSIZE];
    let region = xattr_region(VALID_XATTR_BLOCK_SIZE, attrs);
    blk[..VALID_XATTR_BLOCK_SIZE].copy_from_slice(&region);
    set_footer(&mut blk, nid, ino, 0);
    let addr = b.alloc_block();
    b.put_block(addr, &blk);
    b.map_nid(nid, ino, addr);
}
