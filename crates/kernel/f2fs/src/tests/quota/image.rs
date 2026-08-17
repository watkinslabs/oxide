//! A quota file assembled byte by byte, so the tests below read the format
//! rather than this crate's own encoder.

use alloc::vec;
use alloc::vec::Vec;

use crate::quota::info::Revision;
use crate::quota::uapi::*;

/// A quota file of `blocks` blocks, headers written, everything else zero.
pub fn file(kind: usize, rev: Revision, blocks: u32) -> Vec<u8> {
    let mut f = vec![0u8; blocks as usize * QT_BLOCK_SIZE];
    put32(&mut f, DQH_MAGIC, MAGIC[kind]);
    put32(&mut f, DQH_VERSION, match rev { Revision::R0 => VERSION_R0, Revision::R1 => VERSION_R1 });
    put32(&mut f, INFO_OFF + DQI_BGRACE, 604_800);
    put32(&mut f, INFO_OFF + DQI_IGRACE, 604_800);
    put32(&mut f, INFO_OFF + DQI_BLOCKS, blocks);
    f
}

pub fn put32(f: &mut [u8], at: usize, v: u32) {
    f[at..at + U32_LEN].copy_from_slice(&v.to_le_bytes());
}

pub fn put64(f: &mut [u8], at: usize, v: u64) {
    f[at..at + U64_LEN].copy_from_slice(&v.to_le_bytes());
}

pub fn put16(f: &mut [u8], at: usize, v: u16) {
    f[at..at + U16_LEN].copy_from_slice(&v.to_le_bytes());
}

/// Where a block starts.
pub fn block_at(blk: u32) -> usize { blk as usize * QT_BLOCK_SIZE }

/// Point slot `idx` of tree block `blk` at block `to`.
pub fn link(f: &mut [u8], blk: u32, idx: u32, to: u32) {
    put32(f, block_at(blk) + idx as usize * REF_SIZE, to);
}

/// Where record slot `i` of leaf block `blk` starts.
pub fn entry_at(blk: u32, i: usize, rev: Revision) -> usize {
    block_at(blk) + DQDH_SIZE + i * rev.entry_size()
}

/// The whole chain of tree blocks an id needs, root first, ending at a leaf.
///
/// Written the long way — one reference per level, computed from the id the
/// way the format computes it — so a wrong index in the code under test does
/// not agree with a wrong index here.
pub fn plant(f: &mut [u8], id: u32, depth: u32, chain: &[u32]) {
    assert_eq!(chain.len(), depth as usize, "one block per level");
    let epb = (QT_BLOCK_SIZE >> REF_BITS) as u32;
    let mut here = QT_TREE_OFF;
    for (level, &next) in chain.iter().enumerate() {
        let mut v = id;
        let mut steps = depth - level as u32 - 1;
        while steps > 0 { v /= epb; steps -= 1; }
        link(f, here, v % epb, next);
        here = next;
    }
}

/// Write a revision-one record for `id` into slot `i` of leaf `blk`.
#[allow(clippy::too_many_arguments)]
pub fn r1_entry(
    f: &mut [u8],
    blk: u32,
    i: usize,
    id: u32,
    ihard: u64,
    isoft: u64,
    curinodes: u64,
    bhard_units: u64,
    bsoft_units: u64,
    curspace: u64,
    btime: u64,
    itime: u64,
) {
    let at = entry_at(blk, i, Revision::R1);
    put32(f, at + R1_ID, id);
    put64(f, at + R1_IHARDLIMIT, ihard);
    put64(f, at + R1_ISOFTLIMIT, isoft);
    put64(f, at + R1_CURINODES, curinodes);
    put64(f, at + R1_BHARDLIMIT, bhard_units);
    put64(f, at + R1_BSOFTLIMIT, bsoft_units);
    put64(f, at + R1_CURSPACE, curspace);
    put64(f, at + R1_BTIME, btime);
    put64(f, at + R1_ITIME, itime);
    let n = u16::from_le_bytes([f[block_at(blk) + DQDH_ENTRIES], f[block_at(blk) + DQDH_ENTRIES + 1]]);
    put16(f, block_at(blk) + DQDH_ENTRIES, n + 1);
}
