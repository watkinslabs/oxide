// ext4 htree (indexed directory) hash + index descent, per Linux
// fs/ext4/hash.c + namei.c. Read of an htree directory works via the
// linear leaf scan in `lookup_in_dir` (leaf blocks are ordinary
// `ext4_dir_entry_2` blocks). For WRITE we must place a new name in
// the leaf block whose hash range covers `hash(name)`, so Linux's own
// hash lookup finds it. We descend the dx index (no rebalance) and
// insert into the covering leaf; a full leaf surfaces `DirFull` rather
// than splitting (a correct split/index-grow is a larger follow-up,
// noted in the module audit) — never corrupting the index.

use crate::dir;
use crate::inode::Inode;
use crate::mount::{Mount, MountError};
use crate::superblock::Superblock;

extern crate alloc;

/// `EXT4_INDEX_FL` in `i_flags` — directory uses an htree index.
pub const EXT4_INDEX_FL: u32 = 0x1000;

// Hash algorithm ids (`s_def_hash_version` / dx_root info.hash_version).
const DX_HASH_LEGACY:            u8 = 0;
const DX_HASH_HALF_MD4:          u8 = 1;
const DX_HASH_TEA:               u8 = 2;
const DX_HASH_LEGACY_UNSIGNED:   u8 = 3;
const DX_HASH_HALF_MD4_UNSIGNED: u8 = 4;
const DX_HASH_TEA_UNSIGNED:      u8 = 5;

const EXT4_HTREE_EOF_32: u32 = 0x7fff_ffff;

/// Compute the ext4 directory hash major value for `name`.
/// `version` is the dx_root's stored `hash_version`; `seed` is the
/// fs `s_hash_seed` (default constants used when all-zero).
/// # C: O(name.len())
pub fn dirhash_major(name: &[u8], version: u8, seed: &[u32; 4]) -> u32 {
    // Default seed (MD4 IV) unless the fs seed is non-zero.
    let mut buf: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
    if seed.iter().any(|&w| w != 0) { buf = *seed; }

    let (mut major, _minor) = match version {
        DX_HASH_LEGACY | DX_HASH_LEGACY_UNSIGNED => {
            (dx_hack_hash(name, version == DX_HASH_LEGACY), 0u32)
        }
        DX_HASH_HALF_MD4 | DX_HASH_HALF_MD4_UNSIGNED => {
            let signed = version == DX_HASH_HALF_MD4;
            let mut p = name;
            let mut inb = [0u32; 8];
            loop {
                str2hashbuf(p, &mut inb, 8, signed);
                half_md4_transform(&mut buf, &inb);
                if p.len() <= 32 { break; }
                p = &p[32..];
            }
            (buf[1], buf[2])
        }
        DX_HASH_TEA | DX_HASH_TEA_UNSIGNED => {
            let signed = version == DX_HASH_TEA;
            let mut p = name;
            let mut inb = [0u32; 4];
            loop {
                str2hashbuf(p, &mut inb, 4, signed);
                tea_transform(&mut buf, &inb);
                if p.len() <= 16 { break; }
                p = &p[16..];
            }
            (buf[0], buf[1])
        }
        _ => (0, 0),
    };
    major &= !1;
    if major == (EXT4_HTREE_EOF_32 << 1) { major = (EXT4_HTREE_EOF_32 - 1) << 1; }
    major
}

const DELTA: u32 = 0x9E37_79B9;

fn tea_transform(buf: &mut [u32; 4], inb: &[u32]) {
    let mut sum = 0u32;
    let (mut b0, mut b1) = (buf[0], buf[1]);
    let (a, b, c, d) = (inb[0], inb[1], inb[2], inb[3]);
    for _ in 0..16 {
        sum = sum.wrapping_add(DELTA);
        b0 = b0.wrapping_add(
            ((b1 << 4).wrapping_add(a)) ^ (b1.wrapping_add(sum)) ^ ((b1 >> 5).wrapping_add(b)));
        b1 = b1.wrapping_add(
            ((b0 << 4).wrapping_add(c)) ^ (b0.wrapping_add(sum)) ^ ((b0 >> 5).wrapping_add(d)));
    }
    buf[0] = buf[0].wrapping_add(b0);
    buf[1] = buf[1].wrapping_add(b1);
}

#[inline] fn f(x: u32, y: u32, z: u32) -> u32 { z ^ (x & (y ^ z)) }
#[inline] fn g(x: u32, y: u32, z: u32) -> u32 { (x & y).wrapping_add((x ^ y) & z) }
#[inline] fn h(x: u32, y: u32, z: u32) -> u32 { x ^ y ^ z }

const K1: u32 = 0;
const K2: u32 = 0x5A82_7999;
const K3: u32 = 0x6ED9_EBA1;

fn half_md4_transform(buf: &mut [u32; 4], inb: &[u32; 8]) {
    let (mut a, mut b, mut c, mut d) = (buf[0], buf[1], buf[2], buf[3]);
    macro_rules! round {
        ($fn:ident, $a:ident, $b:ident, $c:ident, $d:ident, $x:expr, $s:expr) => {
            $a = $a.wrapping_add($fn($b, $c, $d)).wrapping_add($x);
            $a = ($a << $s) | ($a >> (32 - $s));
        };
    }
    // Round 1
    round!(f, a, b, c, d, inb[0].wrapping_add(K1),  3);
    round!(f, d, a, b, c, inb[1].wrapping_add(K1),  7);
    round!(f, c, d, a, b, inb[2].wrapping_add(K1), 11);
    round!(f, b, c, d, a, inb[3].wrapping_add(K1), 19);
    round!(f, a, b, c, d, inb[4].wrapping_add(K1),  3);
    round!(f, d, a, b, c, inb[5].wrapping_add(K1),  7);
    round!(f, c, d, a, b, inb[6].wrapping_add(K1), 11);
    round!(f, b, c, d, a, inb[7].wrapping_add(K1), 19);
    // Round 2
    round!(g, a, b, c, d, inb[1].wrapping_add(K2),  3);
    round!(g, d, a, b, c, inb[3].wrapping_add(K2),  5);
    round!(g, c, d, a, b, inb[5].wrapping_add(K2),  9);
    round!(g, b, c, d, a, inb[7].wrapping_add(K2), 13);
    round!(g, a, b, c, d, inb[0].wrapping_add(K2),  3);
    round!(g, d, a, b, c, inb[2].wrapping_add(K2),  5);
    round!(g, c, d, a, b, inb[4].wrapping_add(K2),  9);
    round!(g, b, c, d, a, inb[6].wrapping_add(K2), 13);
    // Round 3
    round!(h, a, b, c, d, inb[3].wrapping_add(K3),  3);
    round!(h, d, a, b, c, inb[7].wrapping_add(K3),  9);
    round!(h, c, d, a, b, inb[2].wrapping_add(K3), 11);
    round!(h, b, c, d, a, inb[6].wrapping_add(K3), 15);
    round!(h, a, b, c, d, inb[1].wrapping_add(K3),  3);
    round!(h, d, a, b, c, inb[5].wrapping_add(K3),  9);
    round!(h, c, d, a, b, inb[0].wrapping_add(K3), 11);
    round!(h, b, c, d, a, inb[4].wrapping_add(K3), 15);
    buf[0] = buf[0].wrapping_add(a);
    buf[1] = buf[1].wrapping_add(b);
    buf[2] = buf[2].wrapping_add(c);
    buf[3] = buf[3].wrapping_add(d);
}

/// Pack up to `num*4` bytes of `msg` into `num` u32 words, padding the
/// tail with the length pattern per `str2hashbuf_{signed,unsigned}`.
fn str2hashbuf(msg: &[u8], out: &mut [u32], num: usize, signed: bool) {
    let mut pad = (msg.len() as u32) | ((msg.len() as u32) << 8);
    pad |= pad << 16;
    let mut val = pad;
    let mut len = msg.len();
    if len > num * 4 { len = num * 4; }
    let mut oi = 0usize;
    let mut written = 0usize;
    for i in 0..len {
        let cv = if signed { (msg[i] as i8) as i32 } else { msg[i] as i32 };
        val = (cv as u32).wrapping_add(val << 8);
        if (i % 4) == 3 {
            out[oi] = val; oi += 1; written += 1;
            val = pad;
        }
    }
    // Trailing partial word + remaining padding words (num words total).
    if written < num {
        out[oi] = val; oi += 1; written += 1;
    }
    while written < num {
        out[oi] = pad; oi += 1; written += 1;
    }
}

/// Legacy ext2 directory hash (`dx_hack_hash`).
fn dx_hack_hash(name: &[u8], signed: bool) -> u32 {
    let (mut hash0, mut hash1) = (0x12a3fe2du32, 0x37abe8f9u32);
    for &b in name {
        let c = if signed { (b as i8) as i32 } else { b as i32 };
        let hash = hash1.wrapping_add(hash0 ^ (c as u32).wrapping_mul(7152373));
        let hash = if (hash & 0x8000_0000) != 0 { hash.wrapping_sub(0x7fff_ffff) } else { hash };
        hash1 = hash0;
        hash0 = hash;
    }
    hash0
}

impl Mount {
    /// Insert `(name → child_ino)` into an htree directory by hashing
    /// the name and descending the dx index to the covering leaf. The
    /// index itself is left untouched (only leaf contents change), so
    /// the on-disk hash ranges stay valid and Linux's lookup finds the
    /// new entry. A full target leaf returns `DirFull`.
    /// # C: O(index entries) + 1 leaf RMW
    pub(crate) fn htree_insert(
        &self, dir_node: &Inode, dir_ino: u32, gen: u32,
        name: &[u8], child_ino: u32, file_type: u8,
    ) -> Result<(), MountError> {
        let bs = self.sb.block_size as usize;
        let usable = crate::csum::dir_usable_len(&self.sb, bs);
        let root = self.read_file_block_meta(dir_node, 0)?;
        // dx_root info: hash_version @ 0x1C (28), indirect_levels @ 0x1E (30).
        let hash_version = root[0x1C];
        let indirect = root[0x1E];
        let hash = dirhash_major(name, hash_version, &self.sb.hash_seed);

        // Descend: dx_root = dot(12) + dotdot(12) + dx_root_info(8), so the
        // dx_entry[] array begins at offset 0x20. entries[0] overlays
        // {limit,count}; its block is the hash-0 range. entry i ≥ 1:
        // hash @ +0, block @ +4.
        let mut leaf_lblk = self.dx_find_leaf(&root, 0x20, hash)?;
        if indirect >= 1 {
            // Two-level index: descend one more dx_node block.
            let node = self.read_file_block_meta(dir_node, leaf_lblk)?;
            // dx_node has an 8-byte fake dirent header; entries at 0x08.
            leaf_lblk = self.dx_find_leaf(&node, 0x08, hash)?;
        }

        let mut leaf = self.read_file_block_meta(dir_node, leaf_lblk)?;
        if leaf.len() < bs { leaf.resize(bs, 0); }
        match dir::insert(&mut leaf[..usable], child_ino, file_type, name) {
            Ok(()) => {
                crate::csum::stamp_dirent_tail(&self.sb, dir_ino, gen, &mut leaf);
                self.run_journaled(|m| m.write_file_block_meta(dir_node, leaf_lblk, &leaf))
            }
            Err(dir::DirError::Full) => Err(MountError::DirFull),
            Err(e) => Err(MountError::Dir(e)),
        }
    }

    /// Find the logical dir block whose hash range covers `hash` in a
    /// dx index whose `dx_entry[]` array starts at byte `entries_off`.
    /// The first entry overlays `{__le16 limit, __le16 count}`; its
    /// `block` field (at entries_off+4) is the hash-0 child.
    fn dx_find_leaf(&self, node: &[u8], entries_off: usize, hash: u32)
        -> Result<u32, MountError>
    {
        let count = u16::from_le_bytes([node[entries_off + 2], node[entries_off + 3]]) as usize;
        if count == 0 { return Err(MountError::NotFound); }
        // entry 0: implicit hash 0, block @ entries_off+4.
        let mut chosen = u32::from_le_bytes([
            node[entries_off + 4], node[entries_off + 5],
            node[entries_off + 6], node[entries_off + 7]]);
        for i in 1..count {
            let eo = entries_off + i * 8;
            let ehash = u32::from_le_bytes([node[eo], node[eo + 1], node[eo + 2], node[eo + 3]]);
            if hash < ehash { break; }
            chosen = u32::from_le_bytes([node[eo + 4], node[eo + 5], node[eo + 6], node[eo + 7]]);
        }
        Ok(chosen)
    }
}

/// Re-export for the superblock-less hash callers / tests.
pub fn default_hash_version(sb: &Superblock) -> u8 { sb.def_hash_version }

#[cfg(test)]
mod tests {
    use super::*;

    // Vectors captured from a real e2fsprogs-built htree dir
    // (hash_version 1 = half_md4, seed UUID 14d9057c-8c41-4093-8a0f-23e3f08b2db9).
    const SEED: [u32; 4] = [0x7c05_d914, 0x9340_418c, 0xe323_0f8a, 0xb92d_8bf0];

    #[test]
    fn half_md4_matches_e2fsprogs() {
        assert_eq!(dirhash_major(b"sub_entry_number_64", 1, &SEED), 0x02d0_92e6);
        assert_eq!(dirhash_major(b"sub_entry_number_56", 1, &SEED), 0x02e2_6dd8);
        assert_eq!(dirhash_major(b"sub_entry_number_74", 1, &SEED), 0x03e7_7e64);
    }

    #[test]
    fn hash_low_bit_cleared() {
        assert_eq!(dirhash_major(b"anything", 1, &SEED) & 1, 0);
    }
}
