// ext4 htree (indexed directory) hash + index descent.
// Read of an htree directory works via the
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

        // Descend to the covering leaf, remembering the dx block that points at
        // it (and where its dx_countlimit lives) — that's where a leaf split
        // inserts the new dx_entry. dx_root: dot(12)+dotdot(12)+info(8) → entries
        // at 0x20. dx_node: 8-byte fake header → entries at 0x08.
        let (leaf_lblk, dx_lblk, count_off) = if indirect >= 1 {
            let node_lblk = self.dx_find_leaf(&root, 0x20, hash)?;
            let node = self.read_file_block_meta(dir_node, node_lblk)?;
            let leaf_lblk = self.dx_find_leaf(&node, 0x08, hash)?;
            (leaf_lblk, node_lblk, 0x08usize)
        } else {
            (self.dx_find_leaf(&root, 0x20, hash)?, 0u32, 0x20usize)
        };

        let mut leaf = self.read_file_block_meta(dir_node, leaf_lblk)?;
        if leaf.len() < bs { leaf.resize(bs, 0); }
        match dir::insert(&mut leaf[..usable], child_ino, file_type, name) {
            Ok(()) => {
                crate::csum::stamp_dirent_tail(&self.sb, dir_ino, gen, &mut leaf);
                return self.run_journaled(|m| m.write_file_block_meta(dir_node, leaf_lblk, &leaf));
            }
            Err(dir::DirError::Full) => {} // full leaf → split (Linux `ext4_dx_add_entry`)
            Err(e) => return Err(MountError::Dir(e)),
        }
        self.htree_split(dir_node, dir_ino, gen, leaf_lblk, dx_lblk, count_off,
                         hash_version, name, child_ino, file_type)
    }

    /// Split the full leaf `leaf_lblk` (Linux `ext4_dx_add_entry` → `do_split`):
    /// redistribute its entries + the new one by hash across the old leaf and a
    /// freshly allocated one, then add a `dx_entry {split_hash, new_leaf}` to the
    /// dx block at `dx_lblk`. A full dx block grows the index a level first.
    /// # C: O(entries) + 2 leaf writes + 1 dx write
    #[allow(clippy::too_many_arguments)]
    fn htree_split(
        &self, dir_node: &Inode, dir_ino: u32, gen: u32,
        leaf_lblk: u32, dx_lblk: u32, count_off: usize, hash_version: u8,
        new_name: &[u8], new_ino: u32, new_ft: u8,
    ) -> Result<(), MountError> {
        let bs = self.sb.block_size as usize;
        let usable = crate::csum::dir_usable_len(&self.sb, bs);
        let seed = &self.sb.hash_seed;

        let dx = self.read_file_block_meta(dir_node, dx_lblk)?;
        let limit = u16::from_le_bytes([dx[count_off], dx[count_off + 1]]);
        let count = u16::from_le_bytes([dx[count_off + 2], dx[count_off + 3]]);
        if count >= limit {
            return self.htree_grow(dir_node, dir_ino, gen, leaf_lblk, dx_lblk, count_off,
                                   hash_version, new_name, new_ino, new_ft);
        }

        // Gather all entries (existing leaf + the new one) tagged by hash, sorted.
        let leaf = self.read_file_block_meta(dir_node, leaf_lblk)?;
        let mut ents: alloc::vec::Vec<(u32, u32, u8, alloc::vec::Vec<u8>)> = alloc::vec::Vec::new();
        dir::iter_active(&leaf[..usable.min(leaf.len())], |e| {
            ents.push((dirhash_major(e.name, hash_version, seed), e.inode, e.file_type, e.name.to_vec()));
            true
        }).map_err(MountError::Dir)?;
        ents.push((dirhash_major(new_name, hash_version, seed), new_ino, new_ft, new_name.to_vec()));
        // Total order: hash, then name. Equal major hashes are ordinary in an
        // htree (that is what the collision bit exists for), so hash alone
        // leaves the order of a collision run to the sort's stability. Naming
        // the tie explicitly makes the split deterministic AND lets this use
        // the unstable sort, whose 4 KiB scratch frame the stable one would
        // otherwise put on an ext4 write path.
        ents.sort_unstable_by(|a, b| a.0.cmp(&b.0).then_with(|| a.3.cmp(&b.3)));

        // Split near the middle, keeping equal-hash entries together (the new
        // dx boundary hash must not fall inside a run of identical hashes).
        let mut split = ents.len() / 2;
        while split < ents.len() && split > 0 && ents[split].0 == ents[split - 1].0 { split += 1; }
        if split == 0 || split >= ents.len() { return Err(MountError::DirFull); }
        let split_hash = ents[split].0;

        let old_buf = self.build_leaf_block(bs, usable, &ents[..split], dir_ino, gen)?;
        let new_buf = self.build_leaf_block(bs, usable, &ents[split..], dir_ino, gen)?;

        self.run_journaled(|m| {
            let new_lblk = m.append_dir_block(dir_ino, &new_buf)?;
            m.write_file_block_meta(dir_node, leaf_lblk, &old_buf)?;
            let mut dx = m.read_file_block_meta(dir_node, dx_lblk)?;
            let count = u16::from_le_bytes([dx[count_off + 2], dx[count_off + 3]]) as usize;
            // dx_entry k at count_off + k*8; entry 0 holds {limit,count,block}.
            // Find the sorted insert slot i in 1..=count (entry hashes ascending).
            let mut i = 1usize;
            while i < count {
                let o = count_off + i * 8;
                let h = u32::from_le_bytes([dx[o], dx[o + 1], dx[o + 2], dx[o + 3]]);
                if h > split_hash { break; }
                i += 1;
            }
            let src = count_off + i * 8;
            let end = count_off + count * 8;
            dx.copy_within(src..end, src + 8);
            dx[src..src + 4].copy_from_slice(&split_hash.to_le_bytes());
            dx[src + 4..src + 8].copy_from_slice(&new_lblk.to_le_bytes());
            dx[count_off + 2..count_off + 4].copy_from_slice(&((count as u16) + 1).to_le_bytes());
            crate::csum::stamp_dx_tail(&self.sb, dir_ino, gen, &mut dx, count_off);
            m.write_file_block_meta(dir_node, dx_lblk, &dx)
        })
    }

    /// Build a leaf dir block from `ents` (a run of `{_hash, ino, ft, name}`):
    /// one free entry spanning the usable region, then each name inserted; tail
    /// csum stamped. # C: O(entries)
    fn build_leaf_block(
        &self, bs: usize, usable: usize, ents: &[(u32, u32, u8, alloc::vec::Vec<u8>)],
        dir_ino: u32, gen: u32,
    ) -> Result<alloc::vec::Vec<u8>, MountError> {
        let mut buf = alloc::vec![0u8; bs];
        buf[4..6].copy_from_slice(&(usable as u16).to_le_bytes()); // free entry: inode=0, rec_len=usable
        for (_h, ino, ft, name) in ents {
            dir::insert(&mut buf[..usable], *ino, *ft, name).map_err(MountError::Dir)?;
        }
        crate::csum::stamp_dirent_tail(&self.sb, dir_ino, gen, &mut buf);
        Ok(buf)
    }

    /// Grow the htree index a level when the dx block that must take a new
    /// `dx_entry` is full. Case A (a full dx_ROOT, single-level → two-level,
    /// Linux `ext4_dx_add_entry` root-overflow path): push all the root's
    /// dx_entries into a fresh dx_NODE, leave the root pointing at it with
    /// `indirect_levels=1`, then retry the split into the now-roomy node.
    /// # C: O(entries) + 1 node write + 1 root write
    #[allow(clippy::too_many_arguments)]
    fn htree_grow(
        &self, dir_node: &Inode, dir_ino: u32, gen: u32,
        leaf_lblk: u32, dx_lblk: u32, count_off: usize, hash_version: u8,
        new_name: &[u8], new_ino: u32, new_ft: u8,
    ) -> Result<(), MountError> {
        let bs = self.sb.block_size as usize;

        // Case B: a full dx_NODE at level 1. Split it (move its upper-half
        // dx_entries to a new node) and add a dx_entry for the new node to the
        // ROOT, then retry the original insert (re-descends into the now-roomy
        // node). A full ROOT here would need a 3rd level (>~600K entries at
        // 1 KiB) — that rare case surfaces as DirFull.
        if dx_lblk != 0 {
            let node = self.read_file_block_meta(dir_node, dx_lblk)?;
            let ncount = u16::from_le_bytes([node[count_off + 2], node[count_off + 3]]) as usize;
            let nlimit = crate::csum::dx_entry_limit(&self.sb, bs, count_off);
            let split = ncount / 2;
            if split == 0 || split >= ncount { return Err(MountError::DirFull); }
            let so = count_off + split * 8;
            let boundary_hash = u32::from_le_bytes([node[so], node[so + 1], node[so + 2], node[so + 3]]);

            // Root must have room for the new node's dx_entry.
            let root = self.read_file_block_meta(dir_node, 0)?;
            let root_count = u16::from_le_bytes([root[0x22], root[0x23]]) as usize;
            let root_limit = u16::from_le_bytes([root[0x20], root[0x21]]) as usize;
            if root_count >= root_limit { return Err(MountError::DirFull); } // 3rd level unneeded in practice

            // Build the new node: fake header + upper-half entries; entry 0 is its
            // countlimit whose `block` is entries[split].block (implicit hash 0).
            let new_ncount = ncount - split;
            let mut newnode = alloc::vec![0u8; bs];
            newnode[4..6].copy_from_slice(&(bs as u16).to_le_bytes());
            for k in 0..new_ncount {
                let src = count_off + (split + k) * 8;
                let dof = count_off + k * 8;
                newnode[dof..dof + 8].copy_from_slice(&node[src..src + 8]);
            }
            newnode[count_off..count_off + 2].copy_from_slice(&nlimit.to_le_bytes());
            newnode[count_off + 2..count_off + 4].copy_from_slice(&(new_ncount as u16).to_le_bytes());

            // Old node keeps the lower half.
            let mut oldnode = node.clone();
            oldnode[count_off + 2..count_off + 4].copy_from_slice(&(split as u16).to_le_bytes());

            self.run_journaled(|m| {
                crate::csum::stamp_dx_tail(&self.sb, dir_ino, gen, &mut newnode, count_off);
                let new_node_lblk = m.append_dir_block(dir_ino, &newnode)?;
                crate::csum::stamp_dx_tail(&self.sb, dir_ino, gen, &mut oldnode, count_off);
                m.write_file_block_meta(dir_node, dx_lblk, &oldnode)?;
                // Insert {boundary_hash, new_node_lblk} into the root, sorted.
                let mut r = m.read_file_block_meta(dir_node, 0)?;
                let rc = u16::from_le_bytes([r[0x22], r[0x23]]) as usize;
                let mut i = 1usize;
                while i < rc {
                    let o = 0x20 + i * 8;
                    let h = u32::from_le_bytes([r[o], r[o + 1], r[o + 2], r[o + 3]]);
                    if h > boundary_hash { break; }
                    i += 1;
                }
                let src = 0x20 + i * 8;
                let end = 0x20 + rc * 8;
                r.copy_within(src..end, src + 8);
                r[src..src + 4].copy_from_slice(&boundary_hash.to_le_bytes());
                r[src + 4..src + 8].copy_from_slice(&new_node_lblk.to_le_bytes());
                r[0x22..0x24].copy_from_slice(&((rc as u16) + 1).to_le_bytes());
                crate::csum::stamp_dx_tail(&self.sb, dir_ino, gen, &mut r, 0x20);
                m.write_file_block_meta(dir_node, 0, &r)
            })?;

            // Retry the original insert: re-descends root → the correct (roomy) node.
            let d2 = self.read_inode(dir_ino)?;
            return self.htree_insert(&d2, dir_ino, gen, new_name, new_ino, new_ft);
        }

        let root = self.read_file_block_meta(dir_node, 0)?;
        let root_count = u16::from_le_bytes([root[0x22], root[0x23]]) as usize;

        // Build the new dx_NODE: 8-byte fake dirent header (spans the block) then
        // the countlimit at 0x08 + the root's dx_entries copied verbatim.
        let node_count_off = 0x08usize;
        let node_limit = crate::csum::dx_entry_limit(&self.sb, bs, node_count_off);
        let mut node = alloc::vec![0u8; bs];
        node[4..6].copy_from_slice(&(bs as u16).to_le_bytes()); // fake dirent rec_len = bs
        // Copy root entries[0..root_count] (8 bytes each) → node entries[0..].
        for k in 0..root_count {
            let so = 0x20 + k * 8;
            let dof = node_count_off + k * 8;
            node[dof..dof + 8].copy_from_slice(&root[so..so + 8]);
        }
        // entry 0 in the node is the countlimit: set the node's own limit + the
        // (copied) count. Its `block` field (@+4, the hash-0 leaf) came from the
        // root's entry 0 above and is preserved.
        node[node_count_off..node_count_off + 2].copy_from_slice(&node_limit.to_le_bytes());
        node[node_count_off + 2..node_count_off + 4].copy_from_slice(&(root_count as u16).to_le_bytes());

        let node_lblk = self.run_journaled(|m| {
            let node_lblk = m.append_dir_block(dir_ino, &{
                let mut n = node.clone();
                crate::csum::stamp_dx_tail(&self.sb, dir_ino, gen, &mut n, node_count_off);
                n
            })?;
            // Rewrite the root to a single entry pointing at the node, depth 1.
            let mut r = m.read_file_block_meta(dir_node, 0)?;
            r[0x1E] = 1; // indirect_levels = 1
            // entry0 = {limit@0x20 (unchanged), count@0x22, block@0x24}; the root
            // now holds ONE entry pointing at the node.
            r[0x22..0x24].copy_from_slice(&1u16.to_le_bytes()); // count = 1
            r[0x24..0x28].copy_from_slice(&node_lblk.to_le_bytes());
            crate::csum::stamp_dx_tail(&self.sb, dir_ino, gen, &mut r, 0x20);
            m.write_file_block_meta(dir_node, 0, &r)?;
            Ok(node_lblk)
        })?;

        // Re-read the inode: `append_block` above grew the extent tree with the
        // new node block, and the passed `dir_node` is now stale (it can't
        // resolve `node_lblk`). The leaf is reached through the node; retry there.
        let d2 = self.read_inode(dir_ino)?;
        self.htree_split(&d2, dir_ino, gen, leaf_lblk, node_lblk, node_count_off,
                         hash_version, new_name, new_ino, new_ft)
    }

    /// Convert a FULL single-block linear directory to an INDEXED (htree) one
    /// (Linux `make_indexed_dir`): move block 0's real entries to a fresh leaf,
    /// reformat block 0 as a dx_root pointing at it, set EXT4_INDEX_FL, then
    /// insert `(name → child)` through the now-indexed htree path. This is what
    /// keeps directory lookup O(log N) instead of letting a linear dir grow
    /// unbounded. # C: O(entries) + 3 block writes
    pub(crate) fn htree_create(
        &self, dir_ino: u32, gen: u32, name: &[u8], child_ino: u32, file_type: u8,
    ) -> Result<(), MountError> {
        let bs = self.sb.block_size as usize;
        let usable = crate::csum::dir_usable_len(&self.sb, bs);
        let dir_node = self.read_inode(dir_ino)?;

        // Collect block 0's real entries (everything but `.` and `..`).
        let blk0 = self.read_file_block_meta(&dir_node, 0)?;
        let mut dotdot = dir_ino;
        let mut reals: alloc::vec::Vec<(u32, u32, u8, alloc::vec::Vec<u8>)> = alloc::vec::Vec::new();
        dir::iter_active(&blk0[..usable.min(blk0.len())], |e| {
            if e.name == b"." {}
            else if e.name == b".." { dotdot = e.inode; }
            else { reals.push((0, e.inode, e.file_type, e.name.to_vec())); }
            true
        }).map_err(MountError::Dir)?;

        // The single leaf holds every real entry (it has more room than block 0
        // did — no `.`/`..` — so a full block 0's entries fit with the new one).
        let leaf = self.build_leaf_block(bs, usable, &reals, dir_ino, gen)?;

        // Reformat block 0 as a dx_root: dot(12) + dotdot(12, rec_len spans the
        // rest to hide the index from a linear reader) + dx_root_info + entries[0].
        let mut root = alloc::vec![0u8; bs];
        root[0..4].copy_from_slice(&dir_ino.to_le_bytes());
        root[4..6].copy_from_slice(&12u16.to_le_bytes());
        root[6] = 1; root[7] = dir::DT_DIR; root[8] = b'.';
        root[12..16].copy_from_slice(&dotdot.to_le_bytes());
        root[16..18].copy_from_slice(&((bs - 12) as u16).to_le_bytes());
        root[18] = 2; root[19] = dir::DT_DIR; root[20] = b'.'; root[21] = b'.';
        root[0x1C] = self.sb.def_hash_version; // dx_root_info.hash_version
        root[0x1D] = 8;                        // info_length
        root[0x1E] = 0;                        // indirect_levels
        let root_limit = crate::csum::dx_entry_limit(&self.sb, bs, 0x20);
        root[0x20..0x22].copy_from_slice(&root_limit.to_le_bytes()); // entry0.limit
        root[0x22..0x24].copy_from_slice(&1u16.to_le_bytes());       // entry0.count

        self.run_journaled(|m| {
            let leaf_lblk = m.append_dir_block(dir_ino, &leaf)?;
            let mut r = root.clone();
            r[0x24..0x28].copy_from_slice(&leaf_lblk.to_le_bytes()); // entry0.block → leaf
            crate::csum::stamp_dx_tail(&self.sb, dir_ino, gen, &mut r, 0x20);
            m.write_file_block_meta(&dir_node, 0, &r)?;
            // Set EXT4_INDEX_FL (i_flags @ 0x20) on the dir inode.
            let (mut ib, _off) = m.read_inode_bytes(dir_ino)?;
            let fl = u32::from_le_bytes([ib[0x20], ib[0x21], ib[0x22], ib[0x23]]) | EXT4_INDEX_FL;
            ib[0x20..0x24].copy_from_slice(&fl.to_le_bytes());
            m.write_inode_bytes(dir_ino, &ib)
        })?;

        // Now indexed — insert the triggering entry through the htree path.
        let d2 = self.read_inode(dir_ino)?;
        self.htree_insert(&d2, dir_ino, gen, name, child_ino, file_type)
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
