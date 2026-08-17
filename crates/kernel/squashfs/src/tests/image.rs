//! In-memory squashfs image builder, uncompressed by construction.
//!
//! Lays out a real little-endian squashfs image: superblock, one inode-table
//! metadata block, one directory-table metadata block for the root, a data
//! region for regular files (no fragments — every file is whole blocks, the
//! last one possibly short), and an id table. Every field is uncompressed
//! (`NOI`/`NOD`/`NOF` set); `compress.rs` owns codec coverage, not this.
//!
//! The root directory always carries a name INDEX: one header per entry, and
//! one index entry per header after the first. This is a builder choice, not
//! a mirror of what a real `mksquashfs` emits at this size — it exists so
//! every fixture exercises the indexed resume path, not just a large one.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use sectors::MemImage;

use crate::uapi::{comp, flags, itype, size, INVALID_BLK, INVALID_FRAG, INVALID_XATTR,
                   COMPRESSED_BIT, COMPRESSED_BIT_BLOCK, SQUASHFS_MAGIC, SUPER_BYTES,
                   SUPPORTED_MAJOR, SUPPORTED_MINOR};

/// The root directory's inode number. Every fixture's root is this.
pub const ROOT_INO: u32 = 1;

/// A root-level entry's payload.
enum Data {
    Reg(Vec<u8>),
    /// A regular file whose data is entirely SPARSE holes: `len` bytes read as
    /// zero, and nothing is written to the medium for it.
    Hole(u64),
    Symlink(String),
}

struct Entry { name: String, ino: u32, data: Data }

/// Builds one in-memory image. # C: see module docs
pub struct Builder {
    block_size: u32,
    entries: Vec<Entry>,
    next_ino: u32,
}

impl Builder {
    /// # C: O(1)
    pub fn new() -> Self { Self { block_size: 131072, entries: Vec::new(), next_ino: 2 } }

    /// Override the image's data block size. Must be a power of two, at
    /// least the page size and at most the format's block-size cap — the
    /// same rule [`crate::superblock::Super::parse`] enforces. # C: O(1)
    pub fn block_size(mut self, bs: u32) -> Self { self.block_size = bs; self }

    /// Add a regular file at the root. # C: O(1)
    pub fn file(mut self, name: &str, data: &[u8]) -> Self {
        let ino = self.next_ino; self.next_ino += 1;
        self.entries.push(Entry { name: name.to_string(), ino, data: Data::Reg(data.to_vec()) });
        self
    }

    /// Add a regular file of `len` bytes, stored entirely as sparse holes.
    /// # C: O(1)
    pub fn hole_file(mut self, name: &str, len: u64) -> Self {
        let ino = self.next_ino; self.next_ino += 1;
        self.entries.push(Entry { name: name.to_string(), ino, data: Data::Hole(len) });
        self
    }

    /// Add a symlink at the root. # C: O(1)
    pub fn symlink(mut self, name: &str, target: &str) -> Self {
        let ino = self.next_ino; self.next_ino += 1;
        self.entries.push(Entry { name: name.to_string(), ino,
            data: Data::Symlink(target.to_string()) });
        self
    }

    /// Assemble the image and wrap it in a byte-addressed [`MemImage`].
    /// # C: O(image bytes)
    pub fn build(self) -> MemImage { MemImage::from_bytes(1, self.build_bytes()) }

    /// Assemble the image bytes directly, for tests that want to corrupt one
    /// field before mounting. # C: O(image bytes)
    pub fn build_bytes(self) -> Vec<u8> {
        let bs = self.block_size;
        // Root's entries are listed in NAME order — the on-disk contract
        // `lookup` relies on to stop early.
        let mut sorted: Vec<&Entry> = self.entries.iter().collect();
        sorted.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));

        let mut buf = alloc::vec![0u8; SUPER_BYTES];

        // ---- data blocks (regular files only; holes write nothing) --------
        let mut data_of: Vec<(u32, u64, Vec<u32>, u64)> = Vec::new(); // (ino, start, block_words, size)
        for e in &self.entries {
            match &e.data {
                Data::Reg(bytes) => {
                    let start = buf.len() as u64;
                    let mut words = Vec::new();
                    for chunk in bytes.chunks(bs as usize) {
                        words.push(chunk.len() as u32 | COMPRESSED_BIT_BLOCK);
                        buf.extend_from_slice(chunk);
                    }
                    if bytes.is_empty() { words.clear(); }
                    data_of.push((e.ino, start, words, bytes.len() as u64));
                }
                Data::Hole(len) => {
                    let n = len.div_ceil(u64::from(bs));
                    let words = alloc::vec![COMPRESSED_BIT_BLOCK; n as usize];
                    data_of.push((e.ino, 0, words, *len));
                }
                Data::Symlink(_) => {}
            }
        }

        // ---- directory listing layout (byte sizes only, root fits one block) ----
        struct Hdr { name_len: usize, cum_before: u32 }
        let mut hdrs = Vec::new();
        let mut cum = 0u32;
        for e in &sorted {
            hdrs.push(Hdr { name_len: e.name.len(), cum_before: cum });
            cum += (size::DIR_HEADER + size::DIR_ENTRY + e.name.len()) as u32;
        }
        let listing_len = cum;

        // Index: one entry per header after the first.
        let index_count = hdrs.len().saturating_sub(1);
        let mut index_bytes_len = 0usize;
        for h in hdrs.iter().skip(1) { index_bytes_len += size::DIR_INDEX + h.name_len; }

        // ---- inode table (single metadata block) --------------------------
        let root_index_off = size::LDIR_INODE;
        let mut off = root_index_off + index_bytes_len;
        let mut inode_off = Vec::new(); // (ino, offset)
        for e in &self.entries {
            inode_off.push((e.ino, off as u16));
            off += match &e.data {
                Data::Reg(_) | Data::Hole(_) => {
                    let n = data_of.iter().find(|(i, ..)| *i == e.ino).unwrap().2.len();
                    size::REG_INODE + n * size::BLOCK_LIST_ENTRY
                }
                Data::Symlink(t) => size::SYMLINK_INODE + t.len(),
            };
        }
        let inode_payload_len = off;

        let mut inode_payload = alloc::vec![0u8; inode_payload_len];
        // root LDIR
        put_u16(&mut inode_payload, 0, itype::LDIR);
        put_u16(&mut inode_payload, 2, 0o755); // mode, no S_IFMT bits
        put_u16(&mut inode_payload, 4, 0); // uid idx
        put_u16(&mut inode_payload, 6, 0); // gid idx
        put_u32(&mut inode_payload, 8, 0); // mtime
        put_u32(&mut inode_payload, 12, ROOT_INO);
        put_u32(&mut inode_payload, 16, sorted.len() as u32 + 2); // nlink
        put_u32(&mut inode_payload, 20, listing_len); // size
        put_u32(&mut inode_payload, 24, 0); // start_block (dir table, single block)
        put_u32(&mut inode_payload, 28, ROOT_INO); // parent: root is its own parent
        put_u16(&mut inode_payload, 32, index_count as u16);
        put_u16(&mut inode_payload, 34, 0); // offset within dir table block
        put_u32(&mut inode_payload, 36, INVALID_XATTR);
        // root's directory index, inline right after the LDIR struct
        let mut p = root_index_off;
        for (i, h) in hdrs.iter().enumerate().skip(1) {
            put_u32(&mut inode_payload, p, h.cum_before);
            put_u32(&mut inode_payload, p + 4, 0); // start_block: same single block
            put_u32(&mut inode_payload, p + 8, (h.name_len - 1) as u32);
            p += size::DIR_INDEX;
            let name = &sorted[i].name;
            inode_payload[p..p + name.len()].copy_from_slice(name.as_bytes());
            p += name.len();
        }
        // per-entry inodes, in INSERTION order (matches inode_off above)
        for e in &self.entries {
            let at = inode_off.iter().find(|(i, _)| *i == e.ino).unwrap().1 as usize;
            put_u16(&mut inode_payload, at, 0); // type_word set below
            put_u16(&mut inode_payload, at + 2, 0o644);
            put_u16(&mut inode_payload, at + 4, 0);
            put_u16(&mut inode_payload, at + 6, 0);
            put_u32(&mut inode_payload, at + 8, 0);
            put_u32(&mut inode_payload, at + 12, e.ino);
            match &e.data {
                Data::Reg(_) | Data::Hole(_) => {
                    put_u16(&mut inode_payload, at, itype::REG);
                    let (_, start, words, size) =
                        data_of.iter().find(|(i, ..)| *i == e.ino).unwrap();
                    put_u32(&mut inode_payload, at + 16, *start as u32);
                    put_u32(&mut inode_payload, at + 20, INVALID_FRAG);
                    put_u32(&mut inode_payload, at + 24, 0);
                    put_u32(&mut inode_payload, at + 28, *size as u32);
                    let mut q = at + size::REG_INODE;
                    for w in words { put_u32(&mut inode_payload, q, *w); q += 4; }
                }
                Data::Symlink(t) => {
                    put_u16(&mut inode_payload, at, itype::SYMLINK);
                    put_u32(&mut inode_payload, at + 16, 1); // nlink
                    put_u32(&mut inode_payload, at + 20, t.len() as u32);
                    inode_payload[at + 24..at + 24 + t.len()].copy_from_slice(t.as_bytes());
                }
            }
        }
        let inode_table_start = buf.len() as u64;
        append_meta_block(&mut buf, &inode_payload);

        // ---- directory table (single metadata block) -----------------------
        let mut dir_payload = alloc::vec![0u8; listing_len as usize];
        let mut q = 0usize;
        for e in &sorted {
            let this_off = inode_off.iter().find(|(i, _)| *i == e.ino).unwrap().1;
            put_u32(&mut dir_payload, q, 0); // count - 1 == 0 (one entry per header)
            put_u32(&mut dir_payload, q + 4, 0); // inode block, relative to inode table
            put_u32(&mut dir_payload, q + 8, e.ino); // base_ino
            q += size::DIR_HEADER;
            put_u16(&mut dir_payload, q, this_off); // inode offset
            put_u16(&mut dir_payload, q + 2, 0); // delta 0: base_ino IS this entry's ino
            let type_word = match &e.data {
                Data::Reg(_) | Data::Hole(_) => itype::REG,
                Data::Symlink(_) => itype::SYMLINK,
            };
            put_u16(&mut dir_payload, q + 4, type_word);
            put_u16(&mut dir_payload, q + 6, (e.name.len() - 1) as u16);
            q += size::DIR_ENTRY;
            dir_payload[q..q + e.name.len()].copy_from_slice(e.name.as_bytes());
            q += e.name.len();
        }
        let directory_table_start = buf.len() as u64;
        append_meta_block(&mut buf, &dir_payload);

        // ---- id table: one id (0), one data block, one index entry --------
        let id_data_addr = buf.len() as u64;
        append_meta_block(&mut buf, &0u32.to_le_bytes());
        let id_table_start = buf.len() as u64;
        buf.extend_from_slice(&id_data_addr.to_le_bytes());

        let bytes_used = buf.len() as u64;

        // ---- superblock -----------------------------------------------------
        put_u32(&mut buf, 0, SQUASHFS_MAGIC);
        put_u32(&mut buf, 4, self.next_ino - 1);
        put_u32(&mut buf, 8, 0);
        put_u32(&mut buf, 12, bs);
        put_u32(&mut buf, 16, 0); // fragments
        put_u16(&mut buf, 20, comp::ZLIB);
        put_u16(&mut buf, 22, bs.trailing_zeros() as u16); // block_log
        put_u16(&mut buf, 24, (1 << flags::NOI) | (1 << flags::NOD) | (1 << flags::NOF));
        put_u16(&mut buf, 26, 1); // no_ids
        put_u16(&mut buf, 28, SUPPORTED_MAJOR);
        put_u16(&mut buf, 30, SUPPORTED_MINOR);
        put_u64(&mut buf, 32, 0); // root_inode: block 0, offset 0
        put_u64(&mut buf, 40, bytes_used);
        put_u64(&mut buf, 48, id_table_start);
        put_u64(&mut buf, 56, INVALID_BLK);
        put_u64(&mut buf, 64, inode_table_start);
        put_u64(&mut buf, 72, directory_table_start);
        put_u64(&mut buf, 80, INVALID_BLK);
        put_u64(&mut buf, 88, INVALID_BLK);

        buf
    }
}

impl Default for Builder { fn default() -> Self { Self::new() } }

fn put_u16(buf: &mut [u8], off: usize, v: u16) { buf[off..off + 2].copy_from_slice(&v.to_le_bytes()); }
fn put_u32(buf: &mut [u8], off: usize, v: u32) { buf[off..off + 4].copy_from_slice(&v.to_le_bytes()); }
fn put_u64(buf: &mut [u8], off: usize, v: u64) { buf[off..off + 8].copy_from_slice(&v.to_le_bytes()); }

/// Append one uncompressed metadata block (length word + payload), returning
/// the address of its length word. # C: O(payload bytes)
fn append_meta_block(buf: &mut Vec<u8>, payload: &[u8]) -> u64 {
    let addr = buf.len() as u64;
    let word = (payload.len() as u16) | COMPRESSED_BIT;
    buf.extend_from_slice(&word.to_le_bytes());
    buf.extend_from_slice(payload);
    addr
}
