// External xattr block (`i_file_acl` target) encoder + hashes. The decoder
// (`decode_block`) and the placement orchestration (`Mount::store_xattrs`) live
// in the parent `xattr` module; this owns building a Linux-valid block buffer
// (header + sorted entries + per-entry `e_hash` + block `h_hash`). The
// `h_checksum` is stamped by the caller (needs the block address).

use alloc::string::String;
use alloc::vec::Vec;

use super::{BLOCK_HDR_LEN, ENTRY_HDR_LEN, EXT4_XATTR_MAGIC, split_name, xattr_suffix_bytes,
            xattr_entry_len, xattr_value_size};

/// `ext4_xattr_hash_entry`: name-then-value rolling hash for `e_hash`. Value is
/// hashed as 4-byte little-endian words over the padded (`EXT4_XATTR_SIZE`)
/// value length — the trailing pad bytes are zero. # C: O(name + value)
fn entry_hash(name: &[u8], value: &[u8]) -> u32 {
    const NAME_SHIFT: u32 = 5;
    const VALUE_SHIFT: u32 = 16;
    let mut hash: u32 = 0;
    for &c in name {
        hash = (hash << NAME_SHIFT) ^ (hash >> (32 - NAME_SHIFT)) ^ (c as u32);
    }
    if !value.is_empty() {
        let nwords = xattr_value_size(value.len()) / 4;
        for w in 0..nwords {
            let mut word = [0u8; 4];
            for (b, slot) in word.iter_mut().enumerate() {
                let idx = w * 4 + b;
                if idx < value.len() { *slot = value[idx]; }
            }
            let v = u32::from_le_bytes(word);
            hash = (hash << VALUE_SHIFT) ^ (hash >> (32 - VALUE_SHIFT)) ^ v;
        }
    }
    hash
}

/// `ext4_xattr_rehash`: fold the per-entry `e_hash`es into the block `h_hash`.
/// A zero `e_hash` forces `h_hash = 0` (Linux marks the block non-shareable),
/// so this must run over entries in on-disk order. # C: O(N)
fn block_hash(entry_hashes: &[u32]) -> u32 {
    const BLOCK_SHIFT: u32 = 16;
    let mut hash: u32 = 0;
    for &eh in entry_hashes {
        if eh == 0 { return 0; }
        hash = (hash << BLOCK_SHIFT) ^ (hash >> (32 - BLOCK_SHIFT)) ^ eh;
    }
    hash
}

/// Encode `entries` into a fresh EXTERNAL xattr block of `bs` bytes:
/// `ext4_xattr_header` (magic, refcount=1, blocks=1, h_hash) + sorted entries
/// (each carrying its `e_hash`) growing up from offset 32, values growing down
/// from the block end (offsets relative to block start, per `decode_block`).
/// `Err(())` if the on-disk-expressible entries do not fit one block, or there
/// are none (caller frees the block instead). The `h_checksum` is stamped
/// separately (needs the block address). # C: O(N log N)
pub fn encode_block(entries: &[(String, Vec<u8>)], bs: usize) -> Result<Vec<u8>, ()> {
    if bs < BLOCK_HDR_LEN + 4 { return Err(()); }
    let mut sorted: Vec<(u8, Vec<u8>, &[u8])> = Vec::with_capacity(entries.len());
    for (full, val) in entries {
        if let Some((idx, suffix)) = split_name(full) {
            let name = xattr_suffix_bytes(suffix);
            if name.len() > u8::MAX as usize { return Err(()); }
            sorted.push((idx, name, val.as_slice()));
        }
    }
    if sorted.is_empty() { return Err(()); }
    sorted.sort_unstable_by(|a, b| a.0.cmp(&b.0)
        .then(a.1.len().cmp(&b.1.len()))
        .then(a.1.cmp(&b.1)));

    let mut blk = alloc::vec![0u8; bs];
    blk[0..4].copy_from_slice(&EXT4_XATTR_MAGIC.to_le_bytes());
    blk[4..8].copy_from_slice(&1u32.to_le_bytes());   // h_refcount = 1 (not shared)
    blk[8..12].copy_from_slice(&1u32.to_le_bytes());  // h_blocks = 1
    let mut entry_ptr = BLOCK_HDR_LEN;
    let mut value_end = bs;
    let mut e_hashes: Vec<u32> = Vec::with_capacity(sorted.len());
    for (idx, suffix, val) in &sorted {
        let name_bytes = suffix.as_slice();
        let name_len = name_bytes.len();
        let elen = xattr_entry_len(name_len);
        let vsize = xattr_value_size(val.len());
        if value_end < BLOCK_HDR_LEN + vsize { return Err(()); }
        let value_pos = value_end - vsize;
        // Entry headers (up) + the 4-byte terminator must not overrun the
        // values (down).
        if entry_ptr + elen + 4 > value_pos { return Err(()); }
        // e_value_offs is relative to the block start (base_off = 0).
        blk[value_pos..value_pos + val.len()].copy_from_slice(val);
        blk[entry_ptr] = name_len as u8;
        blk[entry_ptr + 1] = *idx;
        blk[entry_ptr + 2..entry_ptr + 4].copy_from_slice(&(value_pos as u16).to_le_bytes());
        // e_value_inum = 0 (inline) — zeroed region.
        blk[entry_ptr + 8..entry_ptr + 12].copy_from_slice(&(val.len() as u32).to_le_bytes());
        let eh = entry_hash(name_bytes, val);
        blk[entry_ptr + 12..entry_ptr + 16].copy_from_slice(&eh.to_le_bytes());
        e_hashes.push(eh);
        blk[entry_ptr + ENTRY_HDR_LEN..entry_ptr + ENTRY_HDR_LEN + name_len]
            .copy_from_slice(name_bytes);
        entry_ptr += elen;
        value_end = value_pos;
    }
    let hh = block_hash(&e_hashes);
    blk[12..16].copy_from_slice(&hh.to_le_bytes());
    Ok(blk)
}
