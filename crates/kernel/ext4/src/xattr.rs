// Two on-disk homes for an inode's xattrs:
//   * IN-INODE (ibody): the space between the inode's `i_extra_isize` end and
//     the inode record end holds `ext4_xattr_ibody_header` (4-byte magic
//     0xEA020000) + a sorted `ext4_xattr_entry[]` (entries grow UP from
//     `IFIRST`) + the value bytes (grow DOWN from the inode-record end).
//   * EXTERNAL block (`i_file_acl`): a single fs-block beginning with the
//     32-byte `ext4_xattr_header`, then the same entry+value layout keyed to
//     the block start.
//
// This module is the bridge between that disk format and the in-core
// `vfs::SimpleXattrs` store attached to every ext4 inode (D45). IBODY and the
// single EXTERNAL block are both read on load and rewritten by `store_xattrs`.
//
extern crate alloc;
mod lifecycle;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use vfs::SimpleXattrs;

use crate::csum::EXT4_GOOD_OLD_INODE_SIZE;
use crate::mount::{Mount, MountError};

/// `EXT4_XATTR_MAGIC` (`ext4_xattr_{ibody_,}header.h_magic`), stored `__le32`.
pub const EXT4_XATTR_MAGIC: u32 = 0xEA02_0000;
/// `sizeof(struct ext4_xattr_entry)` — the fixed per-entry header.
const ENTRY_HDR_LEN: usize = 16;
/// `sizeof(struct ext4_xattr_header)` — the external-block header.
const BLOCK_HDR_LEN: usize = 32;
/// Default `i_extra_isize` (`mke2fs` writes 32 for 256-byte inodes).
const DEFAULT_EXTRA_ISIZE: usize = 32;
const XATTR_NS_USER: u8 = 1;
const XATTR_NS_POSIX_ACL_ACCESS: u8 = 2;
const XATTR_NS_POSIX_ACL_DEFAULT: u8 = 3;
const XATTR_NS_TRUSTED: u8 = 4;
const XATTR_NS_SECURITY: u8 = 6;
const XATTR_NS_SYSTEM: u8 = 7;

/// `EXT4_XATTR_LEN(name_len)` — on-disk entry record size, 4-byte aligned.
#[inline]
fn xattr_entry_len(name_len: usize) -> usize { (name_len + 3 + ENTRY_HDR_LEN) & !3 }

/// `EXT4_XATTR_SIZE(value_len)` — on-disk value slot size, 4-byte aligned.
#[inline]
fn xattr_value_size(value_len: usize) -> usize { (value_len + 3) & !3 }

/// Split a full xattr name into `(e_name_index, suffix)` per the ext4 prefix
/// table. `None` for a name in no known namespace (caller leaves it in-core
/// only). # C: O(1)
fn split_name(full: &str) -> Option<(u8, &str)> {
    if let Some(rest) = full.strip_prefix("user.")     { return Some((XATTR_NS_USER, rest)); }
    if full == "system.posix_acl_access"               { return Some((XATTR_NS_POSIX_ACL_ACCESS, "")); }
    if full == "system.posix_acl_default"              { return Some((XATTR_NS_POSIX_ACL_DEFAULT, "")); }
    if let Some(rest) = full.strip_prefix("trusted.")  { return Some((XATTR_NS_TRUSTED, rest)); }
    if let Some(rest) = full.strip_prefix("security.") { return Some((XATTR_NS_SECURITY, rest)); }
    if let Some(rest) = full.strip_prefix("system.")   { return Some((XATTR_NS_SYSTEM, rest)); }
    None
}

/// Reconstruct the full xattr name from `(e_name_index, e_name)`. For the
/// POSIX-ACL indices (2/3) the name IS the prefix (`e_name` is empty). # C: O(1)
fn join_name(name_index: u8, name: &str) -> Option<String> {
    let prefix = match name_index {
        XATTR_NS_USER => "user.",
        XATTR_NS_POSIX_ACL_ACCESS => return Some("system.posix_acl_access".to_string()),
        XATTR_NS_POSIX_ACL_DEFAULT => return Some("system.posix_acl_default".to_string()),
        XATTR_NS_TRUSTED => "trusted.",
        XATTR_NS_SECURITY => "security.",
        XATTR_NS_SYSTEM => "system.",
        _ => return None,
    };
    let mut s = String::with_capacity(prefix.len() + name.len());
    s.push_str(prefix);
    s.push_str(name);
    Some(s)
}

fn xattr_suffix_from_bytes(name: &[u8]) -> String {
    vfs::path_from_bytes(name)
}

pub(super) fn xattr_suffix_bytes(name: &str) -> Vec<u8> {
    vfs::path_into_bytes(name)
}

/// Decode an entry+value stream into `(full_name, value)` pairs. `first_off` is
/// the byte offset of the first `ext4_xattr_entry`; `base_off` is the offset
/// `e_value_offs` is relative to (= `first_off` for ibody, = block start for the
/// external block); `end_off` bounds the region. Inline values only (an entry
/// with `e_value_inum != 0` stores its value in a separate inode — skipped).
/// # C: O(N_entries)
fn decode_entries(buf: &[u8], first_off: usize, base_off: usize, end_off: usize,
                  out: &mut Vec<(String, Vec<u8>)>)
{
    let mut p = first_off;
    loop {
        if p + 4 > end_off { break; }
        // IS_LAST_ENTRY: a zero u32 (name_len==0, name_index==0, value_offs==0).
        if buf[p] == 0 && buf[p + 1] == 0 && buf[p + 2] == 0 && buf[p + 3] == 0 { break; }
        if p + ENTRY_HDR_LEN > end_off { break; }
        let name_len   = buf[p] as usize;
        let name_index = buf[p + 1];
        let value_offs = u16::from_le_bytes([buf[p + 2], buf[p + 3]]) as usize;
        let value_inum = u32::from_le_bytes([buf[p + 4], buf[p + 5], buf[p + 6], buf[p + 7]]);
        let value_size = u32::from_le_bytes([buf[p + 8], buf[p + 9], buf[p + 10], buf[p + 11]]) as usize;
        let name_start = p + ENTRY_HDR_LEN;
        let name_end   = name_start + name_len;
        if name_end > end_off { break; }
        let next = p + xattr_entry_len(name_len);
        // Inline values only; external-value-inode entries are skipped.
        if value_inum == 0 {
            let v_start = base_off + value_offs;
            let v_end   = v_start + value_size;
            if v_end <= end_off {
                let name = xattr_suffix_from_bytes(&buf[name_start..name_end]);
                if let Some(full) = join_name(name_index, &name) {
                    out.push((full, buf[v_start..v_end].to_vec()));
                }
            }
        }
        if next <= p { break; } // guard against a malformed zero-length stride
        p = next;
    }
}

/// Decode the IBODY xattr area of a raw inode (`hdr_off` = `128 + i_extra_isize`).
/// Empty when the magic is absent. # C: O(N_entries)
pub fn decode_ibody(ino_bytes: &[u8], hdr_off: usize, isize: usize) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    if hdr_off + 4 > isize { return out; }
    let magic = u32::from_le_bytes([ino_bytes[hdr_off], ino_bytes[hdr_off + 1],
                                    ino_bytes[hdr_off + 2], ino_bytes[hdr_off + 3]]);
    if magic != EXT4_XATTR_MAGIC { return out; }
    let base = hdr_off + 4; // IFIRST — value offsets are relative to this
    decode_entries(ino_bytes, base, base, isize, &mut out);
    out
}

/// Decode an EXTERNAL xattr block (`i_file_acl` target). Entries begin after the
/// 32-byte header; value offsets are relative to the block start. # C: O(N)
pub fn decode_block(blk: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    if blk.len() < BLOCK_HDR_LEN + 4 { return out; }
    let magic = u32::from_le_bytes([blk[0], blk[1], blk[2], blk[3]]);
    if magic != EXT4_XATTR_MAGIC { return out; }
    decode_entries(blk, BLOCK_HDR_LEN, 0, blk.len(), &mut out);
    out
}

/// Encode `entries` into the IBODY region `[hdr_off..isize]` of a raw inode
/// buffer. The region is zeroed first; an empty `entries` leaves it all-zero
/// (no magic — matching Linux clearing the last ibody xattr). Entries are
/// sorted (`e_name_index`, name_len, name) as Linux maintains them. Returns
/// `Err(())` if the entries + values do not fit. # C: O(N log N)
pub fn encode_ibody(ino_bytes: &mut [u8], hdr_off: usize, isize: usize,
                    entries: &[(String, Vec<u8>)]) -> Result<(), ()>
{
    if hdr_off > isize { return Err(()); }
    for b in ino_bytes[hdr_off..isize].iter_mut() { *b = 0; }
    if entries.is_empty() { return Ok(()); }
    if hdr_off + 4 > isize { return Err(()); }

    // Split + sort. Names in no known namespace are dropped (cannot be
    // expressed on disk); they survive only in the in-core store.
    let mut sorted: Vec<(u8, Vec<u8>, &[u8])> = Vec::with_capacity(entries.len());
    for (full, val) in entries {
        if let Some((idx, suffix)) = split_name(full) {
            let name = xattr_suffix_bytes(suffix);
            if name.len() > u8::MAX as usize { return Err(()); }
            sorted.push((idx, name, val.as_slice()));
        }
    }
    if sorted.is_empty() {
        // Nothing on-disk-expressible; leave the (already zeroed) no-magic region.
        return Ok(());
    }
    sorted.sort_by(|a, b| a.0.cmp(&b.0)
        .then(a.1.len().cmp(&b.1.len()))
        .then(a.1.cmp(&b.1)));

    ino_bytes[hdr_off..hdr_off + 4].copy_from_slice(&EXT4_XATTR_MAGIC.to_le_bytes());
    let base = hdr_off + 4;
    let mut entry_ptr = base;
    let mut value_end = isize;

    for (idx, suffix, val) in &sorted {
        let name_bytes = suffix.as_slice();
        let name_len = name_bytes.len();
        let elen = xattr_entry_len(name_len);
        let vsize = xattr_value_size(val.len());
        if value_end < base + vsize { return Err(()); }
        let value_pos = value_end - vsize;
        // Entry headers (growing up) + the 4-byte terminator must not collide
        // with the values (growing down).
        if entry_ptr + elen + 4 > value_pos { return Err(()); }
        let value_offs = value_pos - base;
        ino_bytes[value_pos..value_pos + val.len()].copy_from_slice(val);
        ino_bytes[entry_ptr] = name_len as u8;
        ino_bytes[entry_ptr + 1] = *idx;
        ino_bytes[entry_ptr + 2..entry_ptr + 4].copy_from_slice(&(value_offs as u16).to_le_bytes());
        // e_value_inum = 0 (inline) — region already zeroed.
        ino_bytes[entry_ptr + 8..entry_ptr + 12].copy_from_slice(&(val.len() as u32).to_le_bytes());
        // e_hash = 0 (ibody entries carry no hash) — region already zeroed.
        ino_bytes[entry_ptr + ENTRY_HDR_LEN..entry_ptr + ENTRY_HDR_LEN + name_len]
            .copy_from_slice(name_bytes);
        entry_ptr += elen;
        value_end = value_pos;
    }
    // 4-byte terminator already present (zeroed region).
    Ok(())
}

#[path = "xattr/external.rs"]
mod external;
pub use external::encode_block;

impl Mount {
    /// `i_extra_isize` from a raw inode buffer, sanity-bounded so the ibody
    /// header lands inside the inode record. 0 = no ibody xattr area. # C: O(1)
    fn extra_isize_of(ino_bytes: &[u8], isize: usize) -> usize {
        if isize <= EXT4_GOOD_OLD_INODE_SIZE { return 0; }
        let v = u16::from_le_bytes([ino_bytes[0x80], ino_bytes[0x81]]) as usize;
        if EXT4_GOOD_OLD_INODE_SIZE + v + 4 > isize { 0 } else { v }
    }

    /// Read `i_file_acl` (external xattr block LBA) from a raw inode buffer:
    /// `i_file_acl_lo` @0x68 merged with `l_i_file_acl_high` @0x76. # C: O(1)
    fn file_acl_of(ino_bytes: &[u8]) -> u64 {
        let lo = u32::from_le_bytes([ino_bytes[0x68], ino_bytes[0x69], ino_bytes[0x6A], ino_bytes[0x6B]]) as u64;
        let hi = u16::from_le_bytes([ino_bytes[0x76], ino_bytes[0x77]]) as u64;
        lo | (hi << 32)
    }

    /// Populate `store` (the inode's in-core `SimpleXattrs`) from disk: the
    /// EXTERNAL block first, then the IBODY area (ibody wins on a name clash).
    /// Called at `iget`/build so xattrs survive eviction + remount. Read-only —
    /// never rewrites the inode, so no-xattr inodes are untouched. # C: O(N)
    pub fn load_xattrs(&self, ino: u32, store: &SimpleXattrs) {
        let isize = self.sb.inode_size as usize;
        let (bytes, _off) = match self.read_inode_bytes(ino) { Ok(x) => x, Err(_) => return };
        let facl = Self::file_acl_of(&bytes);
        if facl != 0 {
            if let Ok(blk) = self.read_metadata_block(facl) {
                for (n, v) in decode_block(&blk) { let _ = store.set(&n, v, false, false); }
            }
        }
        let extra = Self::extra_isize_of(&bytes, isize);
        if extra != 0 {
            for (n, v) in decode_ibody(&bytes, EXT4_GOOD_OLD_INODE_SIZE + extra, isize) {
                let _ = store.set(&n, v, false, false);
            }
        }
    }

    /// Re-encode the full xattr set into the inode's IBODY area and write the
    /// inode back (journaled). `NoSpace` if the entries do not fit ibody; callers
    /// needing Linux placement should use `store_xattrs`. # C: O(N) encode +
    /// O(1) journaled I/O
    pub fn store_ibody_xattrs(&self, ino: u32, entries: &[(String, Vec<u8>)]) -> Result<(), MountError> {
        let isize = self.sb.inode_size as usize;
        if isize <= EXT4_GOOD_OLD_INODE_SIZE { return Err(MountError::NoSpace); }
        self.run_journaled(|m| {
            let (mut bytes, _off) = m.read_inode_bytes(ino)?;
            // Use the on-disk i_extra_isize; if absent but the fs has the space,
            // stamp the standard 32 (matches `init_inode`) before placing xattrs.
            let mut extra = Self::extra_isize_of(&bytes, isize);
            if extra == 0 {
                if EXT4_GOOD_OLD_INODE_SIZE + DEFAULT_EXTRA_ISIZE + 4 > isize {
                    return Err(MountError::NoSpace);
                }
                if !entries.is_empty() {
                    bytes[0x80..0x82].copy_from_slice(&(DEFAULT_EXTRA_ISIZE as u16).to_le_bytes());
                    extra = DEFAULT_EXTRA_ISIZE;
                } else {
                    return Ok(()); // nothing to write, no extra area — leave inode as-is
                }
            }
            let hdr_off = EXT4_GOOD_OLD_INODE_SIZE + extra;
            encode_ibody(&mut bytes, hdr_off, isize, entries).map_err(|_| MountError::NoSpace)?;
            m.write_inode_bytes(ino, &bytes)?;
            Ok(())
        })
    }

    /// Persist the full xattr set (Linux `ext4_xattr_set_handle` placement): try
    /// the IBODY first; on overflow spill ALL on-disk entries to the EXTERNAL
    /// block (`i_file_acl`), allocating one if needed and stamping its
    /// header/hash/csum. When everything fits IBODY, any previously-allocated
    /// external block is freed (else its stale entries would resurface, since
    /// `load_xattrs` reads the block too). One journaled transaction. `NoSpace`
    /// if the entries fit neither IBODY nor one external block. # C: O(N) + I/O
    pub fn store_xattrs(&self, ino: u32, entries: &[(String, Vec<u8>)]) -> Result<(), MountError> {
        let isize = self.sb.inode_size as usize;
        if isize <= EXT4_GOOD_OLD_INODE_SIZE { return Err(MountError::NoSpace); }
        let bs = self.sb.block_size as usize;
        self.run_journaled(|m| {
            let (mut bytes, _off) = m.read_inode_bytes(ino)?;
            let mut extra = Self::extra_isize_of(&bytes, isize);
            if extra == 0 {
                if EXT4_GOOD_OLD_INODE_SIZE + DEFAULT_EXTRA_ISIZE + 4 > isize {
                    return Err(MountError::NoSpace);
                }
                bytes[0x80..0x82].copy_from_slice(&(DEFAULT_EXTRA_ISIZE as u16).to_le_bytes());
                extra = DEFAULT_EXTRA_ISIZE;
            }
            let hdr_off = EXT4_GOOD_OLD_INODE_SIZE + extra;
            let old_facl = Self::file_acl_of(&bytes);
            // Try IBODY-only. Encode into the live buffer; on overflow the buffer
            // is discarded (re-read) before the external path.
            if encode_ibody(&mut bytes, hdr_off, isize, entries).is_ok() {
                let old_sectors = Self::i_blocks_of(&bytes);
                if old_facl != 0 { Self::detach_external_block(&mut bytes, bs); }
                let new_sectors = Self::i_blocks_of(&bytes);
                if old_facl != 0 {
                    m.account_i_blocks_delta(ino, old_sectors, new_sectors)?;
                }
                if let Err(e) = m.write_inode_bytes(ino, &bytes) {
                    if old_facl != 0 { return Err(m.rollback_i_blocks_delta(ino, new_sectors, old_sectors, e)); }
                    return Err(e)
                }
                if old_facl != 0 {
                    if let Err(e) = m.free_block(old_facl) {
                        return Err(m.rollback_i_blocks_delta(ino, new_sectors, old_sectors, e));
                    }
                }
                return Ok(());
            }
            // IBODY overflow → external block. Re-read to drop the partial encode.
            let (mut bytes, _off) = m.read_inode_bytes(ino)?;
            encode_ibody(&mut bytes, hdr_off, isize, &[]).map_err(|_| MountError::NoSpace)?;
            let mut blk = encode_block(entries, bs).map_err(|_| MountError::NoSpace)?;
            let old_sectors = Self::i_blocks_of(&bytes);
            let mut charged_sectors = old_sectors;
            let block_nr = if old_facl != 0 { old_facl } else {
                charged_sectors = old_sectors.saturating_add((bs / 512) as u32);
                m.account_i_blocks_delta(ino, old_sectors, charged_sectors)?;
                let b = match m.alloc_block(0) {
                    Ok(b) => b,
                    Err(e) => {
                        return Err(m.rollback_i_blocks_delta(ino, charged_sectors, old_sectors, e));
                    }
                };
                Self::attach_external_block(&mut bytes, b, bs);
                b
            };
            crate::csum::stamp_xattr_block_csum(&m.sb, block_nr, &mut blk);
            if let Err(e) = m.metadata_write(block_nr * bs as u64, &blk) {
                if old_facl == 0 {
                    let _ = m.free_block(block_nr);
                    return Err(m.rollback_i_blocks_delta(ino, charged_sectors, old_sectors, e));
                }
                return Err(e);
            }
            if let Err(e) = m.write_inode_bytes(ino, &bytes) {
                if old_facl == 0 {
                    let _ = m.free_block(block_nr);
                    return Err(m.rollback_i_blocks_delta(ino, charged_sectors, old_sectors, e));
                }
                return Err(e);
            }
            Ok(())
        })
    }

    /// Low 32 bits of ext4 `i_blocks`. # C: O(1)
    fn i_blocks_of(bytes: &[u8]) -> u32 {
        u32::from_le_bytes([bytes[0x1C], bytes[0x1D], bytes[0x1E], bytes[0x1F]])
    }

    /// Point `i_file_acl` at `block_nr` and add its one fs-block to `i_blocks`.
    /// # C: O(1)
    fn attach_external_block(bytes: &mut [u8], block_nr: u64, bs: usize) {
        bytes[0x68..0x6C].copy_from_slice(&((block_nr & 0xFFFF_FFFF) as u32).to_le_bytes());
        bytes[0x76..0x78].copy_from_slice(&(((block_nr >> 32) & 0xFFFF) as u16).to_le_bytes());
        let sectors = (bs / 512) as u32;
        let ib = u32::from_le_bytes([bytes[0x1C], bytes[0x1D], bytes[0x1E], bytes[0x1F]]);
        bytes[0x1C..0x20].copy_from_slice(&ib.saturating_add(sectors).to_le_bytes());
    }

    /// Clear `i_file_acl` and subtract its fs-block from `i_blocks` (block is
    /// freed by the caller after the inode write). # C: O(1)
    fn detach_external_block(bytes: &mut [u8], bs: usize) {
        bytes[0x68..0x6C].copy_from_slice(&0u32.to_le_bytes());
        bytes[0x76..0x78].copy_from_slice(&0u16.to_le_bytes());
        let sectors = (bs / 512) as u32;
        let ib = u32::from_le_bytes([bytes[0x1C], bytes[0x1D], bytes[0x1E], bytes[0x1F]]);
        bytes[0x1C..0x20].copy_from_slice(&ib.saturating_sub(sectors).to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISIZE: usize = 256;
    const HDR: usize = 160; // 128 + 32

    fn blank_inode() -> Vec<u8> {
        let mut b = alloc::vec![0u8; ISIZE];
        b[0x80..0x82].copy_from_slice(&32u16.to_le_bytes()); // i_extra_isize
        b
    }

    #[test]
    fn name_split_join_roundtrip() {
        for full in ["user.foo", "trusted.x", "security.selinux", "system.bar",
                     "system.posix_acl_access", "system.posix_acl_default"] {
            let (idx, suffix) = split_name(full).expect("split");
            assert_eq!(join_name(idx, suffix).as_deref(), Some(full));
        }
        assert!(split_name("bogus.ns").is_none());
    }

    #[test]
    fn ibody_encode_decode_roundtrip() {
        let mut b = blank_inode();
        let entries = alloc::vec![
            ("security.selinux".to_string(), b"system_u:object_r:etc_t:s0\0".to_vec()),
            ("user.comment".to_string(), b"hello".to_vec()),
        ];
        encode_ibody(&mut b, HDR, ISIZE, &entries).expect("encode");
        // magic present
        assert_eq!(u32::from_le_bytes([b[HDR], b[HDR+1], b[HDR+2], b[HDR+3]]), EXT4_XATTR_MAGIC);
        let mut got = decode_ibody(&b, HDR, ISIZE);
        got.sort();
        let mut want = entries.clone();
        want.sort();
        assert_eq!(got, want);
    }

    #[test]
    fn ibody_xattr_name_preserves_non_utf8_suffix_bytes() {
        let mut b = blank_inode();
        let raw_suffix = b"raw-\xff";
        let mut full = "user.".to_string();
        full.push_str(&vfs::path_from_bytes(raw_suffix));
        let entries = alloc::vec![(full.clone(), b"v".to_vec())];
        encode_ibody(&mut b, HDR, ISIZE, &entries).expect("encode raw suffix");
        let name_start = HDR + 4 + ENTRY_HDR_LEN;
        assert_eq!(b[HDR + 4] as usize, raw_suffix.len());
        assert_eq!(&b[name_start..name_start + raw_suffix.len()], raw_suffix);
        assert_eq!(decode_ibody(&b, HDR, ISIZE), entries);
    }

    #[test]
    fn empty_entries_leaves_no_magic() {
        let mut b = blank_inode();
        encode_ibody(&mut b, HDR, ISIZE, &[]).expect("encode empty");
        // region is all-zero → no magic → decode empty
        assert!(decode_ibody(&b, HDR, ISIZE).is_empty());
        for &byte in &b[HDR..ISIZE] { assert_eq!(byte, 0); }
    }

    #[test]
    fn overflow_returns_err() {
        let mut b = blank_inode();
        // 96-byte ibody region (160..256) cannot hold a 200-byte value.
        let entries = alloc::vec![("user.big".to_string(), alloc::vec![0xABu8; 200])];
        assert!(encode_ibody(&mut b, HDR, ISIZE, &entries).is_err());
    }

    #[test]
    fn posix_acl_zero_name_len() {
        let mut b = blank_inode();
        let entries = alloc::vec![("system.posix_acl_access".to_string(), b"\x02\x00\x00\x00".to_vec())];
        encode_ibody(&mut b, HDR, ISIZE, &entries).expect("encode acl");
        // entry name_len must be 0, name_index 2
        assert_eq!(b[HDR + 4], 0, "posix_acl entry has zero-length name");
        assert_eq!(b[HDR + 5], 2, "posix_acl_access name_index = 2");
        let got = decode_ibody(&b, HDR, ISIZE);
        assert_eq!(got, entries);
    }

    #[test]
    fn external_block_decode() {
        let bs = 1024usize;
        let mut blk = alloc::vec![0u8; bs];
        blk[0..4].copy_from_slice(&EXT4_XATTR_MAGIC.to_le_bytes());
        // one entry: user.x = "v", value at end of block.
        let name = b"x";
        let p = BLOCK_HDR_LEN;
        blk[p] = name.len() as u8;       // name_len
        blk[p + 1] = 1;                  // name_index = user
        let value_pos = bs - 4;          // aligned slot
        blk[p + 2..p + 4].copy_from_slice(&(value_pos as u16).to_le_bytes()); // value_offs (base = block start)
        blk[p + 8..p + 12].copy_from_slice(&1u32.to_le_bytes());              // value_size
        blk[p + ENTRY_HDR_LEN..p + ENTRY_HDR_LEN + 1].copy_from_slice(name);
        blk[value_pos] = b'v';
        let got = decode_block(&blk);
        assert_eq!(got, alloc::vec![("user.x".to_string(), b"v".to_vec())]);
    }

    #[test]
    fn external_xattr_name_preserves_non_utf8_suffix_bytes() {
        let raw_suffix = b"raw-\xff";
        let mut full = "user.".to_string();
        full.push_str(&vfs::path_from_bytes(raw_suffix));
        let entries = alloc::vec![(full.clone(), b"v".to_vec())];
        let blk = encode_block(&entries, 1024).expect("encode external raw suffix");
        let name_start = BLOCK_HDR_LEN + ENTRY_HDR_LEN;
        assert_eq!(blk[BLOCK_HDR_LEN] as usize, raw_suffix.len());
        assert_eq!(&blk[name_start..name_start + raw_suffix.len()], raw_suffix);
        assert_eq!(decode_block(&blk), entries);
    }
}
