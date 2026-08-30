// Module manifest: xattr disk codec, placement, external blocks, EA inodes,
// and final-release lifecycle share the ext4 xattr ownership boundary.
extern crate alloc;
mod lifecycle;
mod ea_inode;
mod placement;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

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
                  ea_mount: Option<&Mount>, out: &mut Vec<(String, Vec<u8>)>)
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
        let value = if value_inum == 0 {
            let v_start = base_off + value_offs;
            let v_end = v_start + value_size;
            (v_end <= end_off).then(|| buf[v_start..v_end].to_vec())
        } else {
            ea_mount.and_then(|mount| mount.read_ea_inode_value(value_inum, value_size).ok())
        };
        if let Some(value) = value {
            let name = xattr_suffix_from_bytes(&buf[name_start..name_end]);
            if let Some(full) = join_name(name_index, &name) {
                if value_inum == 0 || external::entry_hash(name.as_bytes(), &value)
                    == u32::from_le_bytes([buf[p + 12], buf[p + 13], buf[p + 14], buf[p + 15]]) {
                    out.push((full, value));
                }
            }
        }
        if next <= p { break; } // guard against a malformed zero-length stride
        p = next;
    }
}

fn collect_ea_inode_refs(buf: &[u8], first_off: usize, end_off: usize, out: &mut Vec<u32>) {
    let mut p = first_off;
    while p + 4 <= end_off {
        if buf[p] == 0 && buf[p + 1] == 0 && buf[p + 2] == 0 && buf[p + 3] == 0 { break; }
        if p + ENTRY_HDR_LEN > end_off { break; }
        let name_len = buf[p] as usize;
        let next = p.checked_add(xattr_entry_len(name_len)).unwrap_or(end_off + 1);
        if next > end_off { break; }
        let ino = u32::from_le_bytes([buf[p + 4], buf[p + 5], buf[p + 6], buf[p + 7]]);
        if ino != 0 { out.push(ino); }
        if next <= p { break; }
        p = next;
    }
}

/// Decode the IBODY xattr area of a raw inode (`hdr_off` = `128 + i_extra_isize`).
/// Empty when the magic is absent. # C: O(N_entries)
pub fn decode_ibody(ino_bytes: &[u8], hdr_off: usize, isize: usize) -> Vec<(String, Vec<u8>)> {
    decode_ibody_with_mount(ino_bytes, hdr_off, isize, None)
}

fn decode_ibody_with_mount(ino_bytes: &[u8], hdr_off: usize, isize: usize,
                           ea_mount: Option<&Mount>) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    if hdr_off + 4 > isize { return out; }
    let magic = u32::from_le_bytes([ino_bytes[hdr_off], ino_bytes[hdr_off + 1],
                                    ino_bytes[hdr_off + 2], ino_bytes[hdr_off + 3]]);
    if magic != EXT4_XATTR_MAGIC { return out; }
    let base = hdr_off + 4; // IFIRST — value offsets are relative to this
    decode_entries(ino_bytes, base, base, isize, ea_mount, &mut out);
    out
}

/// Decode an EXTERNAL xattr block (`i_file_acl` target). Entries begin after the
/// 32-byte header; value offsets are relative to the block start. # C: O(N)
pub fn decode_block(blk: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    if blk.len() < BLOCK_HDR_LEN + 4 { return out; }
    let magic = u32::from_le_bytes([blk[0], blk[1], blk[2], blk[3]]);
    if magic != EXT4_XATTR_MAGIC { return out; }
    decode_entries(blk, BLOCK_HDR_LEN, 0, blk.len(), None, &mut out);
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
    sorted.sort_unstable_by(|a, b| a.0.cmp(&b.0)
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
    /// Return the Linux `h_hash` key of an external xattr block. # C: O(1)
    fn xattr_block_hash(block: &[u8]) -> u32 {
        if block.len() < BLOCK_HDR_LEN { return 0; }
        u32::from_le_bytes([block[12], block[13], block[14], block[15]])
    }

    /// Add one block to the mbcache index. The index contains block identities
    /// only; callers still compare canonical decoded entries before sharing.
    /// # C: O(log N)
    fn xattr_cache_insert(&self, block: u64, image: &[u8]) {
        if !self.behaviour().mbcache { return; }
        let key = Self::xattr_block_hash(image);
        if key == 0 { return; }
        let mut state = self.state.lock();
        let list = state.xattr_block_cache.entry(key).or_default();
        if !list.contains(&block) { list.push(block); }
    }

    /// Remove a block identity after its last on-disk reference is released.
    /// # C: O(log N)
    fn xattr_cache_remove(&self, block: u64, image: &[u8]) {
        let key = Self::xattr_block_hash(image);
        let mut state = self.state.lock();
        if let Some(list) = state.xattr_block_cache.get_mut(&key) {
            list.retain(|b| *b != block);
            if list.is_empty() { state.xattr_block_cache.remove(&key); }
        }
    }

    /// Find an existing byte-identical external xattr block. A hash collision
    /// is harmless because Linux compares the actual entries before sharing.
    /// # C: O(candidates * block)
    fn xattr_cache_find(&self, image: &[u8]) -> Option<u64> {
        if !self.behaviour().mbcache { return None; }
        let key = Self::xattr_block_hash(image);
        let candidates = self.state.lock().xattr_block_cache.get(&key).cloned()?;
        let wanted = decode_block(image);
        candidates.into_iter().find(|block| {
            self.read_metadata_block(*block).map(|old| decode_block(&old) == wanted).unwrap_or(false)
        })
    }

    /// Increment an external xattr block's Linux `h_refcount`. # C: O(block)
    fn xattr_block_get(&self, block: u64) -> Result<Vec<u8>, MountError> {
        let mut image = self.read_metadata_block(block)?;
        if image.len() < BLOCK_HDR_LEN { return Err(MountError::BadBlock); }
        let refs = u32::from_le_bytes([image[4], image[5], image[6], image[7]]);
        image[4..8].copy_from_slice(&refs.saturating_add(1).to_le_bytes());
        crate::csum::stamp_xattr_block_csum(&self.sb, block, &mut image);
        self.metadata_write(block * self.sb.block_size as u64, &image)?;
        Ok(image)
    }

    /// Read an external xattr block's Linux reference count before deciding
    /// whether an update may modify it in place. # C: O(block)
    fn xattr_block_refcount(&self, block: u64) -> Result<u32, MountError> {
        let image = self.read_metadata_block(block)?;
        if image.len() < BLOCK_HDR_LEN { return Err(MountError::BadBlock); }
        Ok(u32::from_le_bytes([image[4], image[5], image[6], image[7]]))
    }

    /// Drop one external xattr reference, returning true when its block is
    /// now unreferenced and must be freed. # C: O(block)
    fn xattr_block_put(&self, block: u64) -> Result<bool, MountError> {
        let mut image = self.read_metadata_block(block)?;
        if image.len() < BLOCK_HDR_LEN { return Err(MountError::BadBlock); }
        let refs = u32::from_le_bytes([image[4], image[5], image[6], image[7]]);
        if refs == 0 { return Err(MountError::BadBlock); }
        if refs == 1 { return Ok(true); }
        image[4..8].copy_from_slice(&(refs - 1).to_le_bytes());
        crate::csum::stamp_xattr_block_csum(&self.sb, block, &mut image);
        self.metadata_write(block * self.sb.block_size as u64, &image)?;
        Ok(false)
    }

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
            let old_image = if old_facl == 0 { None } else {
                Some(m.read_metadata_block(old_facl)?)
            };
            let original_sectors = Self::i_blocks_of(&bytes);
            let mut old_ea = Vec::new();
            collect_ea_inode_refs(&bytes, hdr_off + 4, isize, &mut old_ea);
            if let Some(image) = old_image.as_ref() {
                collect_ea_inode_refs(image, BLOCK_HDR_LEN, image.len(), &mut old_ea);
            }
            // Try IBODY-only. Encode into the live buffer; on overflow the buffer
            // is discarded (re-read) before the external path.
            if encode_ibody(&mut bytes, hdr_off, isize, entries).is_ok() {
                if old_facl != 0 { Self::detach_external_block(&mut bytes, bs); }
                let current_sectors = Self::i_blocks_of(&bytes);
                let old_ea_sectors = old_ea.iter().try_fold(0u32, |sum, ea_ino|
                    Ok::<u32, MountError>(sum.saturating_add(m.ea_inode_sectors(*ea_ino)?)))?;
                let new_sectors = current_sectors.saturating_sub(old_ea_sectors);
                m.account_i_blocks_delta(ino, original_sectors, new_sectors)?;
                bytes[0x1C..0x20].copy_from_slice(&new_sectors.to_le_bytes());
                if let Err(e) = m.write_inode_bytes(ino, &bytes) {
                    return Err(m.rollback_i_blocks_delta(ino, new_sectors, original_sectors, e));
                }
                if old_facl != 0 {
                    let old_image = m.read_metadata_block(old_facl)?;
                    let last = m.xattr_block_put(old_facl)?;
                    if last {
                        m.xattr_cache_remove(old_facl, &old_image);
                        if let Err(e) = m.free_block(old_facl) {
                            return Err(m.rollback_i_blocks_delta(ino, new_sectors, original_sectors, e));
                        }
                    }
                }
                for ea_ino in old_ea { m.put_ea_inode(ea_ino)?; }
                return Ok(());
            }
            // IBODY overflow → external block. Re-read to drop the partial encode.
            let (mut bytes, _off) = m.read_inode_bytes(ino)?;
            encode_ibody(&mut bytes, hdr_off, isize, &[]).map_err(|_| MountError::NoSpace)?;
            let mut ea = Vec::new();
            let mut new_ea_sectors = 0u32;
            for (name, value) in entries {
                if value.len() > bs {
                    if m.sb.feature_incompat & crate::superblock::INCOMPAT_EA_INODE == 0 {
                        return Err(MountError::NoSpace);
                    }
                    let (ea_ino, _) = m.lookup_create_ea_inode(ino, value)?;
                    let hash = m.ea_value_hash(value);
                    ea.push((name.clone(), ea_ino, hash));
                    new_ea_sectors = new_ea_sectors.saturating_add(
                        (value.len().div_ceil(bs) as u32).saturating_mul(m.sb.sectors_per_block()));
                }
            }
            let mut blk = external::encode_block_with_ea(entries, &ea, bs)
                .map_err(|_| MountError::NoSpace)?;
            let old_sectors = Self::i_blocks_of(&bytes);
            let mut charged_sectors = old_sectors;
            let old_refs = if old_facl == 0 { 0 } else { m.xattr_block_refcount(old_facl)? };
            let cached = m.xattr_cache_find(&blk);
            let shared = cached.filter(|block| *block != old_facl);
            let same_old = cached == Some(old_facl);
            let mut allocated = false;
            let block_nr = if old_facl != 0 && (old_refs <= 1 || same_old) {
                // An unshared block is the inode's private xattr storage and
                // may be rewritten in place. Byte-identical shared storage
                // needs no mutation and remains attached as-is.
                old_facl
            } else if let Some(existing) = shared {
                // Linux mbcache shares the existing physical block, but the
                // inode still owns one i_blocks charge for its reference.
                blk = m.xattr_block_get(existing)?;
                Self::attach_external_block(&mut bytes, existing, bs);
                existing
            } else {
                charged_sectors = old_sectors.saturating_add(m.sb.sectors_per_block());
                m.account_i_blocks_delta(ino, old_sectors, charged_sectors)?;
                let b = match m.alloc_block(0) {
                    Ok(b) => b,
                    Err(e) => {
                        return Err(m.rollback_i_blocks_delta(ino, charged_sectors, old_sectors, e));
                    }
                };
                allocated = true;
                Self::attach_external_block(&mut bytes, b, bs);
                b
            };
            let rewrite = !same_old && shared.is_none();
            if rewrite {
                crate::csum::stamp_xattr_block_csum(&m.sb, block_nr, &mut blk);
            }
            if rewrite {
                if let Err(e) = m.metadata_write(block_nr * bs as u64, &blk) {
                    if allocated { let _ = m.free_block(block_nr); }
                    return if old_facl == 0 {
                        Err(m.rollback_i_blocks_delta(ino, charged_sectors, old_sectors, e))
                    } else { Err(e) };
                }
            }
            if let Err(e) = m.write_inode_bytes(ino, &bytes) {
                if allocated {
                    let _ = m.free_block(block_nr);
                }
                return if old_facl == 0 {
                    Err(m.rollback_i_blocks_delta(ino, charged_sectors, old_sectors, e))
                    } else { Err(e) };
            }
            let old_ea_sectors = old_ea.iter().try_fold(0u32, |sum, ea_ino|
                Ok::<u32, MountError>(sum.saturating_add(m.ea_inode_sectors(*ea_ino)?)))?;
            let current_sectors = Self::i_blocks_of(&bytes);
            let new_sectors = original_sectors.saturating_sub(old_ea_sectors)
                .saturating_add(new_ea_sectors)
                .saturating_add(if old_facl == 0 { m.sb.sectors_per_block() } else { 0 });
            if current_sectors != new_sectors {
                m.account_i_blocks_delta(ino, current_sectors, new_sectors)?;
                bytes[0x1C..0x20].copy_from_slice(&new_sectors.to_le_bytes());
                m.write_inode_bytes(ino, &bytes)?;
            }
            if old_facl != 0 && block_nr != old_facl {
                if m.xattr_block_put(old_facl)? {
                    m.xattr_cache_remove(old_facl, old_image.as_ref().expect("old xattr image"));
                    m.free_block(old_facl)?;
                }
            }
            if rewrite {
                if block_nr != old_facl {
                    m.xattr_cache_insert(block_nr, &blk);
                } else {
                    m.xattr_cache_remove(old_facl, old_image.as_ref().expect("old xattr image"));
                    m.xattr_cache_insert(block_nr, &blk);
                }
            }
            for ea_ino in old_ea { m.put_ea_inode(ea_ino)?; }
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
        let sectors = (bs as u32) / crate::layout::I_BLOCKS_SECTOR_BYTES;
        let ib = u32::from_le_bytes([bytes[0x1C], bytes[0x1D], bytes[0x1E], bytes[0x1F]]);
        bytes[0x1C..0x20].copy_from_slice(&ib.saturating_add(sectors).to_le_bytes());
    }

    /// Clear `i_file_acl` and subtract its fs-block from `i_blocks` (block is
    /// freed by the caller after the inode write). # C: O(1)
    fn detach_external_block(bytes: &mut [u8], bs: usize) {
        bytes[0x68..0x6C].copy_from_slice(&0u32.to_le_bytes());
        bytes[0x76..0x78].copy_from_slice(&0u16.to_le_bytes());
        let sectors = (bs as u32) / crate::layout::I_BLOCKS_SECTOR_BYTES;
        let ib = u32::from_le_bytes([bytes[0x1C], bytes[0x1D], bytes[0x1E], bytes[0x1F]]);
        bytes[0x1C..0x20].copy_from_slice(&ib.saturating_sub(sectors).to_le_bytes());
    }
}

#[cfg(test)]
#[path = "xattr/tests/mod.rs"]
mod tests;
