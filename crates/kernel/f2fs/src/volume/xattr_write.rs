//! Setting and removing extended attributes.
//!
//! The whole region is re-encoded on every change. That is not laziness: the
//! records are packed contiguously with no free list, an attribute in the
//! middle growing or vanishing moves every record after it, and patching in
//! place would leave a gap that terminates the walk early — losing every
//! attribute past it with no error anywhere.

use alloc::vec;
use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::flags::INLINE_XATTR;
use crate::uapi::*;
use crate::xattr::{self, Attr};

use super::dnode::put32;
use super::Volume;

/// Encode a whole attribute list, header first, records packed.
/// # C: O(total bytes)
pub fn encode(attrs: &[Attr]) -> Vec<u8> {
    let mut out = vec![0u8; XATTR_HEADER_SIZE];
    put32(&mut out, XATTR_H_MAGIC, XATTR_MAGIC);
    put32(&mut out, XATTR_H_REFCOUNT, 1);
    for a in attrs {
        let size = xattr::entry_size(a.name.len(), a.value.len());
        let at = out.len();
        out.resize(at + size, 0);
        out[at + XATTR_E_NAME_INDEX] = a.index;
        out[at + XATTR_E_NAME_LEN] = a.name.len() as u8;
        out[at + XATTR_E_VALUE_SIZE..at + XATTR_E_VALUE_SIZE + 2]
            .copy_from_slice(&(a.value.len() as u16).to_le_bytes());
        let body = at + XATTR_ENTRY_HEADER;
        out[body..body + a.name.len()].copy_from_slice(&a.name);
        out[body + a.name.len()..body + a.name.len() + a.value.len()].copy_from_slice(&a.value);
    }
    // The terminator is four zero bytes; without room for it the walk runs
    // into whatever follows the region.
    out.extend_from_slice(&[0u8; XATTR_ENTRY_HEADER]);
    out
}

impl<S: SectorSource> Volume<S> {
    /// Set, replace or remove one attribute.
    ///
    /// `create` refuses a name that exists and `replace` refuses one that does
    /// not; passing both is a contradiction and is refused. A `None` value
    /// removes.
    /// # C: O(region bytes)
    pub fn set_xattr(&mut self, ino: u32, name: &str, value: Option<&[u8]>, create: bool,
                     replace: bool) -> Result<(), Errno> {
        self.writable_or_err()?;
        if create && replace { return Err(Errno::Einval); }
        let (index, key) = xattr::split_name(name).ok_or(Errno::Eopnotsupp)?;
        let inode = self.read_inode(ino)?;
        let area = self.xattr_area(&inode, ino)?;
        let mut attrs = xattr::list(&area).map_err(|_| Errno::Eio)?;
        let at = attrs.iter().position(|a| a.index == index && a.name == key);
        match (value, at) {
            (None, None) => return Err(Errno::Enodata),
            (None, Some(i)) => { attrs.remove(i); }
            (Some(_), Some(_)) if create => return Err(Errno::Eexist),
            (Some(_), None) if replace => return Err(Errno::Enodata),
            (Some(v), Some(i)) => attrs[i].value = v.to_vec(),
            (Some(v), None) => {
                attrs.push(Attr { index, name: key.to_vec(), value: v.to_vec() })
            }
        }
        self.store_xattrs(ino, &attrs)
    }

    /// Lay an attribute list back down across the two halves.
    ///
    /// Whatever does not fit in the inode's own region goes to a block, which
    /// is allocated on demand and released again once the list shrinks enough
    /// to fit inline.
    /// # C: O(region bytes)
    pub(crate) fn store_xattrs(&mut self, ino: u32, attrs: &[Attr]) -> Result<(), Errno> {
        let inode = self.read_inode(ino)?;
        let encoded = encode(attrs);
        let reserve = inode.inline_xattr_addrs * 4;
        let empty = attrs.is_empty();
        // The region's own span excludes the terminator, which the reader
        // supplies from its own padding word.
        let inline_len = if empty { 0 } else { reserve };
        if encoded.len().saturating_sub(XATTR_ENTRY_HEADER) > reserve + VALID_XATTR_BLOCK_SIZE {
            return Err(Errno::Enospc);
        }
        let needs_block = encoded.len().saturating_sub(XATTR_ENTRY_HEADER) > reserve;
        if needs_block && reserve == 0 { return Err(Errno::Enospc); }
        let mut nid = inode.xattr_nid;
        if needs_block && nid == 0 { nid = self.alloc_nid()?; }
        let mut block = self.inode_bytes(ino)?;
        if inline_len > 0 {
            let at = OFFSET_OF_END_OF_I_EXT
                + (DEF_ADDRS_PER_INODE - inode.inline_xattr_addrs) * 4;
            block[at..at + inline_len].fill(0);
            let take = encoded.len().min(inline_len);
            block[at..at + take].copy_from_slice(&encoded[..take]);
            block[I_INLINE] |= INLINE_XATTR;
        } else {
            block[I_INLINE] &= !INLINE_XATTR;
        }
        put32(&mut block, I_XATTR_NID, if needs_block { nid } else { 0 });
        self.put_inode(ino, block)?;
        if needs_block {
            let mut xb = vec![0u8; BLKSIZE];
            let tail = &encoded[inline_len..];
            let take = tail.len().min(VALID_XATTR_BLOCK_SIZE);
            xb[..take].copy_from_slice(&tail[..take]);
            self.write_node(nid, ino, xb, super::curseg::Kind::IndirectNode)?;
        } else if inode.xattr_nid != 0 {
            self.release_node(inode.xattr_nid)?;
            // The attribute block was charged as space when it was written,
            // so dropping it without giving that space back leaves the owner
            // paying for a block nothing occupies.
            self.uncharge_space(ino, BLKSIZE as u64)?;
        }
        let blocks = self.count_blocks(ino)?;
        self.stamp_inode(ino, |b| Self::set_iblocks(b, blocks))
    }

    /// Remove one attribute. # C: O(region bytes)
    pub fn remove_xattr(&mut self, ino: u32, name: &str) -> Result<(), Errno> {
        self.set_xattr(ino, name, None, false, false)
    }
}

#[cfg(test)]
#[path = "../tests/xattrw.rs"]
mod tests;
