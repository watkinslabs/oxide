//! Extended attributes, inline and out-of-line.
//!
//! An inode carries an xattr IDENTIFIER; the identifier's record says where in
//! the xattr stream that inode's attributes start and how many there are. Each
//! attribute is a type word, a name suffix and a value — except that the value
//! may instead be a REFERENCE to a value stored once and shared, which is how
//! the format deduplicates a security label repeated across a whole tree.
//!
//! The stored name has no prefix; the type word's low byte names it. Emitting
//! the suffix alone produces an attribute nobody can ask for by name.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use sectors::SectorSource;
use syscall::errno::Errno;

use crate::limits::{XATTR_COUNT_MAX, XATTR_SIZE_MAX};
use crate::uapi::{size, xattr as xa, INVALID_XATTR, XATTR_BLOCK_SHIFT, XATTR_OFFSET_MASK};

use super::meta::Cursor;
use super::Volume;

/// One attribute's full name and value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attr {
    pub name: String,
    pub value: Vec<u8>,
}

/// The name prefix a type word's low byte stands for.
///
/// A type this build does not know is skipped and not guessed: emitting a name
/// under the wrong namespace would let an unprivileged reader see a `trusted.`
/// attribute as a `user.` one.
/// # C: O(1)
pub fn prefix_of(type_word: u16) -> Option<&'static str> {
    match type_word & xa::PREFIX_MASK {
        xa::USER => Some("user."),
        xa::TRUSTED => Some("trusted."),
        xa::SECURITY => Some("security."),
        _ => None,
    }
}

fn u16_at(b: &[u8], off: usize) -> u16 { u16::from_le_bytes([b[off], b[off + 1]]) }
fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
fn u64_at(b: &[u8], off: usize) -> u64 {
    let mut w = [0u8; 8];
    w.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(w)
}

impl<S: SectorSource> Volume<S> {
    /// Where an xattr reference points in the xattr stream. # C: O(1)
    fn xattr_cursor(&self, reference: u64) -> Cursor {
        Cursor::new(self.xattr_table_start() + (reference >> XATTR_BLOCK_SHIFT),
                    (reference & XATTR_OFFSET_MASK) as usize)
    }

    /// An inode's attributes, resolved through its identifier.
    ///
    /// An identifier of the absent sentinel, or an image with no xattr table,
    /// yields none — which is different from an error, because most inodes on
    /// most images have no attributes at all.
    /// # C: O(attribute bytes)
    pub fn read_xattrs(&self, xattr_id: u32) -> Result<Vec<Attr>, Errno> {
        if xattr_id == INVALID_XATTR || !self.has_xattrs() { return Ok(Vec::new()); }
        let mut id_cur = self.xattr_id_cursor(xattr_id)?;
        let record = self.read_meta(&mut id_cur, size::XATTR_ID)?;
        let count = u32_at(&record, 8);
        let mut cur = self.xattr_cursor(u64_at(&record, 0));
        if count > XATTR_COUNT_MAX { return Err(Errno::Eio); }
        let mut out = Vec::new();
        for _ in 0..count {
            let entry = self.read_meta(&mut cur, size::XATTR_ENTRY)?;
            let type_word = u16_at(&entry, 0);
            let name_size = usize::from(u16_at(&entry, 2));
            let suffix = self.read_meta(&mut cur, name_size)?;
            let value = self.read_value(&mut cur, type_word)?;
            if let Some(prefix) = prefix_of(type_word) {
                let suffix = String::from_utf8(suffix).map_err(|_| Errno::Eio)?;
                let mut name = prefix.to_string();
                name.push_str(&suffix);
                out.push(Attr { name, value });
            }
        }
        Ok(out)
    }

    /// One attribute's value, following a reference when the entry carries one.
    ///
    /// Following the reference moves the cursor to the shared value, so the
    /// cursor the caller keeps must be the one that steps past the REFERENCE,
    /// not past the value it names — the next attribute follows the reference.
    fn read_value(&self, cur: &mut Cursor, type_word: u16) -> Result<Vec<u8>, Errno> {
        if type_word & xa::VALUE_OOL != 0 {
            // What is stored in line is a length word followed by the
            // reference. The length must be the reference's own width: a
            // listing steps past the entry by that length while a fetch reads
            // a fixed-width reference, so any other value makes the two
            // disagree about where the next attribute begins.
            let header = self.read_meta(cur, size::XATTR_VAL)?;
            if u32_at(&header, 0) as usize != size::TABLE_INDEX { return Err(Errno::Eio); }
            let target = self.read_meta(cur, size::TABLE_INDEX)?;
            let mut at = self.xattr_cursor(u64_at(&target, 0));
            return self.read_value_at(&mut at);
        }
        self.read_value_at(cur)
    }

    fn read_value_at(&self, cur: &mut Cursor) -> Result<Vec<u8>, Errno> {
        let header = self.read_meta(cur, size::XATTR_VAL)?;
        let vsize = u32_at(&header, 0) as usize;
        if vsize > XATTR_SIZE_MAX { return Err(Errno::Eio); }
        self.read_meta(cur, vsize)
    }
}
