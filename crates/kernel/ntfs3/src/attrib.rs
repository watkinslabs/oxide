//! An attribute: everything a file IS, on a filesystem where a file has no
//! fields of its own.
//!
//! A name, a timestamp, the file's bytes, a directory's index — each is an
//! attribute in a record, and each is either RESIDENT (its data sits in the
//! record) or NON-RESIDENT (the record holds a runlist naming the clusters).
//! The same attribute type can be either, so a reader that assumes one reads a
//! runlist as data or data as a runlist.
//!
//! A file can also have several attributes of one TYPE distinguished by name:
//! that is what an alternate data stream is. The unnamed `$DATA` attribute is
//! the file's contents; a named one is a stream beside it.

use alloc::vec::Vec;

use crate::uapi::*;

/// One attribute's header.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Attribute {
    pub ty: u32,
    /// Bytes this attribute occupies in the record.
    pub size: u32,
    pub non_resident: bool,
    /// The attribute's name, in UTF-16 units. Empty for the unnamed one.
    pub name: Vec<u16>,
    pub flags: u16,
    pub id: u16,
    /// Where the header sits in the record.
    pub offset: usize,
    pub body: Body,
}

/// What the header carries beyond the common part.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Body {
    Resident {
        data_size: u32,
        data_off: u16,
        indexed: bool,
    },
    NonResident {
        /// First and last cluster of the FILE this segment covers.
        svcn: u64,
        evcn: u64,
        run_off: u16,
        /// Compression unit, as a shift. Zero means uncompressed.
        c_unit: u8,
        alloc_size: u64,
        data_size: u64,
        valid_size: u64,
        /// Clusters actually allocated, on a compressed or sparse attribute.
        total_size: u64,
    },
}

impl Attribute {
    /// The attribute's length in bytes, whichever form it takes. # C: O(1)
    pub fn data_size(&self) -> u64 {
        match self.body {
            Body::Resident { data_size, .. } => u64::from(data_size),
            Body::NonResident { data_size, .. } => data_size,
        }
    }

    /// How far the attribute has actually been written. # C: O(1)
    pub fn valid_size(&self) -> u64 {
        match self.body {
            Body::Resident { data_size, .. } => u64::from(data_size),
            Body::NonResident { valid_size, .. } => valid_size,
        }
    }

    /// Whether the attribute's clusters hold compressed data. # C: O(1)
    pub fn compressed(&self) -> bool { self.flags & ATTR_FLAG_COMPRESSED != 0 }

    /// Whether the attribute may have holes. # C: O(1)
    pub fn sparse(&self) -> bool { self.flags & ATTR_FLAG_SPARSED != 0 }

    /// Whether the attribute's data is encrypted, which nothing here can
    /// read. # C: O(1)
    pub fn encrypted(&self) -> bool { self.flags & ATTR_FLAG_ENCRYPTED != 0 }

    /// The compression unit in clusters, or `None` when uncompressed.
    /// # C: O(1)
    pub fn compression_unit(&self) -> Option<u32> {
        match self.body {
            Body::NonResident { c_unit, .. } if c_unit != 0 && self.compressed() =>
                Some(1u32 << c_unit),
            _ => None,
        }
    }

    /// Whether this is the FIRST segment of a multi-segment attribute, which
    /// is the only one carrying the whole attribute's sizes. # C: O(1)
    pub fn is_first_segment(&self) -> bool {
        match self.body { Body::NonResident { svcn, .. } => svcn == 0, Body::Resident { .. } => true }
    }

    /// Whether this attribute is the unnamed one of its type — a file's own
    /// data rather than a stream beside it. # C: O(1)
    pub fn is_unnamed(&self) -> bool { self.name.is_empty() }

    /// The resident data's span within the record. # C: O(1)
    pub fn resident_span(&self) -> Option<(usize, usize)> {
        let Body::Resident { data_size, data_off, .. } = self.body else { return None };
        let start = self.offset.checked_add(usize::from(data_off))?;
        Some((start, start.checked_add(data_size as usize)?))
    }

    /// Where the packed runlist begins in the record. # C: O(1)
    pub fn run_span(&self) -> Option<(usize, usize)> {
        let Body::NonResident { run_off, .. } = self.body else { return None };
        let start = self.offset.checked_add(usize::from(run_off))?;
        let end = self.offset.checked_add(self.size as usize)?;
        if start > end { return None; }
        Some((start, end))
    }
}

/// Read one 16-bit field. # C: O(1)
fn le16(bytes: &[u8], at: usize) -> u16 { u16::from_le_bytes([bytes[at], bytes[at + 1]]) }

/// Read one 32-bit field. # C: O(1)
fn le32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// Read one 64-bit field. # C: O(1)
fn le64(bytes: &[u8], at: usize) -> u64 {
    let mut out = [0u8; 8];
    out.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(out)
}

/// Decode the attribute whose header begins at `at`.
///
/// Every span the header names is checked against the attribute's own declared
/// size before it is believed: a data offset past the end, a name reaching
/// outside, a non-resident header shorter than its fields all decode into
/// plausible values otherwise.
/// # C: O(name length)
pub fn parse(bytes: &[u8], at: usize) -> Option<Attribute> {
    if at + SIZEOF_RESIDENT > bytes.len() { return None; }
    let ty = le32(bytes, at + ATTR_OFF_TYPE);
    if ty == ATTR_END { return None; }
    let size = le32(bytes, at + ATTR_OFF_SIZE);
    let end = at.checked_add(size as usize)?;
    if size < 8 || end > bytes.len() { return None; }
    let non_resident = bytes[at + ATTR_OFF_NON_RES] != 0;
    let name_len = usize::from(bytes[at + ATTR_OFF_NAME_LEN]);
    let name_off = usize::from(le16(bytes, at + ATTR_OFF_NAME_OFF));
    let flags = le16(bytes, at + ATTR_OFF_FLAGS);
    let id = le16(bytes, at + ATTR_OFF_ID);

    let mut name = Vec::with_capacity(name_len);
    if name_len != 0 {
        let start = at.checked_add(name_off)?;
        let stop = start.checked_add(name_len * 2)?;
        if stop > end { return None; }
        for i in 0..name_len { name.push(le16(bytes, start + i * 2)); }
    }

    let body = if non_resident {
        if at + SIZEOF_NONRESIDENT > bytes.len() { return None; }
        let c_unit = bytes[at + NRES_OFF_C_UNIT];
        let extended = flags & (ATTR_FLAG_COMPRESSED | ATTR_FLAG_SPARSED) != 0;
        if extended && at + SIZEOF_NONRESIDENT_EX > bytes.len() { return None; }
        Body::NonResident {
            svcn: le64(bytes, at + NRES_OFF_SVCN),
            evcn: le64(bytes, at + NRES_OFF_EVCN),
            run_off: le16(bytes, at + NRES_OFF_RUN_OFF),
            c_unit,
            alloc_size: le64(bytes, at + NRES_OFF_ALLOC_SIZE),
            data_size: le64(bytes, at + NRES_OFF_DATA_SIZE),
            valid_size: le64(bytes, at + NRES_OFF_VALID_SIZE),
            total_size: if extended { le64(bytes, at + NRES_OFF_TOTAL_SIZE) } else { 0 },
        }
    } else {
        let data_size = le32(bytes, at + RES_OFF_DATA_SIZE);
        let data_off = le16(bytes, at + RES_OFF_DATA_OFF);
        // The data must lie inside the attribute, or a read of it reaches
        // whatever follows in the record.
        let start = at.checked_add(usize::from(data_off))?;
        if start.checked_add(data_size as usize)? > end { return None; }
        Body::Resident {
            data_size,
            data_off,
            indexed: bytes[at + RES_OFF_FLAGS] & RESIDENT_FLAG_INDEXED != 0,
        }
    };
    Some(Attribute { ty, size, non_resident, name, flags, id, offset: at, body })
}

/// Every attribute in a record, in order. # C: O(record bytes)
pub fn parse_all(bytes: &[u8], header: &crate::record::RecordHeader) -> Vec<Attribute> {
    crate::record::attribute_offsets(bytes, header)
        .into_iter()
        .filter_map(|at| parse(bytes, at))
        .collect()
}

/// The attribute of `ty` whose name is `name`, or `None`.
///
/// Type AND name together: a file with an alternate data stream has two
/// `$DATA` attributes, and taking the first one returns whichever happens to
/// be laid out earlier rather than the one asked for.
/// # C: O(attributes)
pub fn find<'a>(attrs: &'a [Attribute], ty: u32, name: &[u16]) -> Option<&'a Attribute> {
    attrs.iter().find(|a| a.ty == ty && a.name == name && a.is_first_segment())
}

/// Every segment of one attribute, in cluster order.
///
/// A file too fragmented for one record's runlist is split across several
/// attributes of the same type and name, each covering a range of the file's
/// clusters. Reading only the first gives the first part of the file and calls
/// it the whole.
/// # C: O(attributes)
pub fn segments<'a>(attrs: &'a [Attribute], ty: u32, name: &[u16]) -> Vec<&'a Attribute> {
    let mut out: Vec<&Attribute> = attrs.iter().filter(|a| a.ty == ty && a.name == name).collect();
    out.sort_by_key(|a| match a.body { Body::NonResident { svcn, .. } => svcn, _ => 0 });
    out
}

/// The names of every attribute of one type, which is the list of a file's
/// streams. # C: O(attributes)
pub fn names_of(attrs: &[Attribute], ty: u32) -> Vec<Vec<u16>> {
    let mut out = Vec::new();
    for a in attrs.iter().filter(|a| a.ty == ty && a.is_first_segment()) {
        if !out.contains(&a.name) { out.push(a.name.clone()); }
    }
    out
}

#[cfg(test)]
#[path = "tests/attrib.rs"]
mod tests;
