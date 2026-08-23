//! Editing a record: adding, replacing and removing attributes.
//!
//! A record is a packed list, so every change is a memmove of everything after
//! it plus a rewrite of the record's used length. The list is ordered by
//! attribute TYPE and, within a type, by name — an out-of-order insertion
//! produces a record every other implementation walks past the attribute it
//! was looking for.

use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::attrib;
use crate::record::{self, RecordHeader};
use crate::uapi::*;

/// Read one 32-bit field. # C: O(1)
fn le32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// Bytes of the record still free for another attribute.
///
/// The end marker and the record's own header are not free: an attribute
/// written over either leaves a record whose walk never terminates.
/// # C: O(1)
pub fn free_space(bytes: &[u8], header: &RecordHeader) -> usize {
    let total = core::cmp::min(header.total as usize, bytes.len());
    total.saturating_sub(header.used as usize)
}

/// Where an attribute of `ty` named `name` belongs, in type-then-name order.
/// # C: O(attributes)
pub fn insert_offset(bytes: &[u8], header: &RecordHeader, ty: u32, name: &[u16]) -> usize {
    for at in record::attribute_offsets(bytes, header) {
        let Some(attr) = attrib::parse(bytes, at) else { break };
        if attr.ty > ty { return at; }
        if attr.ty == ty && attr.name.as_slice() > name { return at; }
    }
    // Past every attribute is where the end marker sits.
    header.used as usize - 8
}

/// Build a resident attribute of `ty` with `data`. # C: O(data bytes)
pub fn resident(ty: u32, name: &[u16], id: u16, indexed: bool, data: &[u8]) -> Vec<u8> {
    let name_off = SIZEOF_RESIDENT;
    let data_off = (name_off + name.len() * 2).next_multiple_of(8);
    let size = (data_off + data.len()).next_multiple_of(8);
    let mut out = alloc::vec![0u8; size];
    out[ATTR_OFF_TYPE..ATTR_OFF_TYPE + 4].copy_from_slice(&ty.to_le_bytes());
    out[ATTR_OFF_SIZE..ATTR_OFF_SIZE + 4].copy_from_slice(&(size as u32).to_le_bytes());
    out[ATTR_OFF_NON_RES] = 0;
    out[ATTR_OFF_NAME_LEN] = name.len() as u8;
    out[ATTR_OFF_NAME_OFF..ATTR_OFF_NAME_OFF + 2]
        .copy_from_slice(&(name_off as u16).to_le_bytes());
    out[ATTR_OFF_ID..ATTR_OFF_ID + 2].copy_from_slice(&id.to_le_bytes());
    out[RES_OFF_DATA_SIZE..RES_OFF_DATA_SIZE + 4]
        .copy_from_slice(&(data.len() as u32).to_le_bytes());
    out[RES_OFF_DATA_OFF..RES_OFF_DATA_OFF + 2]
        .copy_from_slice(&(data_off as u16).to_le_bytes());
    if indexed { out[RES_OFF_FLAGS] = RESIDENT_FLAG_INDEXED; }
    for (i, unit) in name.iter().enumerate() {
        let at = name_off + i * 2;
        out[at..at + 2].copy_from_slice(&unit.to_le_bytes());
    }
    out[data_off..data_off + data.len()].copy_from_slice(data);
    out
}

/// Build a non-resident attribute over `runs`. # C: O(runs)
#[allow(clippy::too_many_arguments)]
pub fn non_resident(ty: u32, name: &[u16], id: u16, runs: &crate::run::Runs, alloc_size: u64,
                    data_size: u64, valid_size: u64, cluster_bits: u32) -> Vec<u8> {
    non_resident_flags(ty, name, id, runs, alloc_size, data_size, valid_size, cluster_bits, 0)
}

/// Build a non-resident attribute with extended sparse/compressed flags.
/// # C: O(runs)
#[allow(clippy::too_many_arguments)]
pub fn non_resident_flags(ty: u32, name: &[u16], id: u16, runs: &crate::run::Runs,
                          alloc_size: u64, data_size: u64, valid_size: u64,
                          cluster_bits: u32, flags: u16) -> Vec<u8> {
    let packed = crate::run::pack(runs);
    let extended = flags & (ATTR_FLAG_COMPRESSED | ATTR_FLAG_SPARSED) != 0;
    let name_off = if extended { SIZEOF_NONRESIDENT_EX } else { SIZEOF_NONRESIDENT };
    let run_off = (name_off + name.len() * 2).next_multiple_of(8);
    let size = (run_off + packed.len()).next_multiple_of(8);
    let mut out = alloc::vec![0u8; size];
    out[ATTR_OFF_TYPE..ATTR_OFF_TYPE + 4].copy_from_slice(&ty.to_le_bytes());
    out[ATTR_OFF_SIZE..ATTR_OFF_SIZE + 4].copy_from_slice(&(size as u32).to_le_bytes());
    out[ATTR_OFF_NON_RES] = 1;
    out[ATTR_OFF_NAME_LEN] = name.len() as u8;
    out[ATTR_OFF_NAME_OFF..ATTR_OFF_NAME_OFF + 2]
        .copy_from_slice(&(name_off as u16).to_le_bytes());
    out[ATTR_OFF_ID..ATTR_OFF_ID + 2].copy_from_slice(&id.to_le_bytes());
    out[ATTR_OFF_FLAGS..ATTR_OFF_FLAGS + 2].copy_from_slice(&flags.to_le_bytes());
    if flags & ATTR_FLAG_COMPRESSED != 0 { out[NRES_OFF_C_UNIT] = LZNT_CUNIT; }
    let clusters = runs.clusters();
    let evcn = if clusters == 0 { u64::MAX } else { clusters - 1 };
    out[NRES_OFF_EVCN..NRES_OFF_EVCN + 8].copy_from_slice(&evcn.to_le_bytes());
    out[NRES_OFF_RUN_OFF..NRES_OFF_RUN_OFF + 2].copy_from_slice(&(run_off as u16).to_le_bytes());
    let alloc = if alloc_size != 0 { alloc_size } else { clusters << cluster_bits };
    out[NRES_OFF_ALLOC_SIZE..NRES_OFF_ALLOC_SIZE + 8].copy_from_slice(&alloc.to_le_bytes());
    out[NRES_OFF_DATA_SIZE..NRES_OFF_DATA_SIZE + 8].copy_from_slice(&data_size.to_le_bytes());
    out[NRES_OFF_VALID_SIZE..NRES_OFF_VALID_SIZE + 8].copy_from_slice(&valid_size.to_le_bytes());
    if extended {
        let total_size = runs.allocated() << cluster_bits;
        out[NRES_OFF_TOTAL_SIZE..NRES_OFF_TOTAL_SIZE + 8]
            .copy_from_slice(&total_size.to_le_bytes());
    }
    for (i, unit) in name.iter().enumerate() {
        let at = name_off + i * 2;
        out[at..at + 2].copy_from_slice(&unit.to_le_bytes());
    }
    out[run_off..run_off + packed.len()].copy_from_slice(&packed);
    out
}

/// Insert `attr` into a record at the position its type and name give.
///
/// `Enospc` when the record has no room, which is the point at which a real
/// implementation moves an attribute out into a record of its own.
/// # C: O(record bytes)
pub fn insert(bytes: &mut [u8], header: &RecordHeader, attr: &[u8]) -> Result<(), Errno> {
    if attr.len() > free_space(bytes, header) { return Err(Errno::Enospc); }
    let ty = le32(attr, ATTR_OFF_TYPE);
    let name_len = usize::from(attr[ATTR_OFF_NAME_LEN]);
    let name_off = usize::from(u16::from_le_bytes([attr[ATTR_OFF_NAME_OFF],
                                                   attr[ATTR_OFF_NAME_OFF + 1]]));
    let name: Vec<u16> = (0..name_len)
        .map(|i| u16::from_le_bytes([attr[name_off + i * 2], attr[name_off + i * 2 + 1]]))
        .collect();
    let at = insert_offset(bytes, header, ty, &name);
    let used = header.used as usize;
    bytes.copy_within(at..used, at + attr.len());
    bytes[at..at + attr.len()].copy_from_slice(attr);
    record::set_used(bytes, (used + attr.len()) as u32);
    Ok(())
}

/// Remove the attribute whose header sits at `at`. # C: O(record bytes)
pub fn remove_at(bytes: &mut [u8], header: &RecordHeader, at: usize) -> Result<(), Errno> {
    let size = le32(bytes, at + ATTR_OFF_SIZE) as usize;
    let used = header.used as usize;
    if at + size > used { return Err(Errno::Eio); }
    bytes.copy_within(at + size..used, at);
    let new_used = used - size;
    for b in bytes[new_used..used].iter_mut() { *b = 0; }
    record::set_used(bytes, new_used as u32);
    Ok(())
}

/// Replace the attribute at `at` with `attr`. # C: O(record bytes)
pub fn replace_at(bytes: &mut [u8], header: &RecordHeader, at: usize, attr: &[u8])
    -> Result<(), Errno> {
    let old = le32(bytes, at + ATTR_OFF_SIZE) as usize;
    let used = header.used as usize;
    if at + old > used { return Err(Errno::Eio); }
    let total = core::cmp::min(header.total as usize, bytes.len());
    let new_used = used - old + attr.len();
    if new_used > total { return Err(Errno::Enospc); }
    bytes.copy_within(at + old..used, at + attr.len());
    bytes[at..at + attr.len()].copy_from_slice(attr);
    if new_used < used { for b in bytes[new_used..used].iter_mut() { *b = 0; } }
    record::set_used(bytes, new_used as u32);
    Ok(())
}

/// The next attribute identifier a record should hand out. # C: O(1)
pub fn take_attr_id(bytes: &mut [u8]) -> u16 {
    let at = MFT_OFF_NEXT_ATTR_ID;
    let id = u16::from_le_bytes([bytes[at], bytes[at + 1]]);
    bytes[at..at + 2].copy_from_slice(&id.wrapping_add(1).to_le_bytes());
    id
}
