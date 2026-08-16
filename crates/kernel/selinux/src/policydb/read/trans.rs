// The transition tables: role, filename and MLS range.

use alloc::string::String;
use alloc::vec::Vec;

use crate::ebitmap::Ebitmap;
use crate::error::{Error, Result};
use crate::mls::Range;
use crate::policydb::sections::{FilenameTrans, FilenameTransDatum, RangeTrans, RoleTrans};
use crate::reader::Reader;
use crate::uapi::version::{POLICYDB_VERSION_COMP_FTRANS, POLICYDB_VERSION_FILENAME_TRANS,
                          POLICYDB_VERSION_MLS, POLICYDB_VERSION_RANGETRANS,
                          POLICYDB_VERSION_ROLETRANS};

/// Read the role-transition table. # C: O(entries)
pub fn read_role_trans(r: &mut Reader<'_>, version: u32, process_class: u32)
    -> Result<Vec<RoleTrans>>
{
    let nel = r.u32()?;
    let mut out = Vec::new();
    out.try_reserve(nel as usize).map_err(|_| Error::NoMemory)?;
    for _ in 0..nel {
        let [role, ty, new_role] = r.u32_array::<3>()?;
        // Before role transitions gained a class, every entry meant `process`.
        let tclass = if version >= POLICYDB_VERSION_ROLETRANS { r.u32()? } else { process_class };
        out.push(RoleTrans { role, ty, tclass, new_role });
    }
    Ok(out)
}

/// Read the permitted role-change pairs. # C: O(entries)
pub fn read_role_allow(r: &mut Reader<'_>) -> Result<Vec<(u32, u32)>> {
    let nel = r.u32()?;
    let mut out = Vec::new();
    out.try_reserve(nel as usize).map_err(|_| Error::NoMemory)?;
    for _ in 0..nel {
        let [role, new_role] = r.u32_array::<2>()?;
        out.push((role, new_role));
    }
    Ok(out)
}

/// Read the MLS range-transition table. # C: O(entries)
///
/// The section is absent, not empty, in a pre-MLS image: reading a count there
/// would consume the first word of whatever follows.
pub fn read_range_trans(r: &mut Reader<'_>, version: u32, process_class: u32)
    -> Result<Vec<RangeTrans>>
{
    if version < POLICYDB_VERSION_MLS { return Ok(Vec::new()); }
    let nel = r.u32()?;
    let mut out = Vec::new();
    out.try_reserve(nel as usize).map_err(|_| Error::NoMemory)?;
    for _ in 0..nel {
        let [source_type, target_type] = r.u32_array::<2>()?;
        let target_class = if version >= POLICYDB_VERSION_RANGETRANS { r.u32()? }
                           else { process_class };
        let range = Range::read(r)?;
        out.push(RangeTrans { source_type, target_type, target_class, range });
    }
    Ok(out)
}

/// Read the filename-transition table and the target types it names. # C: O(n log n)
pub fn read_filename_trans(r: &mut Reader<'_>, version: u32)
    -> Result<(Vec<FilenameTrans>, Ebitmap)>
{
    if version < POLICYDB_VERSION_FILENAME_TRANS { return Ok((Vec::new(), Ebitmap::new())); }
    let nel = r.u32()?;
    let entries = if version < POLICYDB_VERSION_COMP_FTRANS { read_legacy(r, nel)? }
                  else { read_compressed(r, nel)? };
    // Indexed by the RAW type value, not by value minus one. The two
    // conventions coexist in this policy format — the type-attribute map is
    // value-indexed while the permissive, never-audit and this bitmap are
    // value-keyed — and normalising one of them here would put the set and the
    // lookup one bit apart, which silently stops every filename rule matching.
    let mut ttypes = Ebitmap::new();
    for e in &entries { ttypes.set(e.ttype, true); }
    Ok((entries, ttypes))
}

/// Key ordering used to group and to detect duplicates without a hash table.
fn key_cmp(a: &FilenameTrans, b: &FilenameTrans) -> core::cmp::Ordering {
    a.ttype.cmp(&b.ttype)
        .then(a.tclass.cmp(&b.tclass))
        .then(a.name.as_str().cmp(b.name.as_str()))
}

/// One record per source type; records sharing a key merge into one entry.
///
/// Merging is done by sorting rather than by scanning the entries built so far:
/// the count is attacker-controlled, and a linear scan per record turns a large
/// image into a quadratic load.
fn read_legacy(r: &mut Reader<'_>, nel: u32) -> Result<Vec<FilenameTrans>> {
    let mut raw: Vec<(u32, u32, String, u32, u32)> = Vec::new();
    raw.try_reserve(nel as usize).map_err(|_| Error::NoMemory)?;
    for _ in 0..nel {
        let len = r.u32()?;
        let name = String::from(r.string_of(len)?);
        let [stype, ttype, tclass, otype] = r.u32_array::<4>()?;
        if tclass > u32::from(u16::MAX) { return Err(Error::Malformed); }
        if stype == 0 { return Err(Error::Malformed); }
        raw.push((ttype, tclass, name, stype, otype));
    }
    raw.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)).then(a.2.as_str().cmp(b.2.as_str())));

    let mut out: Vec<FilenameTrans> = Vec::new();
    for (ttype, tclass, name, stype, otype) in raw {
        let fresh = match out.last() {
            Some(e) => e.ttype != ttype || e.tclass != tclass || e.name != name,
            None => true,
        };
        if fresh { out.push(FilenameTrans { ttype, tclass, name, data: Vec::new() }); }
        let entry = out.last_mut().ok_or(Error::Malformed)?;
        if !entry.data.iter().any(|d| d.otype == otype) {
            entry.data.push(FilenameTransDatum { stypes: Ebitmap::new(), otype });
        }
        for d in entry.data.iter_mut() {
            if d.otype == otype { d.stypes.set(stype - 1, true); }
        }
    }
    Ok(out)
}

/// One record per key, carrying a source-type bitmap per outcome.
fn read_compressed(r: &mut Reader<'_>, nel: u32) -> Result<Vec<FilenameTrans>> {
    let mut out: Vec<FilenameTrans> = Vec::new();
    out.try_reserve(nel as usize).map_err(|_| Error::NoMemory)?;
    for _ in 0..nel {
        let len = r.u32()?;
        let name = String::from(r.string_of(len)?);
        let [ttype, tclass, ndatum] = r.u32_array::<3>()?;
        if tclass > u32::from(u16::MAX) { return Err(Error::Malformed); }
        if ndatum == 0 { return Err(Error::Malformed); }
        let mut data = Vec::new();
        data.try_reserve(ndatum as usize).map_err(|_| Error::NoMemory)?;
        for _ in 0..ndatum {
            let stypes = Ebitmap::read(r)?;
            let otype = r.u32()?;
            data.push(FilenameTransDatum { stypes, otype });
        }
        out.push(FilenameTrans { ttype, tclass, name, data });
    }
    reject_duplicate_keys(&out)?;
    Ok(out)
}

/// Refuse two entries with the same key, which would make one unreachable.
fn reject_duplicate_keys(entries: &[FilenameTrans]) -> Result<()> {
    let mut order: Vec<usize> = Vec::new();
    order.try_reserve(entries.len()).map_err(|_| Error::NoMemory)?;
    for i in 0..entries.len() { order.push(i); }
    order.sort_by(|&a, &b| key_cmp(&entries[a], &entries[b]));
    for pair in order.windows(2) {
        if key_cmp(&entries[pair[0]], &entries[pair[1]]) == core::cmp::Ordering::Equal {
            return Err(Error::Duplicate);
        }
    }
    Ok(())
}
