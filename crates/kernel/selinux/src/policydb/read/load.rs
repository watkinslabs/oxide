// Section order of a policy image, and the whole-image entry point.
//
// Sections are positional and unlabelled: there is no way to resynchronise
// after a misread, so the order below IS the format. A load either consumes
// the image exactly or fails.

use alloc::vec::Vec;

use crate::avtab::Avtab;
use crate::ebitmap::Ebitmap;
use crate::error::{Error, Result};
use crate::policydb::symbols::{SYM_BOOLS, SYM_TYPES};
use crate::policydb::Policydb;
use crate::reader::Reader;
use crate::uapi::version::{POLICYDB_VERSION_AVTAB, POLICYDB_VERSION_BOOL};

use super::{cond, header, ocon, syms, trans};

/// Class every domain transition is checked against.
const CLASS_PROCESS: &str = "process";

/// Read a whole policy image. # C: O(image)
///
/// A partially-read policy is never returned: a caller that could consult one
/// would be answering with rules the image never finished declaring.
pub fn load(bytes: &[u8]) -> Result<Policydb> {
    load_from(&mut Reader::new(bytes))
}

/// Read a policy from a positioned cursor, so a failure's offset is testable.
fn load_from(r: &mut Reader<'_>) -> Result<Policydb> {
    let h = header::read(r)?;
    let symbols = syms::read_all(r, h.version, h.sym_num)?;
    let process_class = symbols.class_by_name(CLASS_PROCESS).ok_or(Error::UnknownSymbol)?;
    let process_trans_perms = syms::process_trans_perms(&symbols, process_class)?;

    let te_avtab = Avtab::read(r, h.version)?;
    let (te_cond_avtab, cond_list) = if h.version >= POLICYDB_VERSION_BOOL {
        cond::read_list(r, h.version, symbols.nprim[SYM_BOOLS], te_avtab.len())?
    } else {
        (Avtab::with_capacity(0), Vec::new())
    };

    let role_tr = trans::read_role_trans(r, h.version, process_class)?;
    let role_allow = trans::read_role_allow(r)?;
    let (filename_trans, filename_trans_ttypes) = trans::read_filename_trans(r, h.version)?;
    let ocontexts = ocon::read_all(r, h.mls, &symbols, h.ocon_num)?;
    let genfs = ocon::read_genfs(r, h.mls, &symbols)?;
    let range_tr = trans::read_range_trans(r, h.version, process_class)?;
    let type_attr_map = read_type_attr_map(r, h.version, symbols.nprim[SYM_TYPES])?;

    // Trailing bytes mean the reader and the writer disagree about some earlier
    // section's length, so everything read is suspect.
    if !r.at_end() { return Err(Error::Malformed); }

    let mut db = Policydb {
        version: h.version,
        mls: h.mls,
        reject_unknown: h.reject_unknown,
        allow_unknown: h.allow_unknown,
        symbols,
        te_avtab,
        te_cond_avtab,
        cond_list,
        role_tr,
        role_allow,
        filename_trans,
        filename_trans_ttypes,
        ocontexts,
        genfs,
        range_tr,
        type_attr_map,
        permissive_map: h.permissive_map,
        neveraudit_map: h.neveraudit_map,
        policycaps: h.policycaps,
        process_class,
        process_trans_perms,
    };
    cond::evaluate_cond_nodes(&mut db);
    Ok(db)
}

/// Read the type-to-attribute map, one set per type value. # C: O(types)
///
/// Each type's own value is forced into its set. Rules are stored against
/// types and attributes interchangeably and the decision path iterates this
/// set, so without the self bit every plain type rule becomes invisible and
/// the engine denies accesses the policy plainly grants.
fn read_type_attr_map(r: &mut Reader<'_>, version: u32, ntypes: u32) -> Result<Vec<Ebitmap>> {
    let mut map: Vec<Ebitmap> = Vec::new();
    map.try_reserve(ntypes as usize).map_err(|_| Error::NoMemory)?;
    for _ in 0..ntypes {
        let set = if version >= POLICYDB_VERSION_AVTAB { Ebitmap::read(r)? } else { Ebitmap::new() };
        map.push(set);
    }
    for (i, set) in map.iter_mut().enumerate() { set.set(i as u32, true); }
    Ok(map)
}

#[cfg(test)]
#[path = "../../tests/policydb.rs"]
mod tests;
