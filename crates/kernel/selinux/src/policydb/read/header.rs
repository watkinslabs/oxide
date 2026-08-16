// Policy image header: what the image claims to be, and the shape the rest of
// the read must expect.
//
// The declared table counts are cross-checked against the version rather than
// trusted, because every later section is read positionally: a wrong count
// consumes the wrong bytes and every subsequent field is silently misread.

use crate::ebitmap::Ebitmap;
use crate::error::{Error, Result};
use crate::reader::Reader;
use crate::uapi::version::{POLICYDB_CONFIG_MLS, POLICYDB_MAGIC, POLICYDB_SIGNATURE,
                          POLICYDB_VERSION_MLS, POLICYDB_VERSION_NEVERAUDIT,
                          POLICYDB_VERSION_PERMISSIVE, POLICYDB_VERSION_POLCAP,
                          version_supported};

/// Policy config bit: refuse the load when the image names an unknown class.
pub const POLICYDB_CONFIG_REJECT_UNKNOWN: u32 = 0x0002;
/// Policy config bit: grant, rather than deny, unknown classes.
pub const POLICYDB_CONFIG_ALLOW_UNKNOWN: u32 = 0x0004;

/// Length the signature string is always stored with.
const SIGNATURE_LEN: u32 = 8;

/// Per-version table counts: `(min version, max version, sym_num, ocon_num)`.
///
/// A version adds a symbol table or an object-context category by bumping
/// these counts; the image repeats them and the two must agree.
const COMPAT: [(u32, u32, u32, u32); 5] = [
    (15, 15, 5, 6),
    (16, 16, 6, 6),
    (17, 18, 6, 7),
    (19, 30, 8, 7),
    (31, 35, 8, 9),
];

/// Everything the header establishes about the rest of the image.
pub struct Header {
    /// Image version.
    pub version: u32,
    /// Whether contexts carry MLS ranges.
    pub mls: bool,
    /// Refuse the load on an unknown class or permission.
    pub reject_unknown: bool,
    /// Grant permissions on unknown classes.
    pub allow_unknown: bool,
    /// Number of symbol tables that follow.
    pub sym_num: u32,
    /// Number of object-context categories that follow.
    pub ocon_num: u32,
    /// Policy capability bits.
    pub policycaps: Ebitmap,
    /// Types whose domains run permissive.
    pub permissive_map: Ebitmap,
    /// Types whose denials are never audited.
    pub neveraudit_map: Ebitmap,
}

/// Table counts a version mandates, or `None` for a version outside the table.
fn compat_of(version: u32) -> Option<(u32, u32)> {
    COMPAT.iter().find(|(lo, hi, _, _)| (*lo..=*hi).contains(&version))
        .map(|(_, _, sym, ocon)| (*sym, *ocon))
}

/// Read the image header. # C: O(policy capability bits)
pub fn read(r: &mut Reader<'_>) -> Result<Header> {
    if r.u32()? != POLICYDB_MAGIC { return Err(Error::BadMagic); }
    let siglen = r.u32()?;
    if siglen != SIGNATURE_LEN { return Err(Error::BadSignature); }
    if r.take(siglen as usize)? != POLICYDB_SIGNATURE { return Err(Error::BadSignature); }

    let version = r.u32()?;
    if !version_supported(version) { return Err(Error::UnsupportedVersion(version)); }

    let config = r.u32()?;
    let mls = config & POLICYDB_CONFIG_MLS != 0;
    // MLS predates neither the config bit nor the level tables; an image
    // claiming MLS at an older version would leave every level read short.
    if mls && version < POLICYDB_VERSION_MLS { return Err(Error::MlsMismatch); }

    let (want_sym, want_ocon) = compat_of(version).ok_or(Error::UnsupportedVersion(version))?;
    let sym_num = r.u32()?;
    let ocon_num = r.u32()?;
    if sym_num != want_sym || ocon_num != want_ocon { return Err(Error::Malformed); }

    let policycaps = if version >= POLICYDB_VERSION_POLCAP { Ebitmap::read(r)? }
                     else { Ebitmap::new() };
    let permissive_map = if version >= POLICYDB_VERSION_PERMISSIVE { Ebitmap::read(r)? }
                         else { Ebitmap::new() };
    let neveraudit_map = if version >= POLICYDB_VERSION_NEVERAUDIT { Ebitmap::read(r)? }
                         else { Ebitmap::new() };

    Ok(Header {
        version,
        mls,
        reject_unknown: config & POLICYDB_CONFIG_REJECT_UNKNOWN != 0,
        allow_unknown: config & POLICYDB_CONFIG_ALLOW_UNKNOWN != 0,
        sym_num,
        ocon_num,
        policycaps,
        permissive_map,
        neveraudit_map,
    })
}
