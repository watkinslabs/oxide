// Security contexts embedded in the non-symbol sections.
//
// Each component is checked against the symbol tables as it is read. Full
// context validation (role membership, clearance) is deliberately NOT done
// here: sections legitimately reference contexts whose supporting tables are
// still being built, so the caller validates once the policy is whole.

use crate::context::ValidContext;
use crate::error::{Error, Result};
use crate::policydb::symbols::{Symbols, SYM_ROLES, SYM_TYPES, SYM_USERS};
use crate::reader::Reader;

/// Read one context, refusing a dangling symbol value. # C: O(categories)
pub fn read(r: &mut Reader<'_>, mls: bool, s: &Symbols) -> Result<ValidContext> {
    let c = ValidContext::read(r, mls)?;
    check_value(c.user, s.nprim[SYM_USERS])?;
    check_value(c.role, s.nprim[SYM_ROLES])?;
    check_value(c.ty, s.nprim[SYM_TYPES])?;
    Ok(c)
}

/// Refuse a 1-based symbol value outside its table. # C: O(1)
pub fn check_value(value: u32, nprim: u32) -> Result<()> {
    if value == 0 || value > nprim { return Err(Error::UnknownSymbol); }
    Ok(())
}
