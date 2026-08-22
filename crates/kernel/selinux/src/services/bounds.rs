//! Domain-bounds admission for dynamic process transitions.

use crate::error::{Error, Result};
use crate::policydb::Policydb;
use crate::sidtab::{Sid, Sidtab};

/// Whether `new_sid`'s type is unchanged or transitively bounded by
/// `old_sid`'s type. # C: O(types)
pub fn bounded_transition(db: &Policydb, sidtab: &Sidtab,
                          old_sid: Sid, new_sid: Sid) -> Result<bool> {
    let old_type = sidtab.lookup(old_sid).and_then(|c| c.valid()).map(|c| c.ty)
        .ok_or(Error::UnknownSid)?;
    let mut new_type = sidtab.lookup(new_sid).and_then(|c| c.valid()).map(|c| c.ty)
        .ok_or(Error::UnknownSid)?;
    if old_type == new_type { return Ok(true); }

    // Loaded policies reject type-bounds cycles. Keep this query bounded too,
    // because synthetic policy values and retained state must never turn a
    // permission check into an infinite walk.
    for _ in 0..db.symbols.types.len() {
        let bound = db.symbols.ty(new_type).ok_or(Error::UnknownSymbol)?.bounds;
        if bound == 0 { return Ok(false); }
        if bound == old_type { return Ok(true); }
        new_type = bound;
    }
    Ok(false)
}
