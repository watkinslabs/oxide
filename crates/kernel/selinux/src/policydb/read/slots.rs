// Value-indexed placement of symbol records.
//
// Records arrive in whatever order the policy compiler emitted them, but every
// other section refers to them by 1-based value, so the vector index must be
// the value and not the arrival position. Aliases share a value with the
// primary record and must never displace it: an alias sitting in the value slot
// would answer name lookups with a name the rest of the policy never uses.

use alloc::vec::Vec;

use crate::error::{Error, Result};

/// Records being collected into their value slots.
pub struct Slots<T> {
    items: Vec<Option<(bool, T)>>,
}

impl<T> Slots<T> {
    /// Empty slots for values `1..=n`. # C: O(n)
    pub fn new(n: u32) -> Result<Self> {
        let mut items = Vec::new();
        items.try_reserve(n as usize).map_err(|_| Error::NoMemory)?;
        for _ in 0..n { items.push(None); }
        Ok(Self { items })
    }

    /// Store a record at its value, keeping a primary over an alias. # C: O(1)
    pub fn place(&mut self, value: u32, primary: bool, item: T) -> Result<()> {
        let idx = value.checked_sub(1).ok_or(Error::Malformed)? as usize;
        let slot = self.items.get_mut(idx).ok_or(Error::Malformed)?;
        match slot {
            Some((occupant_primary, _)) => {
                if primary && *occupant_primary { return Err(Error::Duplicate); }
                if primary { *slot = Some((primary, item)); }
                Ok(())
            }
            None => { *slot = Some((primary, item)); Ok(()) }
        }
    }

    /// The filled vector, refusing a value the image never declared. # C: O(n)
    pub fn finish(self) -> Result<Vec<T>> {
        let mut out = Vec::new();
        out.try_reserve(self.items.len()).map_err(|_| Error::NoMemory)?;
        for slot in self.items {
            out.push(slot.ok_or(Error::Malformed)?.1);
        }
        Ok(out)
    }
}
