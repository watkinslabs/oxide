//! Canonical GDI handle identity. Client table entries project these identities.
use super::{GdiError, GdiManager};

pub const FIRST_DYNAMIC_SLOT: u32 = 64;
pub const SLOT_LIMIT: u32 = 0x10000;
pub const SLOT_MASK: u32 = SLOT_LIMIT - 1;
pub const TYPE_DC: u32 = 0x010000;
pub const TYPE_FONT: u32 = 0x0a0000;

impl GdiManager {
    pub(super) fn allocate(&mut self, kind: u32) -> Result<u32, GdiError> {
        if self.next >= SLOT_LIMIT { return Err(GdiError::HandleLimit); }
        let slot = self.next;
        self.next += 1;
        Ok(kind | slot)
    }
}

#[cfg(test)]
#[path = "tests/handles.rs"]
mod tests;
