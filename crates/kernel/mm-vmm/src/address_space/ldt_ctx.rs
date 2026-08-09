// `AddressSpace`'s view of its Local Descriptor Table (Linux
// `mm->context.ldt` accessors). The state itself lives in `crate::ldt`; this
// child only exposes it so `address_space.rs` stays a manifest.

use super::AddressSpace;
use crate::ldt::{LdtError, LdtState, LdtView};

impl AddressSpace {
    /// This mm's LDT. `CLONE_VM` siblings reach the same object; a `fork`
    /// child reaches its own copy.
    /// # C: O(1)
    pub fn ldt(&self) -> &LdtState { &self.ldt }

    /// Lock-free snapshot for the context-switch and return-to-user paths.
    /// # C: O(1)
    pub fn ldt_view(&self) -> LdtView { self.ldt.view() }

    /// Build the child's table for `fork` (Linux `ldt_dup_context`). Called
    /// before the child object exists, so the result is moved in rather than
    /// installed.
    /// # C: O(table) when this mm has an LDT
    pub(super) fn dup_ldt(&self) -> Result<LdtState, LdtError> { self.ldt.dup() }
}
