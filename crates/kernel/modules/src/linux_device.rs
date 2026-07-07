// Module manifest: types owns Linux C layout, core owns exported device facade,
// allocs owns heap layout, registry owns pointer tables, devres owns managed resources,
// format owns bounded printf parsing.

extern crate alloc;

mod allocs;
mod core;
mod devres;
mod format;
mod registry;
mod types;

/// Register Linux device-core KPI symbols.
/// # C: O(1)
pub fn export_symbols() {
    core::export_symbols();
}
