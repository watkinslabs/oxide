// Module manifest: types owns Linux C layout, core owns exported device facade,
// allocs owns heap layout, registry owns pointer tables, devres owns managed resources,
// format owns bounded printf parsing, kobject owns Linux kobject/sysfs helpers.

extern crate alloc;

mod allocs;
mod core;
pub(crate) mod devres;
mod format;
mod kobject;
mod registry;
pub(crate) mod types;

/// Register Linux device-core KPI symbols.
/// # C: O(1)
pub fn export_symbols() {
    core::export_symbols();
}
