// Module manifest: types owns Linux C layout, maps owns resource iomap
// state, core owns platform/ACPI/OF exported facade and matching.

mod core;
mod maps;
mod types;

pub(crate) use core::device_match_data;

/// Register Linux platform/firmware KPI symbols.
/// # C: O(1)
pub fn export_symbols() {
    core::export_symbols();
}
