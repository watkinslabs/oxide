// Module manifest: types owns Linux C layout; convert owns bitmap/model translation; core owns exported input facade.

mod convert;
mod core;
mod types;

/// Register Linux input KPI symbols.
/// # C: O(1)
pub fn export_symbols() {
    core::export_symbols();
}
