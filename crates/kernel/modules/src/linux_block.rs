// Module manifest: types owns Linux C layout; core owns exported block facade.

mod core;
mod types;

/// Register Linux block KPI symbols.
/// # C: O(1)
pub fn export_symbols() {
    core::export_symbols();
}
