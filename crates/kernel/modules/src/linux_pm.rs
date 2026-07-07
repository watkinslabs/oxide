// Module manifest: types owns Linux C PM layout, core owns exported runtime/system/wakeup PM facade.

pub(crate) mod types;
mod core;

/// Register Linux PM KPI symbols.
/// # C: O(1)
pub fn export_symbols() {
    core::export_symbols();
}
