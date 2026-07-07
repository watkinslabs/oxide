// Module manifest: types owns Linux C layout, maps owns iomap state, core owns exported PCI facade.

mod core;
mod maps;
mod types;

/// Register Linux PCI KPI symbols.
/// # C: O(1)
pub fn export_symbols() {
    core::export_symbols();
}
