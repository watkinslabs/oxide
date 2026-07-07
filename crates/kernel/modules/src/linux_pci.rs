// Module manifest: types owns Linux C layout, maps owns iomap state, registry bridges Linux PCI drivers to the Rust driver model, core owns exported PCI facade, vectors owns IRQ vector allocation, pm owns PCI power management.

mod core;
mod maps;
mod pm;
mod registry;
mod types;
mod vectors;

/// Register Linux PCI KPI symbols.
/// # C: O(1)
pub fn export_symbols() {
    core::export_symbols();
    pm::export_symbols();
}
