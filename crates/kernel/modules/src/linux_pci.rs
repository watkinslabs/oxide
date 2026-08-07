// Module manifest: types owns Linux C layout, maps owns iomap state, registry bridges Linux PCI drivers to the Rust driver model, core owns exported PCI facade, vectors owns IRQ vector allocation, pm owns PCI power management.

mod core;
mod maps;
mod pm;
mod registry;
mod types;
mod vectors;

/// Reflect a bound module driver's DMA-mask change into its bus device. # C: O(N_bindings)
pub(crate) fn sync_dma_masks(dev: *mut crate::linux_dma::LinuxDevice, streaming: Option<u64>, coherent: Option<u64>) {
    registry::sync_dma_masks(dev, streaming, coherent);
}

/// Register Linux PCI KPI symbols.
/// # C: O(1)
pub fn export_symbols() {
    core::export_symbols();
    pm::export_symbols();
}
