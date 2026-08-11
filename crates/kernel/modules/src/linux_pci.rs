// Module manifest: types owns Linux C layout, maps owns iomap state, registry bridges Linux PCI drivers to the Rust driver model, core owns exported PCI facade, regions owns BAR ownership, pcie owns PCIe capability access, vectors owns IRQ vector allocation, pm owns PCI power management.

mod core;
mod config;
mod maps;
mod pm;
mod pcie;
mod registry;
mod regions;
mod status;
mod types;
mod vectors;

/// Reflect a bound module driver's DMA-mask change into its bus device. # C: O(N_bindings)
pub(crate) fn sync_dma_masks(dev: *mut crate::linux_dma::LinuxDevice, streaming: Option<u64>, coherent: Option<u64>) {
    registry::sync_dma_masks(dev, streaming, coherent);
}

/// Resolve a Linux device facade to its exact PCI requester identity. # C: O(N_bindings)
pub(crate) fn bdf_for_device(dev: *const crate::linux_dma::LinuxDevice) -> Option<pci::Bdf> {
    registry::bdf_for_device(dev)
}

/// Register Linux PCI KPI symbols.
/// # C: O(1)
pub fn export_symbols() {
    core::export_symbols();
    pcie::export_symbols();
    pm::export_symbols();
    status::export_symbols();
}
