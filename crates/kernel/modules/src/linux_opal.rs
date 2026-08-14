// Module manifest: `device` owns opaque OPAL device lifetime, Discovery 0,
// saved-unlock replay, and the public module-ABI entry points.

mod device;

/// Register the TCG OPAL storage security ABI used by NVMe controllers.
/// # C: O(1)
pub fn export_symbols() { device::export_symbols(); }
