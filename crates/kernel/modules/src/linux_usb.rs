// Module manifest: types owns Linux C layout; core owns host driver registry,
// coherent buffers, URBs, and transfer facade; gadget owns device-side USB.

mod core;
mod gadget;
mod types;

/// Register Linux USB KPI symbols.
/// # C: O(1)
pub fn export_symbols() {
    core::export_symbols();
    gadget::export_symbols();
}
