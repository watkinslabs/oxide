// Module manifest: types owns Linux C layout; core owns driver registry,
// coherent buffers, URBs, and exported USB transfer facade.

mod core;
mod types;

/// Register Linux USB KPI symbols.
/// # C: O(1)
pub fn export_symbols() {
    core::export_symbols();
}
