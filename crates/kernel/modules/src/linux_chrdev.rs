// Module manifest: types owns Linux C layout, core owns cdev/major exports,
// misc owns Linux miscdevice registration over the cdev registry.

extern crate alloc;

mod core;
mod misc;
mod types;

/// Register Linux char/misc KPI symbols.
/// # C: O(1)
pub fn export_symbols() {
    core::export_symbols();
    misc::export_symbols();
}
