// Module manifest: types owns Linux C layout; contract owns the ungated ownership/length decisions;
// core owns legacy BIO facade; mq owns blk-mq/request facade.

mod contract;
mod core;
mod misc;
mod mq;
mod types;

/// Register Linux block KPI symbols.
/// # C: O(1)
pub fn export_symbols() {
    core::export_symbols();
    mq::export_symbols();
    misc::export_symbols();
}
