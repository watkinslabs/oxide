// Module manifest: types owns Linux C layout, alloc owns netdev allocation,
// skb owns sk_buff storage, core owns exported netdev facade.

mod alloc;
mod core;
mod skb;
mod types;

/// Register Linux netdev KPI symbols.
/// # C: O(1)
pub fn export_symbols() {
    core::export_symbols();
    skb::export_symbols();
}
