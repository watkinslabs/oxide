// Module manifest: types owns Linux C layout, alloc owns netdev allocation,
// skb owns sk_buff storage, core owns exported netdev facade, napi owns poll
// scheduling, ethtool owns link/report helpers, phy owns PHY compatibility,
// mdio owns managed MDIO-bus lifetime, dql owns byte queue limits.

mod alloc;
mod core;
mod dql;
mod ethtool;
mod misc;
mod mdio;
mod napi;
mod phy;
mod skb;
mod types;

/// Register Linux netdev KPI symbols.
/// # C: O(1)
pub fn export_symbols() {
    core::export_symbols();
    dql::export_symbols();
    ethtool::export_symbols();
    misc::export_symbols();
    mdio::export_symbols();
    napi::export_symbols();
    phy::export_symbols();
    skb::export_symbols();
}
