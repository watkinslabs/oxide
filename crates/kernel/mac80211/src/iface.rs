// Virtual interfaces.
//
// Module manifest:
// - `sdata`:     one interface's state and its accessors.
// - `lifecycle`: create, start, stop, destroy, change type.
// - `config`:    recomputing device and interface configuration and pushing
//                what moved down to the driver.

#[path = "iface/sdata.rs"] pub mod sdata;
#[path = "iface/lifecycle.rs"] pub mod lifecycle;
#[path = "iface/config.rs"] pub mod config;

pub use config::{apply_conf, set_bss, set_channel, set_tx_params, update_bss};
pub use lifecycle::{add, change_type, derive_addr, down, remove, up};
pub use sdata::{IfaceStats, Sdata, SdataState};
