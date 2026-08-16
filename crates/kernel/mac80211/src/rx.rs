// The receive path.
//
// Module manifest:
// - `chain`:   the ordered handler chain and the entry point drivers call.
// - `decrypt`: the decryption step and the replay decision.
// - `defrag`:  reassembly of fragmented frames.
// - `mgmt`:    management-frame dispatch and the protection rule.
// - `ctl`:     control frames.
// - `data`:    reordering, conversion and the receive side of the port.

#[path = "rx/chain.rs"] pub mod chain;
#[path = "rx/ctl.rs"] pub mod ctl;
#[path = "rx/data.rs"] pub mod data;
#[path = "rx/decrypt.rs"] pub mod decrypt;
#[path = "rx/defrag.rs"] pub mod defrag;
#[path = "rx/mgmt.rs"] pub mod mgmt;

pub use chain::rx;
pub use decrypt::{Decrypted, requires_protection};
pub use defrag::{Defrag, DefragCache};
pub use mgmt::may_act_on_mlme;
