// The station table.
//
// Module manifest:
// - `record`: one peer — its counters, its per-identifier state, its buffers.
// - `table`:  the per-interface table and the state-ladder walk.
// - `state`:  the ladder itself, as a pure decision.

#[path = "sta_info/record.rs"] pub mod record;
#[path = "sta_info/state.rs"] pub mod state;
#[path = "sta_info/table.rs"] pub mod table;

pub use record::{PsFrame, Sta};
pub use table::StaTable;
