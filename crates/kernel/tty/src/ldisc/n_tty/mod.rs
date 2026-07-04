// Module manifest:
// - `timing`: pure IXON/VMIN/VTIME decision helpers shared by tty core and tests.
// - `state`: `NTty` state plus private canonical/raw helper routines.
// - `ops`: the `LdiscOps` implementation over `NTty`.

mod timing;
mod state;
mod ops;

pub use state::NTty;
pub use timing::{flow_action, vmin_vtime_decision, FlowAction, VmtDecision, VTIME_TENTH_NS};
