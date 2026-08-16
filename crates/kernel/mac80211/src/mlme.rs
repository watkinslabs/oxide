// The management entity: everything between an interface that is up and a
// link that carries traffic.
//
// Module manifest:
// - `state`:  the client state machine, as a pure decision.
// - `run`:    turning a decision into frames, station state and reports.
// - `auth`:   the authentication exchange.
// - `assoc`:  the association exchange.
// - `deauth`: ending a link, in both directions.
// - `beacon`: beacon monitoring, the traffic-indication map, the beacon an
//             access-point interface transmits.
// - `ap`:     the access-point side of the exchange.
// - `action`: action frames, which today means block-ack negotiation.
// - `timers`: every deadline, driven from one place.

#[path = "mlme/state.rs"] pub mod state;
#[path = "mlme/run.rs"] pub mod run;
#[path = "mlme/auth.rs"] pub mod auth;
#[path = "mlme/assoc.rs"] pub mod assoc;
#[path = "mlme/deauth.rs"] pub mod deauth;
#[path = "mlme/beacon.rs"] pub mod beacon;
#[path = "mlme/ap.rs"] pub mod ap;
#[path = "mlme/action.rs"] pub mod action;
#[path = "mlme/timers.rs"] pub mod timers;

pub use state::{MlmeAction, MlmeEvent, MlmeState, MlmeStep};
pub use timers::tick;
