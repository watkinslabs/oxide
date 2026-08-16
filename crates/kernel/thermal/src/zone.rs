// A thermal zone: one temperature, the trips declared against it, and the
// cooling devices bound to those trips.
//
// Module manifest:
// - `desc`: the provider interface, the zone declaration, and a bind request.
// - `state`: the zone object, its mutable state, and the accessors sysfs uses.
// - `pass`: one update — read, cross trips, govern, apply, re-arm.
// - `bind`: attaching and detaching cooling devices.

pub mod desc;
pub mod state;
pub mod pass;
pub mod bind;

pub use desc::{BindSpec, ZoneDesc, ZoneOps};
pub use state::ThermalZone;
pub use pass::{update, Outcome};
