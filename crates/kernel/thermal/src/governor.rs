// Thermal governors: the policy that turns a temperature and a set of trip
// crossings into cooling-device targets.
//
// Every governor is a pure function over a snapshot (`input`), never over the
// live zone. Two reasons, both load-bearing: the decision is then testable
// without a sensor or a fan, and the zone can release its lock before it
// touches a provider — a cooling device backed by firmware evaluates AML to
// change state, which must not happen under a spinlock.
//
// Module manifest:
// - `input`: the snapshot a governor sees and the target list it returns.
// - `step_wise`: one step per sample, following the temperature trend.
// - `bang_bang`: full on above the trip, off below the hysteresis band.
// - `fair_share`: state proportional to trip depth and instance weight.
// - `user_space`: no cooling of its own; publishes the crossing instead.
// - `registry`: the governor list, the default, and lookup by name.

pub mod input;
pub mod step_wise;
pub mod bang_bang;
pub mod fair_share;
pub mod user_space;
pub mod registry;

pub use input::{GovInput, Governor, InstanceView};
pub use registry::{available_names, by_name, default_governor, GOVERNORS};
