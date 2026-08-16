// Frequency governors: the policy that turns a demand signal into a target
// frequency.
//
// Each governor is a pure function over a snapshot of the policy and the
// demand measured on it, so what a governor would do at a given load is
// checkable without a policy, a driver or a clock.
//
// Module manifest:
// - `input`: the snapshot, the demand signal, and the target returned.
// - `simple`: the three governors with no state — always-fastest,
//   always-slowest, and the one that does what userspace wrote.
// - `ondemand`: sampled-load scaling with a jump to maximum under load.
// - `schedutil`: scheduler-utilisation scaling with its wait-for-IO boost.
// - `registry`: the governor list, the default, and lookup by name.

pub mod input;
pub mod simple;
pub mod ondemand;
pub mod schedutil;
pub mod registry;

pub use input::{Demand, Snapshot, Target};
pub use registry::{available_names, by_name, default_governor, Governor, GOVERNORS};
