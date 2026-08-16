// The `/sys/class/thermal` surface. Owned here rather than in the filesystem
// layer: which attributes a device publishes, what they render as and what a
// write to one means are thermal decisions, and putting them here is what
// makes them testable without a mount.
//
// Module manifest:
// - `names`: attribute names, including the per-trip and per-binding families.
// - `zone`: the zone half — trips, mode, policy, bindings.
// - `cdev`: the cooling-device half — range, current state, statistics.
// - `dispatch`: routing a class device name to the half that owns it.

pub mod names;
pub mod zone;
pub mod cdev;
pub mod dispatch;

pub use dispatch::{attrs, links, show, store, uevent_env};
