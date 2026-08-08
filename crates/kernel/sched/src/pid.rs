// Module manifest:
// - identity: `PidIdentity` — the PID object retained independently of a task
//   allocation, its exit/reap publication, and its credential snapshot.
// - numbers: per-namespace number allocation, the inner-to-outer number
//   mapping, and `nr_in` — the number an identity carries as seen from a
//   named namespace.

mod identity;
mod numbers;

#[cfg(test)]
mod tests;

pub use identity::{CoredumpRecord, PidIdentity, PidInfo};
pub use numbers::{PidMapping, PidMappingError};
