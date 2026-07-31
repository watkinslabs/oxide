// Per-user resource accounting keyed by `(user namespace, uid)` — Linux
// `struct ucounts` (`kernel/ucount.c`). The counter that makes this load
// bearing is `RLIMIT_NPROC`: without it a uid can fork without bound, and
// `setuid(2)`/`execve(2)` lose the deferred-EAGAIN contract that stops a
// privileged daemon from dropping into an over-quota account.
//
// Counts are HIERARCHICAL. A task charged in a nested user namespace also
// charges the ucounts of that namespace's CREATOR in the parent namespace,
// all the way to the initial namespace — otherwise `unshare(CLONE_NEWUSER)`
// would reset every count to zero and be a one-line quota escape. Each level
// is bounded by the ceiling recorded on the namespace BELOW it, which is the
// creating task's own `RLIMIT_NPROC` at creation time.
//
// Module manifest:
// - key:      the `(namespace, uid)` identity a count hangs off.
// - counter:  the counted resource kinds and the per-key counter array.
// - chain:    per-user-namespace creator link + ceiling (Linux
//             `user_namespace::ucounts` / `rlimit_max`).
// - table:    the global key -> counters map and its lifetime rules.
// - rlimit:   the hierarchical inc/dec/overlimit walks.

#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

mod chain;
mod counter;
mod key;
mod rlimit;
mod table;

pub use chain::{forget_namespace, register_namespace, RLIM_INFINITY};
pub use counter::Counter;
pub use key::UcountKey;
pub use rlimit::{dec_rlimit, inc_rlimit, is_overlimit, value};

#[cfg(test)]
mod tests;
