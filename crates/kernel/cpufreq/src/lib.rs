// CPU frequency scaling. Owns the operating points a platform declares, the
// aggregation of every limit in force on them, the governors that choose
// between them, the transition statistics, and the sysfs surface that
// publishes all of it.
//
// Contains no architecture code and no firmware code: the driver interface
// takes a table index, providers register into it, and the scheduler's
// utilisation signal reaches it through one hook.
//
// Module manifest:
// - `uapi`: table-entry flags, the resolution relations, attribute text.
// - `limits`: unit conversions, defaults, the sampling-interval rule.
// - `table`: the operating points and the resolution rule over them.
// - `policy`: one clock domain, its limit sources, and their aggregation.
// - `stats`: per-frequency occupancy and the transition matrix.
// - `governor`: the policies, each a pure function over a snapshot.
// - `driver`: registration, driving a target, applying a limit change.
// - `attrs`: the `cpufreq/` and `cpufreq/stats/` attribute contract.
// - `util`: the scheduler-side utilisation hook (kernel builds only).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod attrs;
pub mod driver;
pub mod governor;
pub mod limits;
pub mod policy;
pub mod stats;
pub mod table;
pub mod uapi;

#[cfg(target_os = "oxide-kernel")]
pub mod util;

pub use driver::{cur_freq, drive, govern, policies, policy_for, register_driver,
                 register_policy, set_limits, CpufreqOps, Driver};
pub use governor::{Demand, Snapshot, Target};
pub use policy::{LimitSource, Limits, Policy, Request};
pub use table::{FreqEntry, FreqTable, TableError};
pub use uapi::{PolicyKind, Relation};
