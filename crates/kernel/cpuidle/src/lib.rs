// CPU idle. Owns the idle-state table a platform declares, the governors that
// choose between those states, the per-CPU accounting a reader uses to judge
// whether the choices were good, and the sysfs surface that publishes both.
//
// Contains no architecture code and no firmware code: the driver interface
// takes the entry method as data, providers register into it, and the
// scheduler's idle loop drives one cycle per park.
//
// Module manifest:
// - `uapi`: state flags, the two disable reasons, attribute text.
// - `limits`: state-count bound, unit conversions, governor thresholds.
// - `state`: one declared state and the table-ordering contract.
// - `usage`: per-state counters and the two mispredict classifications.
// - `governor`: the predictors and the selection over the state table.
// - `driver`: registration, the per-CPU device, governor selection.
// - `select`: one idle cycle — select, enter, measure, reflect.
// - `attrs`: the `cpuidle/state<M>/` attribute contract.
// - `idle`: the scheduler-side entry point (kernel builds only).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod attrs;
pub mod driver;
pub mod governor;
pub mod limits;
pub mod select;
pub mod state;
pub mod uapi;
pub mod usage;

#[cfg(target_os = "oxide-kernel")]
pub mod idle;

pub use driver::{driver, register, register_per_cpu, Driver, IdleOps};
pub use governor::{Governor, Kind, Reflection, SelectInput, Selection};
pub use select::{idle_cycle, Conditions, Cycle};
pub use state::{Entry, IdleState, TableError};
pub use usage::{Mispredict, StateUsage};
