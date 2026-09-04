//! Native Windows scheduler state and fixed-priority dispatcher.

extern crate alloc;

mod entity;
mod policy;
mod process;
mod runqueue;

pub use entity::{NtAdjustReason, NtSchedSnapshot};
pub use policy::{class_relative_priority, NtPriorityClass, NtQuantumPolicy,
    NtRelativePriority};
pub use process::{apply_nt_process, apply_nt_thread, initialize_current_process,
    initialize_new_thread,
    NtProcessSchedConfig, NtProcessSchedRequest, NtSchedError, NtThreadSchedRequest};
pub(crate) use entity::NtEntityState;
pub(crate) use policy::{boost, tick, unwait, NtTickOutcome};
pub(crate) use process::{tick_unlocked, NtProcessState};
pub(crate) use runqueue::NtRunqueue;

#[cfg(test)]
#[path = "nt/tests.rs"]
mod tests;
