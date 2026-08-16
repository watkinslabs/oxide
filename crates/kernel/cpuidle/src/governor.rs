// Idle governors: which state the CPU is put into when it has nothing to run.
//
// A governor is a per-CPU predictor plus a pure selection over the state
// table. Both halves are ungated and take the sleep-length estimate as an
// argument rather than reading a clock, so the whole decision is checkable
// without an idle CPU.
//
// Module manifest:
// - `input`: what a governor sees, what it returns, and the shared scan.
// - `menu`: correction-factor prediction with an interval detector.
// - `teo`: timer-event-oriented prediction from hit and intercept counts.
// - `registry`: the governor list, the default, and lookup by name.

pub mod input;
pub mod menu;
pub mod teo;
pub mod registry;

pub use input::{Reflection, SelectInput, Selection};
pub use registry::{available_names, by_name, default_governor, Governor, Kind, State};
