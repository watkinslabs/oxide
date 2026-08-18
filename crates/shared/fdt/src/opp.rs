//! Device-tree CPU operating-point tables.
//!
//! Module manifest:
//! - `types` — decoded CPU/table/voltage records.
//! - `parse` — phandle graph and OPP-table validation.

mod parse;
mod types;

pub use parse::cpu_opp_tables;
pub use types::{ClockReference, CpuOppTable, OppVoltage, OperatingPoint};

#[cfg(test)]
mod tests;
