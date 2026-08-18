//! CPU idle-state phandle graph decoder.

extern crate alloc;

mod parse;
mod types;

#[cfg(test)]
mod tests;

pub use parse::cpu_idle_tables;
pub use types::{CpuIdleState, CpuIdleTable};
