//! SMC SCMI performance transport and CPU-domain decoder.
//!
//! Module manifest:
//!   types — transport, shared-memory, and CPU-domain records
//!   parse — FDT graph and address-range resolution
//!   tests — fixture-backed binding and rejection coverage

mod types;
mod parse;

pub use types::{ScmiCompletionIrq, ScmiCpuDomain, ScmiPerfProtocol, ScmiSharedMemory, ScmiSmcTransport};
pub use parse::scmi_perf_protocols;

#[cfg(test)]
mod tests;
