//! F721 host-oracle differential syscall-conformance harness (`docs/15`).
//!
//! Module manifest: `oracle` runs a case's Linux ground truth on THIS host
//! kernel (the machine running `cargo test` is real Linux — the oracle);
//! `outcome` is the shared host/oxide result type + errno-class comparison;
//! `corpus` is the table-driven case runner + known-divergence bookkeeping
//! shared by every `conformance_*.rs` test file across every crate.
//!
//! Hosted-only (std, not `#![no_std]`): this crate never ships in a kernel
//! image, it is a `[dev-dependencies]`-only test harness (`docs/02` dev-tool
//! carve-out, same class as `tools/spec-lint`).
pub mod corpus;
pub mod oracle;
pub mod outcome;
