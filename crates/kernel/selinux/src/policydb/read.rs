// Reader for a binary policy image.
//
// Module manifest:
//   header — magic, signature, version, config bits and the per-version
//            symbol/object-context table counts
//   slots  — value-indexed placement of symbol records, alias-aware
//   syms   — the eight symbol tables and the permission bits derived from them
//   ctx    — a security context plus the symbol-range validation it needs
//   cond   — the conditional block list and its enabled-bit recomputation
//   trans  — role, filename and range transitions
//   ocon   — object contexts and per-filesystem path contexts
//   load   — the section order, and the whole-image entry point

mod header;
mod slots;
mod syms;
mod ctx;
mod cond;
mod trans;
mod ocon;
mod load;

pub use cond::evaluate_cond_nodes;
pub use header::{POLICYDB_CONFIG_ALLOW_UNKNOWN, POLICYDB_CONFIG_REJECT_UNKNOWN};
pub use load::load;
