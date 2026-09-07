//! Module manifest: codec owns WINDOWPLACEMENT; policy owns validated normal
//! placement transactions; kernel binds canonical GUI and process parameters.
#[path = "placement/codec.rs"]
mod codec;
#[path = "placement/policy.rs"]
mod policy;
pub(crate) use codec::Context;
#[cfg(target_os = "oxide-kernel")]
#[path = "placement/kernel.rs"]
mod kernel;
#[cfg(target_os = "oxide-kernel")]
pub(crate) use kernel::{set, get, show, record, apply_internal};
#[cfg(test)]
#[path = "tests/placement.rs"]
mod tests;
