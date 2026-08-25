// Module manifest: input-delivery smoke generation lives in `core`; its
// contract tests live under `tests/`.
use super::{dbg, dbg_ignore};
#[path = "input_delivery/core.rs"] mod core;
pub(super) use core::{inject, Mode};
#[cfg(test)]
#[path = "input_delivery/tests/mod.rs"] mod tests;
