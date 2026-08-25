// Module manifest: boot-line composition lives in `core`; contract tests live
// under `tests/` so the command-line policy and its assertions stay separate.
use super::serial_device_name;
#[path = "bootargs/core.rs"] mod core;
pub(super) use core::{kernel_cmdline, kernel_cmdline_for_root};
#[cfg(test)]
#[path = "bootargs/tests/mod.rs"] mod tests;
