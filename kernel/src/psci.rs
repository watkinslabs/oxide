// Thin re-export shim per `52§8` migration. Implementation lives in
// `crates/hal-aarch64/src/psci.rs`. arm-only PSCI CPU_ON wrapper.

#![cfg(target_arch = "aarch64")]

pub use hal_aarch64::psci::*;
