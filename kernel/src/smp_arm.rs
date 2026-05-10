// Thin re-export shim per `52§8` migration. Implementation lives in
// `crates/hal-aarch64/src/smp.rs`. arm-only AP startup driver.

#![cfg(target_arch = "aarch64")]

pub use hal_aarch64::smp::*;
