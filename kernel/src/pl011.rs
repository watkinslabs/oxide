// Thin re-export shim per `52§8` migration. Implementation lives in
// `crates/hal-aarch64/src/pl011.rs`. arm-only PL011 UART driver.

#![cfg(target_arch = "aarch64")]

pub use hal_aarch64::pl011::*;
