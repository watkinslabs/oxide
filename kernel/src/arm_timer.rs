// Thin re-export shim per `52§8` migration. Implementation lives in
// `crates/hal-aarch64/src/timer.rs` (renamed from arm_timer per
// 52§6 — the `arm_` prefix is redundant inside hal-aarch64).

#![cfg(target_arch = "aarch64")]

pub use hal_aarch64::timer::*;
