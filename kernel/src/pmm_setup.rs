// Thin re-export shim per `52§8` migration policy. The PMM bring-up
// + page-meta + rmap-adapter implementation lives in `crates/pmm-setup`
// (Stage B-0). Existing call sites that say `crate::pmm_setup::*`
// keep compiling unchanged; this shim disappears once Stage C
// rewrites the imports.

#![cfg(target_os = "oxide-kernel")]

pub use pmm_setup::*;
