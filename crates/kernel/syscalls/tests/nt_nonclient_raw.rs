//! Normal hosted tests compile the production decoder against the canonical owner.
// Compile-only fixture: no #[test] fn calls anything here.
#![allow(dead_code, unused_imports)]
use ipc::win32_gdi::{nonclient_defaults, logfont, NonclientFont, GdiError, NONCLIENT_BYTES, NONCLIENT_LEGACY_BYTES};
use ipc::win32_sysparams::{Request, SystemParameters};
#[path = "../src/nt_wine_window/nonclient_raw.rs"]
mod decoder;
