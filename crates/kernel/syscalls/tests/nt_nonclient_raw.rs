//! Normal hosted tests compile the production decoder and immutable canonical owner.
// Compile-only fixture: no #[test] fn calls anything here.
#![allow(dead_code, unused_imports)]
use ipc::win32_gdi::{stock_object, Font, StockDescription, FontRecord, GdiError};
#[path = "../src/nt_wine_window/nonclient_raw.rs"]
mod decoder;
#[path = "../../ipc/src/win32_gdi/nonclient.rs"]
mod owner;
