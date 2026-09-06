//! Normal hosted tests compile the production decoder and immutable canonical owner.
use ipc::win32_gdi::{stock_object, StockDescription, FontRecord, GdiError};
#[path = "../src/nt_wine_window/nonclient_raw.rs"]
mod decoder;
#[path = "../../ipc/src/win32_gdi/nonclient.rs"]
mod owner;
