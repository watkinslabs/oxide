extern crate alloc;
use ipc::win32_gdi;
#[path="../../ipc/src/win32_gdi/pen/coverage.rs"]
mod coverage;
#[path="../src/nt_wine_window/pen_raw.rs"]
mod raw;
#[path="../src/nt_gdi/pen/shared.rs"]
mod shared;
#[path="nt_pen_coverage/joined.rs"]
mod joined;
