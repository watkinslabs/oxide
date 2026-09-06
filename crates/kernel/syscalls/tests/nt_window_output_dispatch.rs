//! Execute the production Get/Peek dispatcher with hosted task, wait and publication seams.
extern crate alloc;
#[path="../src/nt_gdi/frame.rs"]
mod nt_gdi_frame;
#[path="../src/nt_gdi/output.rs"]
mod output;
#[path="../src/nt_window_policy.rs"]
mod nt_window_policy;
#[path="nt_window_output_dispatch/presentation.rs"]
mod presentation_fixture;
#[path="nt_window_output_dispatch/protocol.rs"]
mod protocol_fixture;
#[path="nt_window_output_dispatch/erase.rs"]
mod erase_fixture;
#[path="nt_window_output_dispatch/paint_reserve.rs"]
mod paint_reserve_fixture;
include!("nt_window_output_dispatch/fixture.rs");
