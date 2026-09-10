//! Execute the production Get/Peek dispatcher with hosted task, wait and publication seams.
// Scenario scaffolding beyond Disconnected/Full/Presented/GuiBeforeAck has no
// driving #[test] yet (KI-0672); allowed rather than deleted.
#![allow(dead_code, unused_imports)]
extern crate alloc;
#[path="../src/nt_gdi/frame.rs"]
mod nt_gdi_frame;
#[path="../src/nt_gdi/frame_trace_off.rs"]
mod nt_gdi_frame_trace;
#[path="../src/nt_gdi/output.rs"]
mod output;
#[path="../src/nt_window_policy.rs"]
mod nt_window_policy;
#[path="../src/nt_window/rect_query/policy.rs"]
mod rect_query;
#[path="nt_window_output_dispatch/hit_test.rs"]
mod hit_test_fixture;
#[path="nt_window_output_dispatch/position.rs"]
pub(crate) mod position_fixture;
#[path="nt_window_output_dispatch/presentation.rs"]
mod presentation_fixture;
#[path="nt_window_output_dispatch/protocol.rs"]
mod protocol_fixture;
#[path="nt_window_output_dispatch/erase.rs"]
mod erase_fixture;
#[path="nt_window_output_dispatch/paint_reserve.rs"]
mod paint_reserve_fixture;
#[path="nt_window_output_dispatch/hardware_view.rs"]
mod hardware_view_fixture;
#[path="nt_window_output_dispatch/teardown.rs"]
mod teardown_fixture;
#[path="nt_window_output_dispatch/mouse_activate.rs"]
mod mouse_activate_fixture;
#[path="../src/nt_wine_window/cursor_raw.rs"] mod cursor_policy;
#[path="nt_window_output_dispatch/set_cursor.rs"] mod set_cursor_fixture;
mod nt_wine_window { pub(crate) mod cursor_raw {
    pub(crate) use crate::cursor_policy::{set_cursor_step,SetCursorStep};
    pub(crate) use crate::set_cursor_fixture::apply_default_step;
}}
include!("nt_window_output_dispatch/fixture.rs");
