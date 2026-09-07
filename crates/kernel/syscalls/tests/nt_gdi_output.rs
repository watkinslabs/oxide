// Compile-only fixture: no #[test] fn calls anything here, so dead-code
// would flag the whole included surface.
#![allow(dead_code, unused_imports)]
extern crate alloc;
#[path="../src/nt_gdi/frame.rs"]
mod nt_gdi_frame;
#[path="../src/nt_gdi/frame_trace_off.rs"]
mod nt_gdi_frame_trace;
#[path="../src/nt_gdi/output.rs"]
mod output;
