//! Production hardware retrieval with hosted task and user-procedure boundaries.
#![allow(dead_code)]
extern crate alloc;
extern crate self as sched;
extern crate self as timekeeper;
include!("nt_window_hardware/fixture.rs");
#[path = "nt_window_hardware/tests.rs"]
mod tests;
