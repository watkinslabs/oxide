//! Production caret state, live publication and wire snapshots; scheduler and transport are instrumented.
#![allow(dead_code)]
extern crate alloc;
extern crate self as sched;
#[path="../src/nt_window/tests/caret_publisher/environment.rs"]mod environment;
mod nt_window {
    include!("../src/nt_window/tests/caret_publisher/window.rs");
    /// Hosted seam for the canonical caret-blink-interval setting `live.rs`
    /// reads via `super::super::settings`; no case here asserts on the
    /// interval value, so a fixed Win32-default seam is sufficient.
    pub(crate) mod settings {
        pub(crate) fn snapshot_caret_blink_time() -> u32 { ipc::win32_window::DEFAULT_CARET_BLINK_MS }
    }
}
pub use environment::{live,thread_group};
mod nt_compositor {pub mod caret {pub(crate) use crate::environment::publish_current;}}
