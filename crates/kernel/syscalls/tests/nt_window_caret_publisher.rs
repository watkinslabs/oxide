//! Production caret state, live publication and wire snapshots; scheduler and transport are instrumented.
#![allow(dead_code)]
extern crate alloc;
extern crate self as sched;
#[path="../src/nt_window/tests/caret_publisher/environment.rs"]mod environment;
#[path="../src/nt_window/tests/caret_publisher/window.rs"]mod nt_window;
pub use environment::{live,thread_group};
mod nt_compositor {pub mod caret {pub(crate) use crate::environment::publish_current;}}
