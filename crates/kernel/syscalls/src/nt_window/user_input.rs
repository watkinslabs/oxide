//! Module manifest for the per-process input adapters.
//!
//! - `cursor`: cursor position, clip, show-count and the cursor/icon objects.
//! - `capture`: capture, hot keys and thread input attachment.
//! - `keyboard`: the active layout of one thread.
//! - `queue`: queue wake bits, thread-state classes and mouse tracking.
//! - `raw`: raw-input device registration.
//!
//! Every decision lives in the window manager; these modules only resolve the
//! calling process and thread.

#[path = "user_input/cursor.rs"]
mod cursor;
pub(crate) use cursor::*;
#[path = "user_input/capture.rs"]
mod capture;
pub(crate) use capture::*;
#[path = "user_input/keyboard.rs"]
mod keyboard;
pub(crate) use keyboard::*;
#[path = "user_input/queue.rs"]
mod queue;
pub(crate) use queue::*;
#[path = "user_input/raw.rs"]
mod raw;
pub(crate) use raw::*;
