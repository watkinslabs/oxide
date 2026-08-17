//! The background flusher, selected per target.
//!
//! `kernel.rs` — the `kflushd` thread, its wait list and the clock.
//! `hosted.rs` — the same surface with no thread behind it.

#[cfg(target_os = "oxide-kernel")]
#[path = "daemon/kernel.rs"]
mod imp;
#[cfg(not(target_os = "oxide-kernel"))]
#[path = "daemon/hosted.rs"]
mod imp;

pub use imp::{spawn_daemons, wake_flusher};
