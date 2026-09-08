//! Whether the window manager is allowed to manage a window.
//!
//! The decision itself belongs to the protocol both ends read: the backend
//! frames what the manager may frame, and the window owner draws and reserves
//! the parts of the frame the manager does not. Only the tests of that one
//! answer live here.

pub use syscall::nt_compositor::managed::{at_creation, Managed};

#[cfg(test)]
#[path = "tests/managed.rs"]
mod tests;
