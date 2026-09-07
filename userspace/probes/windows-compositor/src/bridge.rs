//! The bridge as one event source: the X connection and the kernel transport.

use std::os::fd::{AsRawFd, RawFd};

use crate::eventloop::{self, EventSource};
use crate::protocol::NativeTransport;
use crate::x11::{Backend, BackendError};

/// Pairs the two halves so one loop can wait on both of their descriptors.
pub struct Bridge<'a, T: NativeTransport + AsRawFd> { backend: &'a mut Backend, transport: &'a mut T }

impl<'a, T: NativeTransport + AsRawFd> Bridge<'a, T> {
    /// # C: O(1)
    pub fn new(backend: &'a mut Backend, transport: &'a mut T) -> Self { Self { backend, transport } }
}

impl<T: NativeTransport + AsRawFd> EventSource for Bridge<'_, T> {
    type Error = BackendError;
    fn step(&mut self) -> Result<bool, BackendError> { self.backend.run_once(self.transport) }
    fn wait_fds(&self) -> [RawFd; 2] { [self.backend.connection_fd(), self.transport.as_raw_fd()] }
    fn before_wait(&mut self) -> Result<(), BackendError> {
        // Requests still in the library's output buffer have not reached the
        // server, so the events they cause cannot be what wakes this wait.
        self.backend.flush();
        // A connection that has failed produces no further event, so waiting
        // on its descriptor would never return.
        if self.backend.connected() { Ok(()) } else { Err(BackendError::X11) }
    }
}

/// Runs the bridge until the display or the kernel transport is gone.
///
/// # C: one `poll(2)` per idle period
pub fn run<T: NativeTransport + AsRawFd>(backend: &mut Backend, transport: &mut T) -> BackendError {
    let mut bridge = Bridge::new(backend, transport);
    eventloop::run(&mut bridge, BackendError::Wait)
}

/// Description of a wait failure, for the caller's exit message.
///
/// # C: O(1)
pub fn describe(error: &BackendError) -> String {
    match error {
        BackendError::Wait(inner) => format!("wait on the display and transport descriptors failed: {inner}"),
        other => format!("{other:?}"),
    }
}

#[cfg(test)]
#[path = "tests/bridge_wait.rs"]
mod tests;
