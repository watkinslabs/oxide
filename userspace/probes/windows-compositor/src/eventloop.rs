//! Blocking wait over the bridge's two descriptors.
//!
//! The bridge has exactly two sources of work: the X connection and the
//! kernel transport. The shape a two-descriptor client uses is to drain
//! everything already available, push its own output, and then block in
//! `poll(2)` on both descriptors until one of them has more. Asking each
//! source in turn and sleeping when neither answered costs a wake per
//! millisecond forever and delays a record that arrives just after the ask
//! by the whole sleep.
//!
//! Draining to empty before the wait is not an optimisation: both sources
//! buffer decoded work that its descriptor no longer signals, so a wait
//! entered with work in hand would wait for the next arrival to release the
//! work already held.

use std::io;
use std::os::fd::RawFd;

/// `poll(2)` timeout meaning "no deadline".
pub const WAIT_FOREVER: i32 = -1;

/// A loop iteration's sources of work and the descriptors that feed them.
pub trait EventSource {
    type Error;
    /// Handles at most one item that is ready; `false` when nothing was.
    fn step(&mut self) -> Result<bool, Self::Error>;
    /// Descriptors whose readability makes `step` productive again.
    fn wait_fds(&self) -> [RawFd; 2];
    /// Last call before the wait: flush output, and refuse to block when a
    /// source can no longer produce anything.
    fn before_wait(&mut self) -> Result<(), Self::Error>;
}

/// Waits until one of `fds` is readable, reporting how many are.
///
/// A signal delivered during the wait is not an event: `poll` reports
/// `EINTR` and the caller has learnt nothing, so the wait is resumed rather
/// than turned into a spurious drain pass.
///
/// # C: O(1), blocks up to `timeout_ms`
pub fn wait_readable(fds: &[RawFd], timeout_ms: i32) -> io::Result<usize> {
    let mut set: Vec<libc::pollfd> = fds.iter().map(|&fd| libc::pollfd { fd, events: libc::POLLIN, revents: 0 }).collect();
    loop {
        let count = unsafe { libc::poll(set.as_mut_ptr(), set.len() as libc::nfds_t, timeout_ms) };
        if count >= 0 { return Ok(count as usize); }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted { return Err(error); }
    }
}

/// Drains every ready item, then blocks until there is another.
///
/// Returns only when a source fails, which for this bridge means the display
/// or the kernel transport is gone.
///
/// # C: one `poll(2)` per idle period, none per item
pub fn run<S: EventSource>(source: &mut S, on_wait_error: impl Fn(io::Error) -> S::Error) -> S::Error {
    loop {
        loop { match source.step() { Ok(true) => {}, Ok(false) => break, Err(error) => return error } }
        if let Err(error) = source.before_wait() { return error; }
        let fds = source.wait_fds();
        if let Err(error) = wait_readable(&fds, WAIT_FOREVER) { return on_wait_error(error); }
    }
}

#[cfg(test)]
#[path = "tests/eventloop.rs"]
mod tests;
