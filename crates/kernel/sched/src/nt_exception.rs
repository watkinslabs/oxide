//! Scheduler-owned exception state for the native Windows personality.
//!
//! Wine's x86-64 signal path keeps the exception record and CONTEXT alive
//! across the user dispatcher.  The scheduler owns the equivalent lifetime
//! here so a later return-to-user pass cannot observe pointers into a syscall
//! stack or a caller-owned temporary buffer.

use alloc::boxed::Box;
use sync::{Spinlock, TaskList as TaskListClass};

pub const EXCEPTION_RECORD_BYTES: usize = 0x98;
pub const CONTEXT_BYTES: usize = 0x4d0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pending {
    pub record: [u8; EXCEPTION_RECORD_BYTES],
    pub context: [u8; CONTEXT_BYTES],
    pub first_chance: bool,
}

/// One pending exception per thread. A second exception while dispatching is
/// not silently queued: the dispatcher must resolve or terminate the current
/// exception before another one can replace it.
pub struct State(Spinlock<Option<Box<Pending>>, TaskListClass>);

impl State {
    pub const fn new() -> Self { Self(Spinlock::new(None)) }

    pub fn publish(&self, pending: Pending) -> Result<(), Pending> {
        let mut state = self.0.lock();
        if state.is_some() { return Err(pending); }
        *state = Some(Box::new(pending));
        Ok(())
    }

    pub fn take(&self) -> Option<Pending> { self.0.lock().take().map(|value| *value) }

    pub fn peek(&self) -> Option<Pending> { self.0.lock().as_deref().copied() }

    pub fn is_pending(&self) -> bool { self.0.lock().is_some() }
}

impl Default for State {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(first_chance: bool) -> Pending {
        Pending { record: [0x5a; EXCEPTION_RECORD_BYTES], context: [0xa5; CONTEXT_BYTES], first_chance }
    }

    #[test]
    fn state_retains_one_owned_exception_until_dispatch_consumes_it() {
        let state = State::new();
        let pending = sample(true);
        assert!(state.publish(pending).is_ok());
        assert!(state.is_pending());
        assert_eq!(state.publish(sample(false)), Err(sample(false)));
        assert_eq!(state.take(), Some(pending));
        assert!(!state.is_pending());
    }
}
