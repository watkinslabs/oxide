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
const EXCEPTION_CODE_OFFSET: usize = 0;
const EXCEPTION_BREAKPOINT: u32 = 0x8000_0003;
const CONTEXT_RIP_OFFSET: usize = 0xf8;

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

/// Apply the x86-64 dispatcher correction to one scheduler-owned exception
/// context before it crosses into the user exception frame. # C: O(1)
pub fn prepare_dispatch_context(record: &[u8; EXCEPTION_RECORD_BYTES], context: &mut [u8; CONTEXT_BYTES]) -> bool {
    let code = u32::from_le_bytes(record[EXCEPTION_CODE_OFFSET..EXCEPTION_CODE_OFFSET + 4].try_into().unwrap());
    if code != EXCEPTION_BREAKPOINT { return true; }
    let rip = u64::from_le_bytes(context[CONTEXT_RIP_OFFSET..CONTEXT_RIP_OFFSET + 8].try_into().unwrap());
    let Some(rip) = rip.checked_sub(1) else { return false; };
    context[CONTEXT_RIP_OFFSET..CONTEXT_RIP_OFFSET + 8].copy_from_slice(&rip.to_le_bytes());
    true
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

    #[test]
    fn breakpoint_dispatch_resumes_at_the_instruction_before_trap() {
        let mut record = [0u8; EXCEPTION_RECORD_BYTES];
        record[EXCEPTION_CODE_OFFSET..EXCEPTION_CODE_OFFSET + 4].copy_from_slice(&EXCEPTION_BREAKPOINT.to_le_bytes());
        let mut context = [0u8; CONTEXT_BYTES];
        context[CONTEXT_RIP_OFFSET..CONTEXT_RIP_OFFSET + 8].copy_from_slice(&0x401001u64.to_le_bytes());
        assert!(prepare_dispatch_context(&record, &mut context));
        assert_eq!(u64::from_le_bytes(context[CONTEXT_RIP_OFFSET..CONTEXT_RIP_OFFSET + 8].try_into().unwrap()), 0x401000);
    }

    #[test]
    fn breakpoint_at_zero_is_rejected_without_mutating_context() {
        let mut record = [0u8; EXCEPTION_RECORD_BYTES];
        record[EXCEPTION_CODE_OFFSET..EXCEPTION_CODE_OFFSET + 4].copy_from_slice(&EXCEPTION_BREAKPOINT.to_le_bytes());
        let mut context = [0u8; CONTEXT_BYTES];
        assert!(!prepare_dispatch_context(&record, &mut context));
        assert_eq!(&context[CONTEXT_RIP_OFFSET..CONTEXT_RIP_OFFSET + 8], &[0; 8]);
    }
}
