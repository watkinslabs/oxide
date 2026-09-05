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
#[cfg(target_arch = "x86_64")]
const CONTEXT_FLAGS_OFFSET: usize = 0x30;
#[cfg(target_arch = "x86_64")]
const CONTEXT_AMD64: u32 = 0x0010_0000;
const CONTEXT_RIP_OFFSET: usize = 0xf8;
#[cfg(target_arch = "x86_64")]
const CONTEXT_RSP_OFFSET: usize = 0x98;
#[cfg(target_arch = "x86_64")]
const EFLAGS_RESERVED_BIT: u64 = 0x2;
#[cfg(target_arch = "x86_64")]
const EFLAGS_IOPL_MASK: u64 = 0x3000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pending {
    pub record: [u8; EXCEPTION_RECORD_BYTES],
    pub context: [u8; CONTEXT_BYTES],
    pub first_chance: bool,
}

impl Pending {
    /// Validate the complete x86-64 exception handoff before ownership enters
    /// scheduler state. # C: O(1)
    pub fn is_valid(&self) -> bool {
        #[cfg(target_arch = "x86_64")]
        {
            let code = u32::from_le_bytes(self.record[EXCEPTION_CODE_OFFSET..EXCEPTION_CODE_OFFSET + 4].try_into().unwrap());
            let flags = u32::from_le_bytes(self.context[CONTEXT_FLAGS_OFFSET..CONTEXT_FLAGS_OFFSET + 4].try_into().unwrap());
            let rip = u64::from_le_bytes(self.context[CONTEXT_RIP_OFFSET..CONTEXT_RIP_OFFSET + 8].try_into().unwrap());
            let rsp = u64::from_le_bytes(self.context[CONTEXT_RSP_OFFSET..CONTEXT_RSP_OFFSET + 8].try_into().unwrap());
            let rflags = u64::from(u32::from_le_bytes(self.context[0x44..0x48].try_into().unwrap()));
            return code != 0 && flags & CONTEXT_AMD64 == CONTEXT_AMD64
                && hal::UserVirtAddr::new(rip).is_some() && hal::UserVirtAddr::new(rsp).is_some()
                && rflags & EFLAGS_RESERVED_BIT != 0 && rflags & EFLAGS_IOPL_MASK == 0;
        }
        #[cfg(not(target_arch = "x86_64"))]
        { false }
    }
}

enum Slot {
    Pending(Box<Pending>),
    Delivering(Box<Pending>),
}

/// One pending exception per thread. A second exception while dispatching is
/// not silently queued: the dispatcher must resolve or terminate the current
/// exception before another one can replace it.
pub struct State(Spinlock<Option<Slot>, TaskListClass>);

impl State {
    pub const fn new() -> Self { Self(Spinlock::new(None)) }

    pub fn publish(&self, pending: Pending) -> Result<(), Pending> {
        if !pending.is_valid() { return Err(pending); }
        let mut state = self.0.lock();
        if state.is_some() { return Err(pending); }
        *state = Some(Slot::Pending(Box::new(pending)));
        Ok(())
    }

    /// Inspect state without changing ownership; delivery must use
    /// `begin_delivery` to reserve the record against a second consumer.
    pub fn peek(&self) -> Option<Pending> {
        self.0.lock().as_ref().map(|slot| match slot {
            Slot::Pending(value) | Slot::Delivering(value) => **value,
        })
    }

    /// Atomically reserve the one pending record for the return-to-user
    /// dispatcher. Only one consumer can own the reservation.
    pub fn begin_delivery(&self) -> Option<Pending> {
        let mut state = self.0.lock();
        let slot = state.take()?;
        match slot {
            Slot::Pending(value) => {
                let pending = *value;
                *state = Some(Slot::Delivering(Box::new(pending)));
                Some(pending)
            }
            Slot::Delivering(value) => { *state = Some(Slot::Delivering(value)); None }
        }
    }

    /// Commit a successfully written user exception frame.
    pub fn complete_delivery(&self) -> bool {
        let mut state = self.0.lock();
        matches!(state.take(), Some(Slot::Delivering(_)))
    }

    /// Return a reserved record when a user-frame write or validation fails.
    pub fn abort_delivery(&self) -> bool {
        let mut state = self.0.lock();
        match state.take() {
            Some(Slot::Delivering(value)) => { *state = Some(Slot::Pending(value)); true }
            Some(other) => { *state = Some(other); false }
            None => false,
        }
    }

    /// Consume a pending record directly. A record reserved by the delivery
    /// path cannot be stolen by another consumer.
    pub fn take(&self) -> Option<Pending> {
        let mut state = self.0.lock();
        match state.take() {
            Some(Slot::Pending(value)) => Some(*value),
            Some(other) => { *state = Some(other); None }
            None => None,
        }
    }

    /// Flush all state during task teardown, including an in-flight delivery.
    pub fn clear(&self) -> bool { self.0.lock().take().is_some() }

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
        let mut record = [0; EXCEPTION_RECORD_BYTES];
        record[EXCEPTION_CODE_OFFSET..EXCEPTION_CODE_OFFSET + 4].copy_from_slice(&0xc000_0005u32.to_le_bytes());
        let mut context = [0; CONTEXT_BYTES];
        context[CONTEXT_FLAGS_OFFSET..CONTEXT_FLAGS_OFFSET + 4].copy_from_slice(&CONTEXT_AMD64.to_le_bytes());
        context[CONTEXT_RIP_OFFSET..CONTEXT_RIP_OFFSET + 8].copy_from_slice(&0x401000u64.to_le_bytes());
        context[CONTEXT_RSP_OFFSET..CONTEXT_RSP_OFFSET + 8].copy_from_slice(&0x7fff_0000u64.to_le_bytes());
        context[0x44..0x48].copy_from_slice(&2u32.to_le_bytes());
        Pending { record, context, first_chance }
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
    fn malformed_context_is_rejected_before_publication() {
        let state = State::new();
        let mut pending = sample(true);
        pending.context[CONTEXT_FLAGS_OFFSET..CONTEXT_FLAGS_OFFSET + 4].fill(0);
        assert_eq!(state.publish(pending), Err(pending));
        assert!(!state.is_pending());
    }

    #[test]
    fn delivery_reservation_has_single_consumer_and_can_be_cleared() {
        let state = State::new();
        let pending = sample(true);
        assert!(state.publish(pending).is_ok());
        assert_eq!(state.begin_delivery(), Some(pending));
        assert_eq!(state.begin_delivery(), None);
        assert!(state.clear());
        assert_eq!(state.take(), None);
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
