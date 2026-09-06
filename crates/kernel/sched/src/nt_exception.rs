//! Scheduler-owned exception state for the native Windows personality.
//!
//! Wine's x86-64 signal path keeps the exception record and CONTEXT alive
//! across the user dispatcher.  The scheduler owns the equivalent lifetime
//! here so a later return-to-user pass cannot observe pointers into a syscall
//! stack or a caller-owned temporary buffer.
//!
//! Module manifest:
//!   `fault`   — hardware trap -> EXCEPTION_RECORD decode, both arches.
//!   `context` — register image -> the dispatcher frame's CONTEXT.

use alloc::boxed::Box;
use sync::{Spinlock, TaskList as TaskListClass};

#[path = "nt_exception/fault.rs"]
pub mod fault;
#[path = "nt_exception/context.rs"]
pub mod context;

pub const EXCEPTION_RECORD_BYTES: usize = 0x98;
pub const CONTEXT_BYTES: usize = 0x4d0;
const EXCEPTION_CODE_OFFSET: usize = 0;
const EXCEPTION_FLAGS_OFFSET: usize = 4;
const EXCEPTION_RECORD_OFFSET: usize = 8;
const EXCEPTION_ADDRESS_OFFSET: usize = 16;
const EXCEPTION_NUMBER_PARAMETERS_OFFSET: usize = 24;
const EXCEPTION_MAXIMUM_PARAMETERS: u32 = 15;
const EXCEPTION_FLAGS_MASK: u32 = 0x7f;
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

/// One exception awaiting the user dispatcher.
///
/// `context` is absent for a HARDWARE trap: the interrupted registers live in
/// the trap frame, and that frame's per-CPU pointer is not safe to dereference
/// once the fault resolver may have switched tasks. The return-to-user pass
/// that performs the delivery owns the live frame, so it — and only it —
/// builds the record. A software raise supplies its own context, because the
/// caller passed one in and the syscall frame is not the state to report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pending {
    pub record: [u8; EXCEPTION_RECORD_BYTES],
    pub context: Option<[u8; CONTEXT_BYTES]>,
    pub first_chance: bool,
}

impl Pending {
    /// A hardware trap whose context the delivery pass will capture. # C: O(1)
    pub fn from_hardware(record: [u8; EXCEPTION_RECORD_BYTES]) -> Self {
        Self { record, context: None, first_chance: true }
    }

    /// Validate the complete x86-64 exception handoff before ownership enters
    /// scheduler state. # C: O(1)
    pub fn is_valid(&self) -> bool {
        if !exception_record_header_valid(&self.record) { return false; }
        let code = u32::from_le_bytes(self.record[EXCEPTION_CODE_OFFSET..EXCEPTION_CODE_OFFSET + 4].try_into().unwrap());
        if code == 0 { return false; }
        let Some(context) = self.context.as_ref() else { return true; };
        #[cfg(target_arch = "x86_64")]
        {
            let flags = u32::from_le_bytes(context[CONTEXT_FLAGS_OFFSET..CONTEXT_FLAGS_OFFSET + 4].try_into().unwrap());
            let rip = u64::from_le_bytes(context[CONTEXT_RIP_OFFSET..CONTEXT_RIP_OFFSET + 8].try_into().unwrap());
            let rsp = u64::from_le_bytes(context[CONTEXT_RSP_OFFSET..CONTEXT_RSP_OFFSET + 8].try_into().unwrap());
            let rflags = u64::from(u32::from_le_bytes(context[0x44..0x48].try_into().unwrap()));
            return flags & CONTEXT_AMD64 == CONTEXT_AMD64
                && hal::UserVirtAddr::new(rip).is_some() && hal::UserVirtAddr::new(rsp).is_some()
                && rflags & EFLAGS_RESERVED_BIT != 0 && rflags & EFLAGS_IOPL_MASK == 0;
        }
        #[cfg(not(target_arch = "x86_64"))]
        { let _ = context; false }
    }
}

/// Validate the fixed portion of a Windows exception record before it is
/// retained by the NT scheduler. Pointer ownership is checked by the caller;
/// this function deliberately does not inspect opaque exception parameters.
/// # C: O(1)
pub fn exception_record_header_valid(record: &[u8; EXCEPTION_RECORD_BYTES]) -> bool {
    let flags = u32::from_le_bytes(record[EXCEPTION_FLAGS_OFFSET..EXCEPTION_FLAGS_OFFSET + 4].try_into().unwrap());
    let count = u32::from_le_bytes(record[EXCEPTION_NUMBER_PARAMETERS_OFFSET..EXCEPTION_NUMBER_PARAMETERS_OFFSET + 4].try_into().unwrap());
    flags & !EXCEPTION_FLAGS_MASK == 0 && count <= EXCEPTION_MAXIMUM_PARAMETERS
}

/// Validate the optional nested-record link without dereferencing it. The
/// address predicate is the address-space owner’s user-range decision, so NT
/// validation cannot create a second memory policy.
/// # C: O(1)
pub fn exception_record_link_valid<F: Fn(u64) -> bool>(record: &[u8; EXCEPTION_RECORD_BYTES], is_user: F) -> bool {
    if !exception_record_header_valid(record) { return false; }
    let nested = u64::from_le_bytes(record[EXCEPTION_RECORD_OFFSET..EXCEPTION_RECORD_OFFSET + 8].try_into().unwrap());
    let address = u64::from_le_bytes(record[EXCEPTION_ADDRESS_OFFSET..EXCEPTION_ADDRESS_OFFSET + 8].try_into().unwrap());
    (nested == 0 || is_user(nested)) && (address == 0 || is_user(address))
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

/// What a raised exception does next.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Disposition {
    /// Enter the user exception dispatcher so handlers get their chance.
    Dispatch,
    /// No handler took it: end the process, reporting the exception code.
    Terminate(i32),
}

/// Decide what one raise does, from the chance it is being given.
///
/// A first chance enters the dispatcher. A SECOND chance means the dispatcher
/// already ran every vectored and frame handler and none accepted, so raising
/// it again would re-enter the same dispatcher forever; the process ends
/// instead, reporting the exception code as its status — which is what a
/// Windows process does with an unhandled exception.
/// # C: O(1)
pub fn raise_disposition(record: &[u8; EXCEPTION_RECORD_BYTES], first_chance: bool) -> Disposition {
    if first_chance { return Disposition::Dispatch; }
    let code = u32::from_le_bytes(record[EXCEPTION_CODE_OFFSET..EXCEPTION_CODE_OFFSET + 4].try_into().unwrap());
    Disposition::Terminate(code as i32)
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
        Pending { record, context: Some(context), first_chance }
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
    fn a_hardware_trap_publishes_without_a_context_and_keeps_the_slot() {
        let state = State::new();
        let mut record = [0u8; EXCEPTION_RECORD_BYTES];
        record[EXCEPTION_CODE_OFFSET..EXCEPTION_CODE_OFFSET + 4]
            .copy_from_slice(&fault::STATUS_ACCESS_VIOLATION.to_le_bytes());
        let pending = Pending::from_hardware(record);
        assert!(pending.context.is_none());
        assert!(pending.first_chance);
        assert!(pending.is_valid());
        assert!(state.publish(pending).is_ok());
        // The delivery pass, not the fault, is what may capture the context.
        assert_eq!(state.begin_delivery().map(|p| p.context), Some(None));
    }

    #[test]
    fn a_record_with_no_exception_code_is_never_published() {
        let state = State::new();
        let pending = Pending::from_hardware([0u8; EXCEPTION_RECORD_BYTES]);
        assert!(!pending.is_valid());
        assert!(state.publish(pending).is_err());
        assert!(!state.is_pending());
    }

    #[test]
    fn malformed_context_is_rejected_before_publication() {
        let state = State::new();
        let mut pending = sample(true);
        pending.context.as_mut().unwrap()[CONTEXT_FLAGS_OFFSET..CONTEXT_FLAGS_OFFSET + 4].fill(0);
        assert_eq!(state.publish(pending), Err(pending));
        assert!(!state.is_pending());
    }

    #[test]
    fn exception_record_bounds_parameters_and_nested_user_links() {
        let mut record = [0u8; EXCEPTION_RECORD_BYTES];
        record[EXCEPTION_NUMBER_PARAMETERS_OFFSET..EXCEPTION_NUMBER_PARAMETERS_OFFSET + 4].copy_from_slice(&3u32.to_le_bytes());
        record[EXCEPTION_RECORD_OFFSET..EXCEPTION_RECORD_OFFSET + 8].copy_from_slice(&0x7000u64.to_le_bytes());
        record[EXCEPTION_ADDRESS_OFFSET..EXCEPTION_ADDRESS_OFFSET + 8].copy_from_slice(&0x401000u64.to_le_bytes());
        assert!(exception_record_link_valid(&record, |address| address >= 0x4000));
        record[EXCEPTION_NUMBER_PARAMETERS_OFFSET..EXCEPTION_NUMBER_PARAMETERS_OFFSET + 4].copy_from_slice(&16u32.to_le_bytes());
        assert!(!exception_record_link_valid(&record, |address| address >= 0x4000));
    }

    #[test]
    fn exception_record_rejects_unknown_flags_and_kernel_links() {
        let mut record = [0u8; EXCEPTION_RECORD_BYTES];
        record[EXCEPTION_FLAGS_OFFSET..EXCEPTION_FLAGS_OFFSET + 4].copy_from_slice(&0x80u32.to_le_bytes());
        assert!(!exception_record_link_valid(&record, |_| true));
        record[EXCEPTION_FLAGS_OFFSET..EXCEPTION_FLAGS_OFFSET + 4].fill(0);
        record[EXCEPTION_RECORD_OFFSET..EXCEPTION_RECORD_OFFSET + 8].copy_from_slice(&0xffff_8000_0000_0000u64.to_le_bytes());
        assert!(!exception_record_link_valid(&record, |address| address < 0x0000_8000_0000_0000));
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
    fn a_first_chance_raise_dispatches_and_a_second_chance_ends_the_process() {
        let mut record = [0u8; EXCEPTION_RECORD_BYTES];
        record[EXCEPTION_CODE_OFFSET..EXCEPTION_CODE_OFFSET + 4]
            .copy_from_slice(&fault::STATUS_ACCESS_VIOLATION.to_le_bytes());
        assert_eq!(raise_disposition(&record, true), Disposition::Dispatch);
        // Re-dispatching a second-chance raise would re-enter the dispatcher
        // that has already refused it, forever.
        assert_eq!(raise_disposition(&record, false),
                   Disposition::Terminate(fault::STATUS_ACCESS_VIOLATION as i32));
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
