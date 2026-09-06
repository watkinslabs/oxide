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

    /// Discard a reserved record whose delivery could not be completed.
    ///
    /// Terminal by construction: the slot is left EMPTY, never re-armed. A
    /// re-armed slot is work the return-to-user loop can never retire — the
    /// loop re-runs the delivery arm, the same input refuses again, and the
    /// pass bound is reached on every kernel entry for the life of the
    /// thread (KI-0459). The caller ends the thread group instead.
    /// # C: O(1)
    pub fn fail_delivery(&self) -> bool {
        let mut state = self.0.lock();
        match state.take() {
            Some(Slot::Delivering(_)) => true,
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

/// Decide one attempt to enter the user exception dispatcher, from the memory
/// the frame builder resolved.
///
/// `frame_writable` reports that the user frame window carved out of the
/// interrupted stack lies inside a writable mapping; `dispatcher` is the
/// resolved `KiUserExceptionDispatcher` entry.
///
/// The FAULTING PC is deliberately not a parameter. An instruction fetch from
/// an unmapped or non-executable address is exactly the access violation being
/// reported (`ExceptionInformation[0]` = execute, `ExceptionAddress` = that
/// address), so validating it before reporting it would drop the one exception
/// the thread must see — the reference validates only the stack it builds the
/// frame on.
///
/// Anything the builder could NOT resolve is unrecoverable: the reference
/// aborts the thread rather than returning to the faulting instruction, so the
/// answer is `Terminate` and the pending record is retired, never re-armed.
/// # C: O(1)
pub fn delivery_outcome(record: &[u8; EXCEPTION_RECORD_BYTES], frame_writable: bool,
                        dispatcher: Option<u64>) -> Disposition {
    if frame_writable && dispatcher.is_some() { return Disposition::Dispatch; }
    raise_disposition(record, false)
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
#[path = "nt_exception/tests.rs"]
mod tests;
