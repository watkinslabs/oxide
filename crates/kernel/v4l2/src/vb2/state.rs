//! Buffer states and the transitions the buffer queue admits.
//!
//! Getting this wrong is how a capture application deadlocks: a buffer stuck
//! in `Active` is never returned, and a buffer wrongly admitted to `Queued`
//! twice is delivered twice. The legality table is therefore data, checked by
//! one function, rather than a condition repeated at each call site.

use syscall::errno::Errno;

/// `enum vb2_buffer_state`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BufState {
    /// Owned by userspace. The state a buffer is allocated in and returns to.
    Dequeued,
    /// Bound to a media request, not yet queued to the device.
    InRequest,
    /// Mid-`buf_prepare`: visible so a concurrent command is refused.
    Preparing,
    /// Owned by the queue, waiting to be handed to the driver.
    Queued,
    /// Handed to the driver, which will complete it.
    Active,
    /// Completed successfully; on the done list, waiting to be dequeued.
    Done,
    /// Completed with an error; on the done list all the same, so the caller
    /// learns about the failure through `DQBUF` rather than losing the buffer.
    Error,
}

impl BufState {
    /// Is the buffer on the done list, i.e. dequeueable? # C: O(1)
    pub fn is_done(self) -> bool { matches!(self, BufState::Done | BufState::Error) }
    /// Does the buffer belong to the queue rather than to userspace? # C: O(1)
    pub fn is_in_flight(self) -> bool {
        matches!(self, BufState::Queued | BufState::Active | BufState::Preparing)
    }
    /// `V4L2_BUF_FLAG_*` bits this state contributes to a reported buffer.
    /// # C: O(1)
    pub fn user_flags(self) -> u32 {
        use crate::uapi::flags::*;
        match self {
            BufState::Queued | BufState::Active => BUF_FLAG_QUEUED,
            BufState::Done => BUF_FLAG_DONE,
            BufState::Error => BUF_FLAG_DONE | BUF_FLAG_ERROR,
            BufState::InRequest => BUF_FLAG_IN_REQUEST,
            _ => 0,
        }
    }
}

/// May `QBUF` accept a buffer in this state?
///
/// Only a buffer userspace owns may be queued. Everything else — already
/// queued, handed to the driver, sitting completed on the done list, or
/// mid-prepare — is `EINVAL`, and that refusal is what stops a program from
/// having the same frame delivered to it twice.
/// # C: O(1)
pub fn may_queue(state: BufState) -> Result<(), Errno> {
    match state {
        BufState::Dequeued | BufState::InRequest => Ok(()),
        _ => Err(Errno::Einval),
    }
}

/// May `PREPARE_BUF` accept a buffer in this state? Preparing a buffer the
/// queue owns is the same violation as queueing one. # C: O(1)
pub fn may_prepare(state: BufState) -> Result<(), Errno> {
    match state {
        BufState::Dequeued => Ok(()),
        _ => Err(Errno::Einval),
    }
}

/// May the driver complete a buffer in this state?
///
/// Completion is legal only from `Active`. A driver completing a buffer it was
/// never handed is a driver bug that would otherwise corrupt the done list, so
/// the queue forces such a buffer to `Error` instead of trusting the report.
/// # C: O(1)
pub fn completion_target(state: BufState, reported: BufState) -> BufState {
    if state != BufState::Active { return BufState::Error; }
    match reported {
        BufState::Done | BufState::Error | BufState::Queued => reported,
        _ => BufState::Error,
    }
}

/// State a buffer ends in when the queue is cancelled.
///
/// `STREAMOFF` returns every buffer to userspace whatever it was doing —
/// queued, in the driver, or already completed. A buffer left behind in any
/// other state is one the application can never recover.
/// # C: O(1)
pub fn cancelled_state(_state: BufState) -> BufState { BufState::Dequeued }
