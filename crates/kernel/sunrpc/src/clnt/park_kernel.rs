// Parking for a reply, in the kernel.
//
// The wait is bounded by the retransmission schedule rather than open-ended.
// An unbounded wait on a datagram transport is a hang: nothing under the RPC
// layer will resend a lost call, so the client that does not wake to retransmit
// waits for a reply that was never going to come.

extern crate alloc;
use alloc::sync::Arc;

use crate::err::{RpcError, RpcResult};
use crate::xprt::{PendingCall, RetryState, TimeoutOutcome};
use super::RpcClient;

/// Milliseconds per nanosecond-denominated tick, for converting the schedule's
/// milliseconds into the absolute nanosecond deadline the scheduler takes.
const NS_PER_MS: u64 = 1_000_000;

impl RpcClient {
    /// Wake every parked caller. # C: O(N_waiters)
    pub(super) fn wake(&self) { self.reply_wait.wake_all(); }

    /// Park until the call completes, the transport dies, a signal arrives, or
    /// the schedule gives up. # C: O(N_wakeups)
    pub(super) fn wait(&self, pend: &Arc<PendingCall>, msg: &[u8]) -> RpcResult<()> {
        let to = self.timeout;
        let mut st = RetryState::start(&to, (self.now_ns)() / NS_PER_MS);
        loop {
            if pend.is_done() { return Ok(()); }
            if self.is_dead() { return Err(RpcError::Disconnected); }
            let deadline_ns = st.minortimeo.saturating_mul(NS_PER_MS);
            // SAFETY: process context; completion and disconnect are atomic
            // predicates that both wake `reply_wait`, and no lock a completer
            // takes is held across this sleep, so the wakeup can be neither
            // missed nor deadlocked against.
            let out = unsafe {
                sched::live::wait_event_interruptible_until(
                    &self.reply_wait, deadline_ns,
                    || (self.now_ns)(),
                    || pend.is_done() || self.is_dead())
            };
            match out {
                sched::WaitOutcome::Interrupted => return Err(RpcError::Interrupted),
                sched::WaitOutcome::Ready => continue,
                sched::WaitOutcome::TimedOut => {}
            }
            match st.adjust(&to, (self.now_ns)() / NS_PER_MS) {
                TimeoutOutcome::Wait => {}
                // A stream transport retransmits beneath us. Resending there
                // would put a second copy of a non-idempotent operation — a
                // rename, an exclusive create — on a connection that already
                // holds the first.
                TimeoutOutcome::Retransmit if self.transport.retransmits() => {
                    self.transport.send(msg)?;
                }
                TimeoutOutcome::Retransmit => {}
                TimeoutOutcome::MajorTimeout => return Err(RpcError::Timeout),
            }
        }
    }
}
