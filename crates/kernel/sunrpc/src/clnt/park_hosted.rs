// Parking for a reply, hosted.
//
// There is no scheduler, so a call that is not already complete when `send`
// returns can never complete. The scripted transports the tests use answer
// synchronously inside `send`, which is what makes the whole engine — encode,
// register, match, decode, retry — testable with no VM and no network.
//
// The retransmission schedule is still consulted so a transport that declines
// to answer produces the same `Timeout` a real one would, rather than a
// `Disconnected` that hides which of the two happened.

extern crate alloc;
use alloc::sync::Arc;

use crate::err::{RpcError, RpcResult};
use crate::xprt::{PendingCall, RetryState, TimeoutOutcome};
use super::RpcClient;

const NS_PER_MS: u64 = 1_000_000;

impl RpcClient {
    pub(super) fn wake(&self) {}

    pub(super) fn wait(&self, pend: &Arc<PendingCall>, msg: &[u8]) -> RpcResult<()> {
        let to = self.timeout;
        let mut st = RetryState::start(&to, (self.now_ns)() / NS_PER_MS);
        loop {
            if pend.is_done() { return Ok(()); }
            if self.is_dead() { return Err(RpcError::Disconnected); }
            match st.adjust(&to, (self.now_ns)() / NS_PER_MS) {
                // With no scheduler the clock cannot advance on its own, so a
                // schedule that still says "wait" would spin forever. A test
                // clock that does advance reaches the deadlines instead.
                TimeoutOutcome::Wait => return Err(RpcError::Timeout),
                TimeoutOutcome::Retransmit if self.transport.retransmits() => {
                    self.transport.send(msg)?;
                }
                TimeoutOutcome::Retransmit => {}
                TimeoutOutcome::MajorTimeout => return Err(RpcError::Timeout),
            }
        }
    }
}
