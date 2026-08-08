// Unicast receive-buffer admission for AF_NETLINK.
//
// A unicast is not enqueued unconditionally: the destination's receive budget
// admits it only when the queue was empty — the first message always fits, so
// a single over-sized message can never deadlock — or when the result still
// fits the budget, and only while the destination is not congested. A refused
// message fails a non-blocking send and otherwise blocks the SENDER, bounded
// by the sender's own send timeout.
//
// Ungated: the verdict must run under hosted `cargo test` (`docs/53`).

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use net::sock_opts::SenderCreds;

use crate::netlink_socket::NetlinkSocket;

/// The outcome of one unicast attempt. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Unicast {
    /// No socket owns the destination port.
    NoPort,
    /// The destination's filter or connected-peer rule dropped it. The send
    /// still reports success, as a filtered message does.
    Dropped,
    /// Admitted and queued.
    Queued,
    /// The budget refused it and the sender may not block, or its send timeout
    /// expired first.
    Again,
    /// A signal reached the blocked sender.
    Interrupted,
}

/// `netlink_attachskb`: whether one message of `len` bytes may be attached to
/// a destination that already holds `queued` bytes under a `rcvbuf` budget.
/// # C: O(1)
pub fn attach_verdict(queued: usize, len: usize, rcvbuf: usize, congested: bool) -> bool {
    if congested { return false; }
    queued == 0 || queued.saturating_add(len) <= rcvbuf
}

impl NetlinkSocket {
    /// `netlink_attachskb` + `netlink_sendskb`: admit one unicast against the
    /// destination's receive budget and queue it, or report that the budget
    /// refused it. The filter runs first, exactly as it does before the
    /// budget in the reference, so a filtered message is never charged to it.
    /// # C: O(msg len)
    pub(crate) fn try_enqueue_from_creds(&self, mut msg: Vec<u8>, src_port: u32,
        creds: SenderCreds) -> crate::admission::Unicast
    {
        let verdict = self.bpf_filter.verdict(&msg);
        if verdict == 0 { return crate::admission::Unicast::Dropped; }
        msg.truncate(msg.len().min(verdict as usize));
        #[cfg(target_os = "oxide-kernel")]
        let security = {
            let sender = sched::live::current().map(|task| alloc::sync::Arc::clone(&task.pid));
            security::network::message_security(sender.as_deref())
        };
        #[cfg(not(target_os = "oxide-kernel"))]
        let security = security::network::message_security(None);
        let mut queue = self.rx_queue.lock();
        if !crate::admission::attach_verdict(queue.bytes, msg.len(), self.base.rcvbuf_bytes(),
            self.rx_congested.load(Ordering::Acquire))
        {
            return crate::admission::Unicast::Again;
        }
        queue.push(msg, src_port, 0, None, creds, security);
        drop(queue);
        #[cfg(target_os = "oxide-kernel")]
        self.waiters.wake_all();
        self.poll_subs.notify();
        crate::admission::Unicast::Queued
    }

    /// `netlink_rcv_wake`: a drained queue releases every sender blocked on
    /// this socket's receive budget. # C: O(waiters)
    pub(crate) fn wake_space_waiters(&self) {
        #[cfg(target_os = "oxide-kernel")]
        self.space_waiters.wake_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An empty destination always takes the message, however large — the
    /// first message is admitted on the "queue was empty" arm, not on the
    /// budget arm, so an over-sized message cannot wedge the port forever.
    #[test]
    fn an_empty_destination_takes_any_single_message() {
        assert!(attach_verdict(0, 1 << 20, 4096, false));
        assert!(attach_verdict(0, 1, 0, false));
    }

    /// With something already queued the budget decides, and the boundary is
    /// inclusive.
    #[test]
    fn a_non_empty_destination_is_judged_against_the_budget() {
        assert!(attach_verdict(100, 28, 128, false));
        assert!(!attach_verdict(100, 29, 128, false));
        assert!(!attach_verdict(4096, 1, 4096, false));
    }

    /// A congested destination refuses even a message that would fit, and even
    /// an empty queue.
    #[test]
    fn congestion_outranks_the_budget() {
        assert!(!attach_verdict(0, 1, 1 << 20, true));
        assert!(!attach_verdict(10, 1, 1 << 20, true));
    }
}
