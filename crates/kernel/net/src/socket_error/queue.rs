//! The socket-owned error queue and its relationship to the pending errno.
//!
//! One socket has exactly one queue, shared by the socket object and its
//! transport owner through an `Arc`. The pending errno (`SO_ERROR`) is not a
//! second state: only ICMP-origin records own it, and every dequeue
//! re-derives it from the record that becomes the new head.

use alloc::collections::VecDeque;
use sync::{Socket as SocketLockClass, Spinlock};

use super::entry::SocketErrorEntry;
use super::uapi::{is_icmp_origin, survives_recverr_purge, SO_EE_ORIGIN_ICMP, SO_EE_ORIGIN_ICMP6,
    SO_EE_ORIGIN_ZEROCOPY, SOCK_ERRQUEUE_RMEM_DEFAULT};
use crate::addr::IpAddr;

/// Canonical Linux-style `sk_err` plus `sk_error_queue`, shared by socket and
/// transport owner.
pub struct SocketError {
    state: Spinlock<SocketErrorState, SocketLockClass>,
}

struct SocketErrorState {
    errno: i32,
    /// The non-fatal error a connection was told about but did not die of.
    /// It never reaches a receive or a send — only the option read reports it,
    /// once, and only when no fatal error is pending.
    errno_soft: i32,
    recverr4: bool,
    recverr6: bool,
    recverr_rfc4884_4: bool,
    recverr_rfc4884_6: bool,
    rmem_limit: usize,
    rmem_used: usize,
    zerocopy_next_id: u32,
    queue: VecDeque<SocketErrorEntry>,
}

impl SocketErrorState {
    /// Append one record when the receive-memory budget allows it. # C: O(1)
    fn enqueue(&mut self, entry: SocketErrorEntry) -> bool {
        let charge = entry.charged_bytes();
        if self.rmem_used + charge > self.rmem_limit { return false; }
        self.rmem_used += charge;
        self.queue.push_back(entry);
        true
    }

    /// Pop the head and re-derive the pending errno from the new head, the way
    /// only ICMP-origin records may own it. # C: O(1)
    fn dequeue(&mut self) -> Option<SocketErrorEntry> {
        let entry = self.queue.pop_front()?;
        self.rmem_used = self.rmem_used.saturating_sub(entry.charged_bytes());
        let next_is_icmp = match self.queue.front() {
            Some(next) if is_icmp_origin(next.origin) => { self.errno = next.errno; true }
            _ => false,
        };
        if is_icmp_origin(entry.origin) && !next_is_icmp { self.errno = 0; }
        Some(entry)
    }
}

impl SocketError {
    /// Empty socket error state. # C: O(1)
    pub const fn new() -> Self {
        Self {
            state: Spinlock::new(SocketErrorState {
                errno: 0, errno_soft: 0, recverr4: false, recverr6: false,
                recverr_rfc4884_4: false, recverr_rfc4884_6: false,
                rmem_limit: SOCK_ERRQUEUE_RMEM_DEFAULT, rmem_used: 0, zerocopy_next_id: 0,
                queue: VecDeque::new(),
            }),
        }
    }

    /// Publish the latest positive Linux errno. # C: O(1)
    pub fn set(&self, errno: i32) -> bool {
        if errno <= 0 { return false; }
        self.state.lock().errno = errno;
        true
    }

    /// Read and clear the pending errno. # C: O(1)
    pub fn take(&self) -> i32 {
        let mut state = self.state.lock();
        let errno = state.errno;
        state.errno = 0;
        errno
    }

    /// Observe pending error state without consuming it. # C: O(1)
    pub fn has(&self) -> bool { self.state.lock().errno != 0 }

    /// Record a non-fatal error the connection survived. It replaces any
    /// earlier one and is never reported by a receive or a send. # C: O(1)
    pub fn set_soft(&self, errno: i32) -> bool {
        if errno <= 0 { return false; }
        self.state.lock().errno_soft = errno;
        true
    }

    /// Forget the non-fatal error: something on this connection worked, so the
    /// event it recorded no longer describes the connection. # C: O(1)
    pub fn clear_soft(&self) { self.state.lock().errno_soft = 0; }

    /// Observe the non-fatal error without consuming it, for the give-up path
    /// that reports it as the cause instead of a bare timeout. # C: O(1)
    pub fn soft(&self) -> i32 { self.state.lock().errno_soft }

    /// The socket-option read of the pending error: the fatal error first,
    /// read and cleared, and only when there is none the non-fatal one, also
    /// read and cleared, so each is reported exactly once. # C: O(1)
    pub fn take_reported(&self) -> i32 {
        let mut state = self.state.lock();
        let errno = state.errno;
        state.errno = 0;
        if errno != 0 { return errno; }
        let soft = state.errno_soft;
        state.errno_soft = 0;
        soft
    }

    /// Track the receive-memory budget the error queue may occupy. # C: O(1)
    pub fn set_rmem_limit(&self, bytes: usize) { self.state.lock().rmem_limit = bytes; }

    /// Enable or disable IPv4 extended-error delivery. Disabling drops every
    /// queued record except the transmit-completion origins, and leaves the
    /// pending errno alone. # C: O(queue)
    pub fn set_recverr4(&self, enabled: bool) {
        let mut state = self.state.lock();
        state.recverr4 = enabled;
        if !enabled { purge(&mut state); }
    }

    /// Enable or disable IPv6 extended-error delivery. # C: O(queue)
    pub fn set_recverr6(&self, enabled: bool) {
        let mut state = self.state.lock();
        state.recverr6 = enabled;
        if !enabled { purge(&mut state); }
    }

    /// Read IPv4 extended-error delivery state. # C: O(1)
    pub fn recverr4(&self) -> bool { self.state.lock().recverr4 }

    /// Read IPv6 extended-error delivery state. # C: O(1)
    pub fn recverr6(&self) -> bool { self.state.lock().recverr6 }

    /// Enable RFC4884 metadata on queued IPv4 ICMP errors. # C: O(1)
    pub fn set_recverr_rfc4884_4(&self, enabled: bool) {
        self.state.lock().recverr_rfc4884_4 = enabled;
    }

    /// Enable RFC4884 metadata on queued ICMPv6 errors. # C: O(1)
    pub fn set_recverr_rfc4884_6(&self, enabled: bool) {
        self.state.lock().recverr_rfc4884_6 = enabled;
    }

    /// Publish one ICMP error according to connected/RECVERR datagram rules.
    /// The record reaches the queue only under RECVERR; the pending errno is
    /// published whenever either RECVERR or a connected hard error applies.
    /// # C: O(1) amortized
    pub fn publish(&self, mut entry: SocketErrorEntry, connected: bool, hard: bool) -> bool {
        let mut state = self.state.lock();
        let recverr = if entry.origin == SO_EE_ORIGIN_ICMP6 { state.recverr6 } else { state.recverr4 };
        if !recverr && (!connected || !hard) { return false; }
        let rfc4884 = if entry.origin == SO_EE_ORIGIN_ICMP6 {
            state.recverr_rfc4884_6
        } else { state.recverr_rfc4884_4 };
        if !rfc4884 { entry.data = 0; }
        state.errno = entry.errno;
        if recverr { state.enqueue(entry); }
        true
    }

    /// Publish one locally detected transmit failure. Delivery is conditional
    /// on the destination family's RECVERR, and never touches the pending
    /// errno — the failing send already returns it. # C: O(1) amortized
    pub fn publish_local(&self, errno: i32, destination: IpAddr, port: u16, info: u32) -> bool {
        let mut state = self.state.lock();
        let recverr = match destination {
            IpAddr::V4(_) => state.recverr4,
            IpAddr::V6(_) => state.recverr6,
        };
        if !recverr { return false; }
        state.enqueue(SocketErrorEntry::local(errno, destination, port, info))
    }

    /// Publish one transmit timestamp. Timestamp records are independent of
    /// RECVERR and never become the pending errno. # C: O(1) amortized
    pub fn publish_timestamping(&self, tstype: u32, tskey: u32, v6: bool, ifindex: u32) -> bool {
        self.state.lock().enqueue(SocketErrorEntry::timestamping(tstype, tskey, v6, ifindex))
    }

    /// Publish one transmit-time scheduling failure. # C: O(1) amortized
    pub fn publish_txtime(&self, errno: i32, code: u8, txtime: u64, v6: bool) -> bool {
        self.state.lock().enqueue(SocketErrorEntry::txtime(errno, code, txtime, v6))
    }

    /// Claim the next zero-copy send identifier for this socket. # C: O(1)
    pub fn next_zerocopy_id(&self) -> u32 {
        let mut state = self.state.lock();
        let id = state.zerocopy_next_id;
        state.zerocopy_next_id = state.zerocopy_next_id.wrapping_add(1);
        id
    }

    /// Publish one zero-copy completion covering `lo..lo+len-1`, extending the
    /// queue tail in place when the identifiers are contiguous with it.
    /// # C: O(1) amortized
    pub fn publish_zerocopy(&self, lo: u32, len: u32, copied: bool, v6: bool) -> bool {
        if len == 0 { return false; }
        let mut state = self.state.lock();
        if let Some(tail) = state.queue.back_mut() {
            if tail.origin == SO_EE_ORIGIN_ZEROCOPY && tail.extend_zerocopy(lo, len) { return true; }
        }
        let hi = lo.wrapping_add(len - 1);
        state.enqueue(SocketErrorEntry::zerocopy(lo, hi, copied, v6))
    }

    /// Pop the oldest extended error, preserving FIFO publication order.
    /// # C: O(1)
    pub fn take_extended(&self) -> Option<SocketErrorEntry> { self.state.lock().dequeue() }

    /// Observe queued extended-error state without consuming it. # C: O(1)
    pub fn has_extended(&self) -> bool { !self.state.lock().queue.is_empty() }

    /// Observe the head record's origin without consuming it. # C: O(1)
    pub fn peek_extended_origin(&self) -> Option<u8> {
        self.state.lock().queue.front().map(|entry| entry.origin)
    }
}

/// Drop every queued record a RECVERR disable discards. # C: O(queue)
fn purge(state: &mut SocketErrorState) {
    let mut kept = VecDeque::new();
    let mut used = 0usize;
    while let Some(entry) = state.queue.pop_front() {
        if survives_recverr_purge(entry.origin) { used += entry.charged_bytes(); kept.push_back(entry); }
    }
    state.queue = kept;
    state.rmem_used = used;
}

impl Default for SocketError { fn default() -> Self { Self::new() } }

/// The ICMP origin a family selects. # C: O(1)
pub const fn icmp_origin(v6: bool) -> u8 {
    if v6 { SO_EE_ORIGIN_ICMP6 } else { SO_EE_ORIGIN_ICMP }
}
