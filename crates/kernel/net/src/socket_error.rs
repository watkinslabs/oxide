use alloc::collections::VecDeque;
use alloc::vec::Vec;
use sync::{Socket as SocketLockClass, Spinlock};

use crate::addr::IpAddr;

pub const SO_EE_ORIGIN_ICMP: u8 = 2;
pub const SO_EE_ORIGIN_ICMP6: u8 = 3;

/// One Linux extended-error queue record for `MSG_ERRQUEUE`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocketErrorEntry {
    pub errno: i32,
    pub origin: u8,
    pub kind: u8,
    pub code: u8,
    pub info: u32,
    pub data: u32,
    pub offender: IpAddr,
    pub destination: IpAddr,
    pub destination_port: u16,
    pub ifindex: u32,
    pub payload: Vec<u8>,
}

/// Canonical Linux-style `sk_err`, shared by socket and transport owner.
pub struct SocketError {
    state: Spinlock<SocketErrorState, SocketLockClass>,
}

struct SocketErrorState {
    errno: i32,
    errno_from_queue: bool,
    recverr4: bool,
    recverr6: bool,
    recverr_rfc4884_4: bool,
    queue: VecDeque<SocketErrorEntry>,
}

impl SocketError {
    /// Empty socket error state. # C: O(1)
    pub const fn new() -> Self {
        Self {
            state: Spinlock::new(SocketErrorState {
                errno: 0, errno_from_queue: false,
                recverr4: false, recverr6: false, recverr_rfc4884_4: false, queue: VecDeque::new(),
            }),
        }
    }

    /// Publish the latest positive Linux errno. # C: O(1)
    pub fn set(&self, errno: i32) -> bool {
        if errno <= 0 { return false; }
        let mut state = self.state.lock();
        state.errno = errno;
        state.errno_from_queue = false;
        true
    }

    /// Read and clear the pending errno. # C: O(1)
    pub fn take(&self) -> i32 {
        let mut state = self.state.lock();
        let errno = state.errno;
        state.errno = 0;
        state.errno_from_queue = false;
        errno
    }

    /// Observe pending error state without consuming it. # C: O(1)
    pub fn has(&self) -> bool { self.state.lock().errno != 0 }

    /// Enable or disable Linux IPv4 extended-error delivery. # C: O(1)
    pub fn set_recverr4(&self, enabled: bool) {
        let mut state = self.state.lock();
        state.recverr4 = enabled;
        if !enabled {
            state.queue.retain(|entry| entry.origin != SO_EE_ORIGIN_ICMP);
            if state.errno_from_queue || state.errno == 0 {
                state.errno = state.queue.front().map(|entry| entry.errno).unwrap_or(0);
                state.errno_from_queue = state.errno != 0;
            }
        }
    }

    /// Enable or disable Linux IPv6 extended-error delivery. # C: O(1)
    pub fn set_recverr6(&self, enabled: bool) {
        let mut state = self.state.lock();
        state.recverr6 = enabled;
        if !enabled {
            state.queue.retain(|entry| entry.origin != SO_EE_ORIGIN_ICMP6);
            if state.errno_from_queue || state.errno == 0 {
                state.errno = state.queue.front().map(|entry| entry.errno).unwrap_or(0);
                state.errno_from_queue = state.errno != 0;
            }
        }
    }

    /// Read Linux IPv4 extended-error delivery state. # C: O(1)
    pub fn recverr4(&self) -> bool { self.state.lock().recverr4 }

    /// Read Linux IPv6 extended-error delivery state. # C: O(1)
    pub fn recverr6(&self) -> bool { self.state.lock().recverr6 }

    /// Enable RFC4884 metadata on queued IPv4 ICMP errors. # C: O(1)
    pub fn set_recverr_rfc4884_4(&self, enabled: bool) {
        self.state.lock().recverr_rfc4884_4 = enabled;
    }

    /// Publish one ICMP error according to connected/RECVERR UDP rules. # C: O(1) amortized
    pub fn publish(&self, mut entry: SocketErrorEntry, connected: bool, hard: bool) -> bool {
        let mut state = self.state.lock();
        let recverr = if entry.origin == SO_EE_ORIGIN_ICMP6 { state.recverr6 } else { state.recverr4 };
        if !recverr && (!connected || !hard) { return false; }
        if entry.origin == SO_EE_ORIGIN_ICMP && !state.recverr_rfc4884_4 { entry.data = 0; }
        if recverr { state.queue.push_back(entry.clone()); }
        state.errno = entry.errno;
        state.errno_from_queue = recverr;
        true
    }

    /// Pop the oldest extended error, preserving FIFO publication order. # C: O(1)
    pub fn take_extended(&self) -> Option<SocketErrorEntry> {
        let mut state = self.state.lock();
        let entry = state.queue.pop_front()?;
        if state.errno_from_queue || state.errno == 0 {
            state.errno = state.queue.front().map(|queued| queued.errno).unwrap_or(0);
            state.errno_from_queue = state.errno != 0;
        }
        Some(entry)
    }

    /// Observe queued extended-error state without consuming it. # C: O(1)
    pub fn has_extended(&self) -> bool { !self.state.lock().queue.is_empty() }
}

impl Default for SocketError { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::{SocketError, SocketErrorEntry};
    use syscall::errno::Errno;

    fn entry(errno: Errno, origin: u8) -> SocketErrorEntry {
        use crate::{IpAddr, Ipv4Addr};
        SocketErrorEntry {
            errno: errno as i32, origin, kind: 3, code: 1, info: 0, data: 0,
            offender: IpAddr::V4(Ipv4Addr::LOOPBACK),
            destination: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            destination_port: 53, ifindex: 1, payload: alloc::vec![1, 2],
        }
    }

    #[test]
    fn latest_positive_error_is_canonical() {
        let error = SocketError::new();
        assert!(!error.set(0));
        assert!(!error.set(-1));
        assert!(error.set(Errno::Econnrefused as i32));
        assert!(error.set(Errno::Econnreset as i32));
        assert_eq!(error.take(), Errno::Econnreset as i32);
        assert_eq!(error.take(), 0);
    }

    #[test]
    fn unconnected_icmp_requires_recverr_and_queues_fifo() {
        let error = SocketError::new();
        let entry = entry(Errno::Ehostunreach, super::SO_EE_ORIGIN_ICMP);
        assert!(!error.publish(entry.clone(), false, true));
        assert!(!error.has());
        error.set_recverr4(true);
        assert!(error.publish(entry.clone(), false, true));
        assert_eq!(error.take_extended(), Some(entry));
    }

    #[test]
    fn disabling_recverr_purges_only_that_family_and_republishes_next() {
        let error = SocketError::new();
        error.set_recverr4(true);
        error.set_recverr6(true);
        error.publish(entry(Errno::Ehostunreach, super::SO_EE_ORIGIN_ICMP), false, true);
        let v6 = entry(Errno::Econnrefused, super::SO_EE_ORIGIN_ICMP6);
        error.publish(v6.clone(), false, true);
        error.set_recverr4(false);
        assert_eq!(error.take(), Errno::Econnrefused as i32);
        assert_eq!(error.take_extended(), Some(v6));
        assert!(!error.has_extended());
    }

    #[test]
    fn dequeue_republishes_fifo_after_so_error_was_consumed() {
        let error = SocketError::new();
        error.set_recverr4(true);
        let first = entry(Errno::Ehostunreach, super::SO_EE_ORIGIN_ICMP);
        let second = entry(Errno::Econnrefused, super::SO_EE_ORIGIN_ICMP);
        error.publish(first.clone(), false, true);
        error.publish(second.clone(), false, true);
        assert_eq!(error.take(), Errno::Econnrefused as i32);
        assert_eq!(error.take_extended(), Some(first));
        assert_eq!(error.take(), Errno::Econnrefused as i32);
        assert_eq!(error.take_extended(), Some(second));
    }

    #[test]
    fn dequeue_does_not_overwrite_newer_transport_error() {
        let error = SocketError::new();
        error.set_recverr4(true);
        let queued = entry(Errno::Ehostunreach, super::SO_EE_ORIGIN_ICMP);
        error.publish(queued.clone(), false, true);
        error.set(Errno::Econnreset as i32);
        assert_eq!(error.take_extended(), Some(queued));
        assert_eq!(error.take(), Errno::Econnreset as i32);
    }
}
