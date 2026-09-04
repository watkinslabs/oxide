//! Bounded asynchronous readiness contract for the Winsock socket boundary.

use alloc::vec::Vec;

use crate::WsaError;

/// Maximum number of sockets in one native asynchronous poll request.
pub const MAX_ASYNC_POLL_FDS: usize = 64;

/// Linux poll bits supplied by the native socket owner.
pub const NATIVE_POLLIN: u16 = 0x0001;
pub const NATIVE_POLLPRI: u16 = 0x0002;
pub const NATIVE_POLLOUT: u16 = 0x0004;
pub const NATIVE_POLLERR: u16 = 0x0008;
pub const NATIVE_POLLHUP: u16 = 0x0010;
pub const NATIVE_POLLNVAL: u16 = 0x0020;

/// Winsock `WSAPOLLFD.events` and `revents` values.
pub const WSA_POLLERR: u16 = 0x0001;
pub const WSA_POLLHUP: u16 = 0x0002;
pub const WSA_POLLNVAL: u16 = 0x0004;
pub const WSA_POLLWRNORM: u16 = 0x0010;
pub const WSA_POLLWRBAND: u16 = 0x0020;
pub const WSA_POLLRDNORM: u16 = 0x0100;
pub const WSA_POLLRDBAND: u16 = 0x0200;

/// Native terminal state retained beside the Linux-shaped poll mask.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeClose { Open, Eof, Reset }

/// One snapshot returned by the native socket owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeReadiness {
    pub socket: u64,
    pub events: u16,
    pub error: Option<i32>,
    pub close: NativeClose,
    pub valid: bool,
}

/// One caller-owned `WSAPOLLFD` request record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AsyncPollFd { pub socket: u64, pub events: u16 }

/// A bounded asynchronous readiness request. The native wait is performed by
/// the socket service; this value only owns the stable request snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AsyncPollRequest { fds: Vec<AsyncPollFd>, timeout_ms: i32 }

/// One projected `WSAPOLLFD` result and its operation error, if any.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AsyncPollResultFd {
    pub socket: u64,
    pub events: u16,
    pub revents: u16,
    pub error: Option<WsaError>,
}

/// Completed readiness projection. `ready_count` counts descriptors, not bits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AsyncPollResult { pub fds: Vec<AsyncPollResultFd>, pub ready_count: usize }

impl AsyncPollRequest {
    /// Copy a bounded request before the native wait can outlive caller storage. # C: O(N_fds)
    pub fn new(fds: &[AsyncPollFd], timeout_ms: i32) -> Result<Self, WsaError> {
        if fds.is_empty() || fds.len() > MAX_ASYNC_POLL_FDS { return Err(WsaError::InvalidArgument); }
        Ok(Self { fds: fds.to_vec(), timeout_ms })
    }

    /// Return the requested timeout; every negative value means infinite. # C: O(1)
    pub const fn timeout_ms(&self) -> i32 { self.timeout_ms }

    /// Return the stable request records handed to the native owner. # C: O(1)
    pub fn fds(&self) -> &[AsyncPollFd] { &self.fds }

    /// Project one native completion into Winsock `WSAPOLLFD` results. # C: O(N_fds * N_native)
    pub fn complete(&self, native: &[NativeReadiness]) -> Result<AsyncPollResult, WsaError> {
        let valid_count = self.fds.iter().filter(|fd| fd.socket != 0 && native.iter().any(|entry| entry.socket == fd.socket && entry.valid)).count();
        if valid_count == 0 { return Err(WsaError::NotSocket); }

        let mut fds = Vec::with_capacity(self.fds.len());
        for &request in &self.fds {
            let Some(snapshot) = native.iter().find(|entry| entry.socket == request.socket) else {
                fds.push(AsyncPollResultFd { socket: request.socket, events: request.events, revents: WSA_POLLNVAL, error: Some(WsaError::NotSocket) });
                continue;
            };
            if !snapshot.valid {
                fds.push(AsyncPollResultFd { socket: request.socket, events: request.events, revents: WSA_POLLNVAL, error: Some(WsaError::NotSocket) });
                continue;
            }
            let revents = project_revents(request.events, snapshot);
            let error = project_error(snapshot);
            fds.push(AsyncPollResultFd { socket: request.socket, events: request.events, revents, error });
        }
        let ready_count = fds.iter().filter(|fd| fd.revents != 0).count();
        Ok(AsyncPollResult { fds, ready_count })
    }
}

fn project_revents(requested: u16, snapshot: &NativeReadiness) -> u16 {
    let mut revents = 0;
    if snapshot.events & NATIVE_POLLIN != 0 { revents |= WSA_POLLRDNORM; }
    if snapshot.events & NATIVE_POLLPRI != 0 { revents |= WSA_POLLRDBAND; }
    if snapshot.events & NATIVE_POLLOUT != 0 { revents |= WSA_POLLWRNORM; }
    if snapshot.events & NATIVE_POLLERR != 0 || snapshot.close == NativeClose::Reset { revents |= WSA_POLLERR; }
    if snapshot.events & NATIVE_POLLHUP != 0 || snapshot.close != NativeClose::Open { revents |= WSA_POLLHUP; }
    if snapshot.events & NATIVE_POLLNVAL != 0 { revents |= WSA_POLLNVAL; }
    let regular = WSA_POLLRDNORM | WSA_POLLRDBAND | WSA_POLLWRNORM | WSA_POLLWRBAND;
    (revents & (requested | WSA_POLLERR | WSA_POLLHUP | WSA_POLLNVAL)) | (revents & !regular & (WSA_POLLERR | WSA_POLLHUP | WSA_POLLNVAL))
}

fn project_error(snapshot: &NativeReadiness) -> Option<WsaError> {
    snapshot.error.map(crate::wsa_error).or_else(|| (snapshot.close == NativeClose::Reset).then_some(WsaError::ConnectionAborted))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn native(socket: u64, events: u16) -> NativeReadiness {
        NativeReadiness { socket, events, error: None, close: NativeClose::Open, valid: true }
    }

    #[test]
    fn bounded_request_copies_and_rejects_empty_or_oversized_batches() {
        assert_eq!(AsyncPollRequest::new(&[], 0), Err(WsaError::InvalidArgument));
        let fds = [AsyncPollFd { socket: 1, events: WSA_POLLRDNORM }; MAX_ASYNC_POLL_FDS + 1];
        assert_eq!(AsyncPollRequest::new(&fds, -1), Err(WsaError::InvalidArgument));
        let request = AsyncPollRequest::new(&fds[..1], -1).unwrap();
        assert_eq!(request.timeout_ms(), -1);
        assert_eq!(request.fds(), &fds[..1]);
    }

    #[test]
    fn native_read_write_error_and_eof_bits_are_filtered_like_wsapoll() {
        let request = AsyncPollRequest::new(&[AsyncPollFd { socket: 7, events: WSA_POLLRDNORM }], 0).unwrap();
        let mut state = native(7, NATIVE_POLLIN | NATIVE_POLLOUT | NATIVE_POLLERR | NATIVE_POLLHUP);
        state.error = Some(111);
        let result = request.complete(&[state]).unwrap();
        assert_eq!(result.ready_count, 1);
        assert_eq!(result.fds[0].revents, WSA_POLLRDNORM | WSA_POLLERR | WSA_POLLHUP);
        assert_eq!(result.fds[0].error, Some(WsaError::ConnectionRefused));
    }

    #[test]
    fn orderly_eof_is_readable_and_reset_supplies_aborted_error() {
        let request = AsyncPollRequest::new(&[AsyncPollFd { socket: 8, events: WSA_POLLRDNORM }], 0).unwrap();
        let mut eof = native(8, NATIVE_POLLHUP);
        eof.close = NativeClose::Eof;
        assert_eq!(request.complete(&[eof]).unwrap().fds[0].error, None);
        let mut reset = native(8, 0);
        reset.close = NativeClose::Reset;
        let result = request.complete(&[reset]).unwrap();
        assert_eq!(result.fds[0].revents, WSA_POLLERR | WSA_POLLHUP);
        assert_eq!(result.fds[0].error, Some(WsaError::ConnectionAborted));
    }

    #[test]
    fn invalid_descriptor_is_pollnval_when_a_valid_peer_exists() {
        let request = AsyncPollRequest::new(&[
            AsyncPollFd { socket: 0, events: WSA_POLLRDNORM },
            AsyncPollFd { socket: 9, events: WSA_POLLRDNORM },
            AsyncPollFd { socket: 10, events: WSA_POLLRDNORM },
        ], 0).unwrap();
        let result = request.complete(&[native(9, NATIVE_POLLIN)]).unwrap();
        assert_eq!(result.ready_count, 3);
        assert_eq!(result.fds[0].revents, WSA_POLLNVAL);
        assert_eq!(result.fds[1].revents, WSA_POLLRDNORM);
        assert_eq!(result.fds[2].revents, WSA_POLLNVAL);
    }

    #[test]
    fn all_invalid_descriptors_fail_the_winsock_call() {
        let request = AsyncPollRequest::new(&[AsyncPollFd { socket: 0, events: 0 }], 0).unwrap();
        assert_eq!(request.complete(&[]), Err(WsaError::NotSocket));
    }
}
