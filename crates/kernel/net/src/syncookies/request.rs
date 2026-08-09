// The two shapes a cookie handshake hands to the connection state machine.
//
// Neither is stored anywhere between the SYN and the acknowledgement — that is
// the entire point of cookies. [`Request`] lives only as long as it takes to
// build one SYN-ACK; [`Rebuild`] only as long as it takes to reconstruct the
// child the acknowledgement proves should exist.

use super::tsopt::Decoded;

/// What the listener decided to answer a SYN with when it chose a cookie over
/// a request: the sequence number that IS the state, and the MSS the cookie
/// rounded the peer's announcement down to.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Request {
    pub isn: u32,
    pub mss: u16,
}

/// Everything a valid cookie proves about a handshake nobody remembered, in
/// the form the child connection is opened from.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Rebuild {
    /// The cookie this side sent, recovered from the acknowledgement.
    pub isn: u32,
    /// The peer's own initial sequence number.
    pub peer_isn: u32,
    /// The MSS the cookie encoded.
    pub mss: u16,
    /// The options the timestamp echo carried back.
    pub opts: Decoded,
    /// The peer's current timestamp value, to echo from here on.
    pub ts_recent: u32,
    /// This connection's timestamp offset, the same one the SYN-ACK used.
    pub ts_off: u32,
    /// The window the acknowledgement advertised, unscaled.
    pub window: u16,
}
