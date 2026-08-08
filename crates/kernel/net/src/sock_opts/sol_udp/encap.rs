// `UDP_ENCAP` receive-side decision. Pure and ungated: the stack's UDP input
// arms are thin callers, so the contract below is exercised directly by
// hosted tests rather than only through a booted receive path.

use super::uapi::UDP_ENCAP_ESPINUDP;

/// Bytes of encapsulated-security-payload header (32-bit security-parameter
/// index followed by a 32-bit sequence number). A body no longer than this
/// cannot be a payload, so it is a key-exchange control packet.
pub const ESP_HDR_LEN: usize = 8;

/// Bytes of the non-payload marker that prefixes a key-exchange control
/// packet multiplexed onto an encapsulation port.
pub const NON_ESP_MARKER_LEN: usize = 4;

/// The single byte a NAT keepalive carries.
pub const KEEPALIVE_BYTE: u8 = 0xff;

/// Why the encapsulation handler kept a datagram away from the socket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncapConsumed {
    /// One `0xff` byte: a NAT keepalive, eaten by the handler.
    Keepalive,
    /// An encapsulated security payload. The handler strips the outer
    /// transport header and hands the datagram to the transform receiver;
    /// with no matching security association the datagram is dropped there.
    /// This tree has no transform subsystem, so that is always the outcome —
    /// the datagram is consumed and never reaches the socket either way.
    SecurityPayload,
}

/// What the encapsulation handler decided about one arriving datagram.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncapVerdict {
    /// Queue the datagram to the socket unchanged. Also the verdict whenever
    /// no handler is installed for the socket's encapsulation identity.
    Deliver,
    /// The handler took the datagram; the socket never sees it.
    Consumed(EncapConsumed),
}

impl EncapVerdict {
    /// The datagram is not queued to the socket. # C: O(1)
    pub fn consumed(&self) -> bool { matches!(self, Self::Consumed(_)) }
}

/// Verdict for one datagram body arriving on a socket whose `UDP_ENCAP`
/// identity is `encap_type`.
///
/// Only the security-encapsulation identity installs a receive handler
/// through a plain socket option; the tunnel identity is a label a tunnel
/// subsystem consults when it installs its own handler, so on its own it
/// leaves ordinary delivery untouched. Every other stored value likewise has
/// no handler and delivers.
///
/// With a handler installed, the body classifies as: a NAT keepalive (one
/// `0xff` byte, eaten); an encapsulated security payload (longer than the
/// payload header and not prefixed by the all-zero non-payload marker,
/// consumed by the transform receiver); or a key-exchange control packet
/// (everything else, delivered to the socket). # C: O(1)
pub fn rx_verdict(encap_type: i32, body: &[u8]) -> EncapVerdict {
    // `UDP_ENCAP_NONE`, `UDP_ENCAP_L2TPINUDP` and anything else: no handler,
    // ordinary delivery.
    if encap_type != UDP_ENCAP_ESPINUDP { return EncapVerdict::Deliver; }
    if body.len() == 1 && body[0] == KEEPALIVE_BYTE {
        return EncapVerdict::Consumed(EncapConsumed::Keepalive);
    }
    if body.len() > ESP_HDR_LEN && body[..NON_ESP_MARKER_LEN] != [0u8; NON_ESP_MARKER_LEN] {
        return EncapVerdict::Consumed(EncapConsumed::SecurityPayload);
    }
    EncapVerdict::Deliver
}
