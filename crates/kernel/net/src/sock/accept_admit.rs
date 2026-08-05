use crate::NetError;

/// Protocol and state shapes distinguished by `accept(2)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcceptShape {
    /// TCP or AF_UNIX listener.
    Listener,
    /// Stream or sequence-packet socket whose state is not listening.
    StreamState,
    /// Datagram, raw, or packet socket with no protocol accept operation.
    NoAcceptOp,
}

/// Result of the protocol accept-operation screen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcceptAdmit {
    /// Inspect the listener's accept queue.
    Listener,
    /// Refuse with the protocol- or state-specific error.
    Refuse(NetError),
}

/// Distinguish a missing protocol operation from a listener state error.
/// # C: O(1)
pub fn admit_accept_shape(shape: AcceptShape) -> AcceptAdmit {
    match shape {
        AcceptShape::Listener => AcceptAdmit::Listener,
        AcceptShape::StreamState => AcceptAdmit::Refuse(NetError::Einval),
        AcceptShape::NoAcceptOp => AcceptAdmit::Refuse(NetError::Eopnotsupp),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listener_reaches_its_accept_queue() {
        assert_eq!(admit_accept_shape(AcceptShape::Listener), AcceptAdmit::Listener);
    }

    #[test]
    fn a_nonlistening_stream_has_an_operation_but_the_wrong_state() {
        assert_eq!(admit_accept_shape(AcceptShape::StreamState),
            AcceptAdmit::Refuse(NetError::Einval));
    }

    #[test]
    fn datagram_raw_and_packet_protocols_have_no_accept_operation() {
        assert_eq!(admit_accept_shape(AcceptShape::NoAcceptOp),
            AcceptAdmit::Refuse(NetError::Eopnotsupp));
        assert_ne!(admit_accept_shape(AcceptShape::NoAcceptOp),
            admit_accept_shape(AcceptShape::StreamState));
    }
}
