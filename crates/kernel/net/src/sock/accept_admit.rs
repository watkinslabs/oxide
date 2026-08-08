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

/// The complete `accept(2)` admission ladder, in order.
///
/// The security decision precedes the shape screen, so a denied accept never
/// discloses whether the socket was a listener at all, and it precedes the
/// listener's queue, so a denial cannot consume a pending connection. Both
/// rungs are caller-supplied and evaluated in ladder order, which is what
/// makes the order observable rather than incidental.
/// # C: O(1) + security
pub fn accept_ladder(security: impl FnOnce() -> Result<(), NetError>,
                     shape: impl FnOnce() -> AcceptShape) -> AcceptAdmit
{
    if let Err(error) = security() { return AcceptAdmit::Refuse(error); }
    admit_accept_shape(shape())
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    #[test]
    fn a_denied_accept_never_asks_the_socket_what_shape_it_is() {
        for shape in [AcceptShape::Listener, AcceptShape::StreamState,
                      AcceptShape::NoAcceptOp] {
            let shaped = Cell::new(0u32);
            let admit = accept_ladder(|| Err(NetError::Eacces),
                || { shaped.set(shaped.get() + 1); shape });
            assert_eq!(admit, AcceptAdmit::Refuse(NetError::Eacces), "{shape:?}");
            // EACCES outranks EINVAL and EOPNOTSUPP, and a denial that read
            // the socket's state would leak whether it could have accepted.
            assert_eq!(shaped.get(), 0, "{shape:?}");
        }
    }

    #[test]
    fn an_admitted_accept_reports_its_own_shape_verdict() {
        let allow = || Ok(());
        assert_eq!(accept_ladder(allow, || AcceptShape::Listener), AcceptAdmit::Listener);
        assert_eq!(accept_ladder(allow, || AcceptShape::StreamState),
            AcceptAdmit::Refuse(NetError::Einval));
        assert_eq!(accept_ladder(allow, || AcceptShape::NoAcceptOp),
            AcceptAdmit::Refuse(NetError::Eopnotsupp));
    }

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
