// Which socket shapes `listen(2)` accepts, and which errno each refusal gets.
//
// The ladder matters more than it looks: a datagram or raw INET socket is
// refused with EOPNOTSUPP because it has no listen operation at all, while a
// stream socket in the wrong state is refused with EINVAL. Collapsing the two
// onto one errno is the kind of divergence a portable caller notices and no
// smoke test does.
//
// AF_UNIX has its own ladder: a datagram socket is refused outright, a socket
// that already listens keeps its listener, and a socket that was never bound
// cannot become one.
//
// This lived in `sock/ops.rs`, which is `#[cfg(target_os = "oxide-kernel")]` —
// a `#[cfg(test)]` block there compiles away in silence.
//
// Ungated on purpose: this is the decision logic, and a target-gated module
// would compile its tests away silently.

use crate::NetError;

/// The socket shapes `listen(2)` tells apart. The caller maps its own socket
/// state onto this; nothing here reads a socket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListenShape {
    /// AF_UNIX, bound to a name and not yet listening.
    UnixBound,
    /// AF_UNIX, already listening.
    UnixListening,
    /// AF_UNIX datagram.
    UnixDatagram,
    /// AF_UNIX, connected or never bound — nothing to publish.
    UnixUnnameable,
    /// INET/INET6 stream.
    Stream,
    /// INET/INET6 datagram, raw, or packet.
    NoListenOp,
}

/// What `listen(2)` does with one shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListenAdmit {
    /// Publish or re-publish the AF_UNIX listener with the new backlog.
    UnixListener,
    /// Hand the stream socket to the TCP state machine.
    Stream,
    /// Refuse with this errno.
    Refuse(NetError),
}

/// The listen ladder. # C: O(1)
pub fn admit_listen(shape: ListenShape) -> ListenAdmit {
    match shape {
        ListenShape::UnixBound | ListenShape::UnixListening => ListenAdmit::UnixListener,
        // A datagram socket has no listen operation, on any family.
        ListenShape::UnixDatagram | ListenShape::NoListenOp =>
            ListenAdmit::Refuse(NetError::Eopnotsupp),
        // It has the operation; this socket is simply in no state to use it.
        ListenShape::UnixUnnameable => ListenAdmit::Refuse(NetError::Einval),
        ListenShape::Stream => ListenAdmit::Stream,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bound_or_already_listening_unix_socket_publishes_its_listener() {
        assert_eq!(admit_listen(ListenShape::UnixBound), ListenAdmit::UnixListener);
        // A second listen only changes the backlog; it never replaces the
        // listener, which would strand every connection already queued on it.
        assert_eq!(admit_listen(ListenShape::UnixListening), ListenAdmit::UnixListener);
    }

    #[test]
    fn a_datagram_socket_has_no_listen_operation_on_any_family() {
        assert_eq!(admit_listen(ListenShape::UnixDatagram),
            ListenAdmit::Refuse(NetError::Eopnotsupp));
        assert_eq!(admit_listen(ListenShape::NoListenOp),
            ListenAdmit::Refuse(NetError::Eopnotsupp));
    }

    #[test]
    fn a_unix_socket_with_no_name_to_publish_is_a_state_error_not_a_missing_operation() {
        // EINVAL, not EOPNOTSUPP: the operation exists, this socket cannot use
        // it. A caller distinguishes "wrong socket" from "wrong moment" here.
        assert_eq!(admit_listen(ListenShape::UnixUnnameable),
            ListenAdmit::Refuse(NetError::Einval));
        assert_ne!(admit_listen(ListenShape::UnixUnnameable),
            admit_listen(ListenShape::UnixDatagram));
    }

    #[test]
    fn a_stream_socket_reaches_the_protocol_state_machine() {
        assert_eq!(admit_listen(ListenShape::Stream), ListenAdmit::Stream);
    }
}
