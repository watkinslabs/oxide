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

/// What `listen(2)` does once the whole ladder has run, carrying the backlog
/// the caller asked for after the namespace ceiling was applied to it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ListenStep {
    /// Publish or re-publish the AF_UNIX listener with this backlog.
    UnixListener(usize),
    /// Hand the stream socket to the TCP state machine with this backlog.
    Stream(usize),
    /// Refuse with this errno.
    Refuse(NetError),
}

/// The complete `listen(2)` ladder, in order.
///
/// The order is the contract. The namespace ceiling is applied FIRST, so the
/// security decision is asked about the backlog the socket will actually get
/// rather than the one the caller typed — a request above `net.core.somaxconn`
/// is indistinguishable from one naming exactly the ceiling, which is what
/// makes the ceiling a ceiling and not a second gate. The socket's own shape
/// is consulted last, so a denied call never reveals whether the socket could
/// have listened at all.
///
/// A namespace with no recorded ceiling uses the compiled default: the ceiling
/// is a tunable that always has a value, never a resource whose absence
/// refuses the call.
///
/// `security` and `shape` are supplied by the caller and evaluated in ladder
/// order, so which rung ran — and which did not — is observable.
/// # C: O(1) + security
pub fn listen_ladder(somaxconn: Option<usize>, backlog: i32,
                     security: impl FnOnce(usize) -> Result<(), NetError>,
                     shape: impl FnOnce() -> ListenShape) -> ListenStep
{
    let limit = somaxconn.unwrap_or(crate::sysctl::DEFAULT_SOMAXCONN);
    let backlog = crate::sysctl::normalize_listen_backlog(backlog, limit);
    if let Err(error) = security(backlog) { return ListenStep::Refuse(error); }
    match admit_listen(shape()) {
        ListenAdmit::UnixListener => ListenStep::UnixListener(backlog),
        ListenAdmit::Stream       => ListenStep::Stream(backlog),
        ListenAdmit::Refuse(e)    => ListenStep::Refuse(e),
    }
}

/// Which `SockKind` a TCP-family socket is in, as seen by a second (or
/// first) `listen(2)` once the ladder above has already admitted the call.
/// The caller maps its own `SockKind` onto this; nothing here reads a socket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpKindShape {
    /// Fresh, never bound into a listener or a connection.
    Init,
    /// Already listening.
    Listening,
    /// Any other state — bound-but-connecting, established, closing. A
    /// stream socket in any of these fails `sock->state == SS_UNCONNECTED`.
    Other,
}

/// What a TCP-family `listen(2)` does once its `SockKind` is known.
///
/// Linux's `inet_listen` (`net/ipv4/af_inet.c`) refuses unless
/// `sock->state == SS_UNCONNECTED`; `inet_csk_listen_start`
/// (`net/ipv4/inet_connection_sock.c`) runs only on that first transition.
/// A later `listen(2)` on an already-listening socket takes the same
/// `SS_UNCONNECTED`-guard success path and republishes the backlog
/// (`sk->sk_max_ack_backlog = backlog`) without rebuilding the listener —
/// it does not refuse and it does not strand connections already queued.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpListenTransition {
    /// First transition into listening: build a real listener.
    Start,
    /// Already listening: republish this backlog on the existing listener.
    Republish,
    /// Any other state (e.g. connected): EINVAL.
    Refuse,
}

/// The TCP-kind rung of the `listen(2)` ladder, once the generic security
/// and shape rungs above have already admitted the call. # C: O(1)
pub fn tcp_listen_transition(shape: TcpKindShape) -> TcpListenTransition {
    match shape {
        TcpKindShape::Init      => TcpListenTransition::Start,
        TcpKindShape::Listening => TcpListenTransition::Republish,
        TcpKindShape::Other     => TcpListenTransition::Refuse,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    /// Which rungs ran, and what the security rung was told.
    #[derive(Default)]
    struct Run { asked: Cell<Option<usize>>, shaped: Cell<u32> }

    fn ladder(run: &Run, somaxconn: Option<usize>, backlog: i32, allow: bool,
              shape: ListenShape) -> ListenStep
    {
        listen_ladder(somaxconn, backlog,
            |b| { run.asked.set(Some(b)); if allow { Ok(()) } else { Err(NetError::Eacces) } },
            || { run.shaped.set(run.shaped.get() + 1); shape })
    }

    #[test]
    fn the_namespace_ceiling_is_applied_before_the_security_decision_sees_it() {
        let run = Run::default();
        assert_eq!(ladder(&run, Some(128), 4096, true, ListenShape::Stream),
            ListenStep::Stream(128));
        assert_eq!(run.asked.get(), Some(128));
    }

    #[test]
    fn a_negative_backlog_reaches_the_ceiling_rather_than_wrapping() {
        // The clamp is unsigned, so -1 is the largest request there is and
        // lands exactly on the ceiling.
        let run = Run::default();
        assert_eq!(ladder(&run, Some(64), -1, true, ListenShape::Stream),
            ListenStep::Stream(64));
        assert_eq!(run.asked.get(), Some(64));
    }

    #[test]
    fn a_namespace_with_no_recorded_ceiling_uses_the_compiled_default() {
        // Absence of a tunable is not a missing resource: it never refuses.
        let run = Run::default();
        assert_eq!(ladder(&run, None, i32::MAX, true, ListenShape::Stream),
            ListenStep::Stream(crate::sysctl::DEFAULT_SOMAXCONN));
        assert_eq!(run.asked.get(), Some(crate::sysctl::DEFAULT_SOMAXCONN));
        assert_eq!(run.shaped.get(), 1);
    }

    #[test]
    fn a_denied_call_never_asks_the_socket_what_shape_it_is() {
        for shape in [ListenShape::Stream, ListenShape::UnixDatagram,
                      ListenShape::UnixUnnameable, ListenShape::NoListenOp] {
            let run = Run::default();
            assert_eq!(ladder(&run, Some(128), 5, false, shape),
                ListenStep::Refuse(NetError::Eacces), "{shape:?}");
            // EACCES outranks the shape's own EOPNOTSUPP/EINVAL, and the
            // shape is never even read.
            assert_eq!(run.shaped.get(), 0, "{shape:?}");
        }
    }

    #[test]
    fn an_admitted_unix_socket_carries_the_clamped_backlog_to_its_listener() {
        let run = Run::default();
        assert_eq!(ladder(&run, Some(8), 100, true, ListenShape::UnixBound),
            ListenStep::UnixListener(8));
        assert_eq!(ladder(&run, Some(8), 3, true, ListenShape::UnixListening),
            ListenStep::UnixListener(3));
    }

    #[test]
    fn an_admitted_socket_with_no_listen_operation_still_reports_its_own_error() {
        let run = Run::default();
        assert_eq!(ladder(&run, Some(8), 3, true, ListenShape::NoListenOp),
            ListenStep::Refuse(NetError::Eopnotsupp));
        assert_eq!(ladder(&run, Some(8), 3, true, ListenShape::UnixDatagram),
            ListenStep::Refuse(NetError::Eopnotsupp));
        assert_eq!(ladder(&run, Some(8), 3, true, ListenShape::UnixUnnameable),
            ListenStep::Refuse(NetError::Einval));
    }

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

    #[test]
    fn a_fresh_socket_starts_a_new_listener() {
        assert_eq!(tcp_listen_transition(TcpKindShape::Init), TcpListenTransition::Start);
    }

    #[test]
    fn an_already_listening_socket_only_republishes_its_backlog() {
        assert_eq!(tcp_listen_transition(TcpKindShape::Listening), TcpListenTransition::Republish);
    }

    /// A connected (or otherwise non-`SS_UNCONNECTED`) stream socket is
    /// EINVAL, matching `net/ipv4/af_inet.c:inet_listen`'s
    /// `sock->state != SS_UNCONNECTED` refusal. Positive control: swapping
    /// this arm to `Start` or `Republish` turns this test RED.
    #[test]
    fn any_other_state_refuses_with_einval() {
        assert_eq!(tcp_listen_transition(TcpKindShape::Other), TcpListenTransition::Refuse);
    }
}
