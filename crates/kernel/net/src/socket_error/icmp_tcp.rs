//! What a connection does with an ICMP error that names it.
//!
//! A connection that is still handshaking dies of the error. One that is
//! already up never does: the error is either published to a socket that asked
//! for extended errors, or kept as the non-fatal record the option read and the
//! give-up path consult. Nothing tears the connection down on an ICMP error
//! alone once it is established.

use crate::tcp_state::TcpState;

/// What the connection owes an ICMP error that named it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpTcpVerdict {
    /// The handshake cannot survive it: publish and close.
    Fatal,
    /// Publish it as the pending error, but leave the connection running.
    Report,
    /// Keep it as the non-fatal record; no reader is woken.
    Soft,
}

/// Decide the fate of an ICMP error against connection state and whether the
/// socket asked for extended errors. # C: O(1)
pub fn icmp_tcp_verdict(state: TcpState, recverr: bool) -> IcmpTcpVerdict {
    match state {
        TcpState::SynSent | TcpState::SynRecv => IcmpTcpVerdict::Fatal,
        _ if recverr => IcmpTcpVerdict::Report,
        _ => IcmpTcpVerdict::Soft,
    }
}

#[cfg(test)]
mod tests {
    use super::{icmp_tcp_verdict, IcmpTcpVerdict};
    use crate::tcp_state::TcpState;

    #[test]
    fn a_handshaking_connection_dies_of_the_error_whatever_the_socket_asked_for() {
        for state in [TcpState::SynSent, TcpState::SynRecv] {
            for recverr in [false, true] {
                assert_eq!(icmp_tcp_verdict(state, recverr), IcmpTcpVerdict::Fatal);
            }
        }
    }

    #[test]
    fn an_established_connection_is_never_torn_down_by_the_error() {
        for state in [TcpState::Established, TcpState::CloseWait, TcpState::FinWait1,
            TcpState::FinWait2, TcpState::Closing, TcpState::LastAck]
        {
            assert_eq!(icmp_tcp_verdict(state, true), IcmpTcpVerdict::Report);
            assert_eq!(icmp_tcp_verdict(state, false), IcmpTcpVerdict::Soft);
        }
    }
}
