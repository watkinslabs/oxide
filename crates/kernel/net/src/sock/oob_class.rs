// How each socket kind answers the out-of-band operations: `recv(MSG_OOB)`
// and `SIOCATMARK`. ONE owner for both answers, because the syscall shim and
// the ioctl path ask the same question of the same kinds and must not be able
// to disagree about it.
//
// Ungated on purpose: these are the errno decisions, and a target-gated module
// would compile its tests away silently.

use super::SockKind;

/// The out-of-band shape of one socket, which is all either answer depends on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OobShape {
    /// AF_UNIX `SOCK_STREAM`, connected: the one AF_UNIX kind with an
    /// out-of-band channel.
    UnixStream,
    /// AF_UNIX `SOCK_SEQPACKET`.
    UnixSeqpacket,
    /// AF_UNIX `SOCK_DGRAM`.
    UnixDgram,
    /// AF_UNIX listening socket.
    UnixListener,
    /// AF_UNIX socket with no connection yet.
    UnixUnbound,
    /// A TCP connection, whose urgent pointer answers the mark.
    Tcp,
    /// Every other kind — no out-of-band channel and no mark to report.
    Other,
}

/// Classify a socket for the out-of-band answers. # C: O(1)
pub fn oob_shape(kind: &SockKind) -> OobShape {
    match kind {
        SockKind::Unix(_, _)        => OobShape::UnixStream,
        SockKind::UnixMsgPair(_, _) => OobShape::UnixSeqpacket,
        SockKind::UnixDgram(_)      => OobShape::UnixDgram,
        SockKind::UnixListener(_)   => OobShape::UnixListener,
        SockKind::UnixUnbound(_, _) => OobShape::UnixUnbound,
        SockKind::TcpConn(_)        => OobShape::Tcp,
        _                           => OobShape::Other,
    }
}

/// What `recv(..., MSG_OOB)` on an AF_UNIX socket does.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecvOob {
    /// Deliver the pending urgent byte.
    Urgent,
    /// EOPNOTSUPP — this socket kind has no out-of-band channel at all.
    Eopnotsupp,
    /// EINVAL — this socket cannot receive, so the request never reaches the
    /// question of an out-of-band channel.
    Einval,
}

/// `recv(MSG_OOB)`'s answer for one socket shape.
///
/// The unconnected stream reports EINVAL rather than EOPNOTSUPP: the receive
/// itself is refused before the out-of-band channel is considered, so the
/// out-of-band flag does not change the answer a plain receive would give.
/// # C: O(1)
pub fn recv_oob(shape: OobShape) -> RecvOob {
    match shape {
        OobShape::UnixStream => RecvOob::Urgent,
        OobShape::UnixSeqpacket | OobShape::UnixDgram => RecvOob::Eopnotsupp,
        _ => RecvOob::Einval,
    }
}

/// Bytes a completed `recv(MSG_OOB)` reports. The out-of-band channel carries
/// exactly one byte, and the count is that fixed one — a destination with no
/// room for it still consumes the byte and still reports one.
pub const URGENT_RECV_LEN: i64 = 1;

/// What a completed `recv(MSG_OOB)` reports, given how many bytes the copy to
/// the destination actually took. The copy's own count is NOT the answer: a
/// zero-length destination takes nothing and still consumes the byte, and the
/// receive still reports one. # C: O(1)
pub fn urgent_recv_len(_copied: usize) -> i64 { URGENT_RECV_LEN }

/// What `ioctl(SIOCATMARK)` on a socket answers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AtMark {
    /// Report whether the next byte read is the urgent mark.
    Report,
    /// EOPNOTSUPP — a socket family that has an out-of-band channel, but not
    /// on this kind, so the mark is not a question this socket can answer.
    Eopnotsupp,
    /// ENOTTY — the request is not one this kind of file implements at all.
    Enotty,
}

/// `SIOCATMARK`'s answer for one socket shape. # C: O(1)
pub fn at_mark(shape: OobShape) -> AtMark {
    match shape {
        OobShape::UnixStream | OobShape::Tcp => AtMark::Report,
        OobShape::UnixSeqpacket | OobShape::UnixDgram | OobShape::UnixListener
            | OobShape::UnixUnbound => AtMark::Eopnotsupp,
        OobShape::Other => AtMark::Enotty,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_connected_unix_stream_receives_out_of_band() {
        assert_eq!(recv_oob(OobShape::UnixStream), RecvOob::Urgent);
    }

    #[test]
    fn unix_datagram_and_seqpacket_have_no_out_of_band_channel() {
        assert_eq!(recv_oob(OobShape::UnixDgram), RecvOob::Eopnotsupp);
        assert_eq!(recv_oob(OobShape::UnixSeqpacket), RecvOob::Eopnotsupp);
    }

    #[test]
    fn an_unreceivable_unix_socket_reports_einval_not_eopnotsupp() {
        // Ordering: the receive is refused before the out-of-band channel is
        // considered, so MSG_OOB does not upgrade the errno.
        assert_eq!(recv_oob(OobShape::UnixUnbound), RecvOob::Einval);
        assert_eq!(recv_oob(OobShape::UnixListener), RecvOob::Einval);
        assert_eq!(recv_oob(OobShape::Other), RecvOob::Einval);
    }

    #[test]
    fn an_out_of_band_receive_reports_one_byte() {
        assert_eq!(urgent_recv_len(1), 1, "the byte the copy took");
        // The divergence that matters: a destination with no room takes
        // nothing, consumes the byte anyway, and still reports one.
        assert_eq!(urgent_recv_len(0), 1, "a zero-length destination still reports one");
    }

    #[test]
    fn the_mark_is_answered_by_the_kinds_that_have_one() {
        assert_eq!(at_mark(OobShape::UnixStream), AtMark::Report);
        assert_eq!(at_mark(OobShape::Tcp), AtMark::Report);
    }

    #[test]
    fn the_other_unix_kinds_cannot_answer_the_mark() {
        for shape in [OobShape::UnixSeqpacket, OobShape::UnixDgram,
                      OobShape::UnixListener, OobShape::UnixUnbound] {
            assert_eq!(at_mark(shape), AtMark::Eopnotsupp, "{shape:?}");
        }
    }

    #[test]
    fn a_kind_with_no_out_of_band_notion_reports_enotty() {
        // ENOTTY, not EOPNOTSUPP: the request is not implemented here at all,
        // which is a different answer from "implemented, not on this kind".
        assert_eq!(at_mark(OobShape::Other), AtMark::Enotty);
    }
}
