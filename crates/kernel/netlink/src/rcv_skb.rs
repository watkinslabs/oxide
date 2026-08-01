// Netlink core datagram framing walk — the decision logic behind
// `NetlinkSocket::write_datagram`. Ungated so the whole contract is covered by
// hosted tests; the socket file only drives the steps this module decides.

use crate::{flags, msg, proto, nlmsg_align, Nlmsghdr};

/// One framing step over a userspace netlink datagram.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Frame {
    pub hdr: Nlmsghdr,
    /// Byte span of this message, `nlmsg_len` exactly.
    pub msg_len: usize,
    /// Offset delta to the next message: the aligned length, clamped to the
    /// bytes that remain. A trailing message whose ALIGNED length overruns the
    /// datagram is accepted and ends the walk.
    pub advance: usize,
}

/// Decode the message at `off`, or `None` to end the walk.
///
/// Ending the walk is never an error for the sender: a datagram tail shorter
/// than one header, a `nlmsg_len` below the header size, and a `nlmsg_len`
/// past the end of the datagram all stop parsing with the send still reporting
/// every byte accepted. Userspace relies on this — `ip(8)` sends a fixed-size
/// request buffer whose `nlmsg_len` covers only its leading message, leaving
/// zeroed padding behind it.
/// # C: O(1)
pub(crate) fn frame_at(datagram: &[u8], off: usize) -> Option<Frame> {
    let remaining = datagram.len().checked_sub(off)?;
    if remaining < Nlmsghdr::SIZE { return None; }
    let hdr = Nlmsghdr::parse(&datagram[off..])?;
    let msg_len = hdr.nlmsg_len as usize;
    if msg_len < Nlmsghdr::SIZE || msg_len > remaining { return None; }
    Some(Frame { hdr, msg_len, advance: nlmsg_align(msg_len).min(remaining) })
}

/// Whether a well-formed message reaches the protocol's request handler.
///
/// Netlink core admits only requests carrying a protocol message type;
/// non-requests and the reserved control types below `NLMSG_MIN_TYPE` are
/// acknowledged (when asked) without ever reaching the family callback.
/// `NETLINK_AUDIT` walks the datagram in its own receive path and applies no
/// such filter, so every well-formed message reaches it.
/// # C: O(1)
pub(crate) fn reaches_handler(protocol: u16, hdr: &Nlmsghdr) -> bool {
    if protocol == proto::NETLINK_AUDIT { return true; }
    hdr.nlmsg_flags & flags::NLM_F_REQUEST != 0 && hdr.nlmsg_type >= msg::NLMSG_MIN_TYPE
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::vec::Vec;

    use super::{frame_at, reaches_handler, Frame};
    use crate::{flags, msg, proto, Nlmsghdr};

    fn frame_bytes(len: u32, ty: u16, flags: u16, trailing: usize) -> Vec<u8> {
        let hdr = Nlmsghdr { nlmsg_len: len, nlmsg_type: ty, nlmsg_flags: flags,
            nlmsg_seq: 7, nlmsg_pid: 9 };
        let mut out = alloc::vec![0u8; (len as usize).max(Nlmsghdr::SIZE) + trailing];
        hdr.write_to(&mut out);
        out
    }

    /// `ip(8)` sends a fixed-size request buffer: one 24-byte `RTM_GETADDR`
    /// followed by 128 zero bytes of unused room. The walk must dispatch the
    /// leading message and end on the padding without failing the send.
    #[test]
    fn zero_padded_dump_request_dispatches_then_ends_without_error() {
        const REQ: u32 = 24;
        const BUF: usize = 152;
        let buf = frame_bytes(REQ, 22, flags::NLM_F_REQUEST | flags::NLM_F_DUMP,
            BUF - REQ as usize);
        assert_eq!(buf.len(), BUF);
        let frame = frame_at(&buf, 0).expect("leading message is well formed");
        assert_eq!(frame.msg_len, REQ as usize);
        assert_eq!(frame.advance, REQ as usize);
        assert_eq!(frame_at(&buf, frame.advance), None, "zero padding ends the walk");
    }

    #[test]
    fn tail_shorter_than_one_header_ends_the_walk() {
        let buf = frame_bytes(Nlmsghdr::SIZE as u32, 22, flags::NLM_F_REQUEST, 15);
        let frame = frame_at(&buf, 0).unwrap();
        assert_eq!(frame.advance, Nlmsghdr::SIZE);
        assert_eq!(frame_at(&buf, frame.advance), None);
        assert_eq!(frame_at(&buf, buf.len()), None);
        assert_eq!(frame_at(&buf, buf.len() + 64), None, "offset past the end is not a panic");
    }

    #[test]
    fn nlmsg_len_below_header_size_ends_the_walk() {
        let buf = frame_bytes((Nlmsghdr::SIZE - 1) as u32, 22, flags::NLM_F_REQUEST, 0);
        assert_eq!(frame_at(&buf, 0), None);
    }

    #[test]
    fn nlmsg_len_past_the_datagram_ends_the_walk() {
        let mut buf = frame_bytes((Nlmsghdr::SIZE + 1) as u32, 22, flags::NLM_F_REQUEST, 0);
        buf.truncate(Nlmsghdr::SIZE);
        assert_eq!(frame_at(&buf, 0), None);
    }

    /// A final message whose ALIGNED length overruns the buffer is accepted:
    /// the advance clamps to the datagram end rather than rejecting the send.
    #[test]
    fn unaligned_final_message_clamps_the_advance() {
        let len = Nlmsghdr::SIZE + 1;
        let buf = frame_bytes(len as u32, 22, flags::NLM_F_REQUEST, 0);
        assert_eq!(buf.len(), len);
        let frame = frame_at(&buf, 0).expect("unaligned trailing message is well formed");
        assert_eq!(frame.msg_len, len);
        assert_eq!(frame.advance, len, "clamped to the datagram, not the 20-byte alignment");
        assert_eq!(frame_at(&buf, frame.advance), None);
    }

    #[test]
    fn two_packed_messages_walk_in_order() {
        let first = Nlmsghdr::SIZE + 2;
        let mut buf = frame_bytes(first as u32, 22, flags::NLM_F_REQUEST, 0);
        buf.resize(crate::nlmsg_align(first), 0);
        let second = frame_bytes(Nlmsghdr::SIZE as u32, 18, flags::NLM_F_REQUEST, 0);
        buf.extend_from_slice(&second);
        let a = frame_at(&buf, 0).unwrap();
        assert_eq!((a.hdr.nlmsg_type, a.msg_len, a.advance), (22, first, crate::nlmsg_align(first)));
        let b = frame_at(&buf, a.advance).unwrap();
        assert_eq!((b.hdr.nlmsg_type, b.msg_len), (18, Nlmsghdr::SIZE));
        assert_eq!(frame_at(&buf, a.advance + b.advance), None);
    }

    fn hdr(ty: u16, fl: u16) -> Nlmsghdr {
        Nlmsghdr { nlmsg_len: Nlmsghdr::SIZE as u32, nlmsg_type: ty, nlmsg_flags: fl,
            nlmsg_seq: 1, nlmsg_pid: 2 }
    }

    #[test]
    fn only_requests_with_a_protocol_type_reach_the_handler() {
        let route = proto::NETLINK_ROUTE;
        assert!(reaches_handler(route, &hdr(22, flags::NLM_F_REQUEST)));
        assert!(!reaches_handler(route, &hdr(22, 0)), "non-request never dispatches");
        assert!(!reaches_handler(route, &hdr(msg::NLMSG_NOOP, flags::NLM_F_REQUEST)));
        assert!(!reaches_handler(route, &hdr(msg::NLMSG_ERROR, flags::NLM_F_REQUEST)));
        assert!(!reaches_handler(route, &hdr(msg::NLMSG_DONE, flags::NLM_F_REQUEST)));
        assert!(!reaches_handler(route, &hdr(msg::NLMSG_OVERRUN, flags::NLM_F_REQUEST)));
        assert!(!reaches_handler(route, &hdr(msg::NLMSG_MIN_TYPE - 1, flags::NLM_F_REQUEST)));
        assert!(reaches_handler(route, &hdr(msg::NLMSG_MIN_TYPE, flags::NLM_F_REQUEST)));
    }

    #[test]
    fn audit_receives_every_well_formed_message() {
        let audit = proto::NETLINK_AUDIT;
        assert!(reaches_handler(audit, &hdr(msg::NLMSG_NOOP, 0)));
        assert!(reaches_handler(audit, &hdr(1124, 0)));
    }

    #[test]
    fn frame_is_copy_for_the_caller_loop() {
        let buf = frame_bytes(Nlmsghdr::SIZE as u32, 22, flags::NLM_F_REQUEST, 0);
        let frame: Frame = frame_at(&buf, 0).unwrap();
        let copied = frame;
        assert_eq!(copied, frame);
    }
}
