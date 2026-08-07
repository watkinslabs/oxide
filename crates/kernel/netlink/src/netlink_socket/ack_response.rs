// NLMSG_ERROR response shaping after the protocol handler supplied its errno.

extern crate alloc;

use alloc::vec::Vec;

use crate::{flags, msg, Nlmsghdr};

const NLMSGERR_HEAD_LEN: usize = 4 + Nlmsghdr::SIZE;

fn reply_header(reply: &[u8]) -> Option<Nlmsghdr> {
    let hdr = Nlmsghdr::parse(reply)?;
    (hdr.nlmsg_type == msg::NLMSG_ERROR && reply.len() >= Nlmsghdr::SIZE + NLMSGERR_HEAD_LEN)
        .then_some(hdr)
}

fn reply_error(reply: &[u8]) -> i32 {
    i32::from_ne_bytes(reply[Nlmsghdr::SIZE..Nlmsghdr::SIZE + 4].try_into().unwrap())
}

fn set_reply_header(reply: &mut [u8], mut hdr: Nlmsghdr) {
    hdr.nlmsg_len = reply.len() as u32;
    hdr.write_to(reply);
}

/// Apply the socket-owned ACK policy after a protocol handler produced one
/// canonical `NLMSG_ERROR`. Error ACKs copy the request payload unless the
/// sender asked for `NETLINK_CAP_ACK`; successful ACKs are always capped.
/// # C: O(reply + request)
pub(super) fn shape(reply: &mut Vec<u8>, request: &[u8], cap_ack: bool, ext_ack: bool) {
    let Some(mut hdr) = reply_header(reply) else { return; };
    let error = reply_error(reply);
    let base = Nlmsghdr::SIZE + NLMSGERR_HEAD_LEN;
    let has_tlvs = hdr.nlmsg_flags & flags::NLM_F_ACK_TLVS != 0;
    if has_tlvs && !ext_ack {
        reply.truncate(base);
        hdr.nlmsg_flags &= !flags::NLM_F_ACK_TLVS;
    }
    if error == 0 || cap_ack {
        hdr.nlmsg_flags |= flags::NLM_F_CAPPED;
        set_reply_header(reply, hdr);
        return;
    }
    let Some(req) = Nlmsghdr::parse(request) else { return; };
    let req_len = req.nlmsg_len as usize;
    if req_len < Nlmsghdr::SIZE || req_len > request.len() { return; }
    if has_tlvs && ext_ack {
        reply.splice(base..base, request[Nlmsghdr::SIZE..req_len].iter().copied());
    } else { reply.extend_from_slice(&request[Nlmsghdr::SIZE..req_len]); }
    set_reply_header(reply, hdr);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{proto, NetlinkSocket};
    use network_namespace::initial;

    fn request(payload: &[u8]) -> Vec<u8> {
        let hdr = Nlmsghdr { nlmsg_len: (Nlmsghdr::SIZE + payload.len()) as u32,
            nlmsg_type: 0x40, nlmsg_flags: flags::NLM_F_REQUEST, nlmsg_seq: 7, nlmsg_pid: 9 };
        let mut out = alloc::vec![0; Nlmsghdr::SIZE + payload.len()];
        hdr.write_to(&mut out);
        out[Nlmsghdr::SIZE..].copy_from_slice(payload);
        out
    }

    fn ack(request: &Nlmsghdr, error: i32) -> Vec<u8> {
        let hdr = Nlmsghdr { nlmsg_len: (Nlmsghdr::SIZE + NLMSGERR_HEAD_LEN) as u32,
            nlmsg_type: msg::NLMSG_ERROR, nlmsg_flags: 0, nlmsg_seq: request.nlmsg_seq, nlmsg_pid: request.nlmsg_pid };
        let mut out = alloc::vec![0; hdr.nlmsg_len as usize];
        hdr.write_to(&mut out);
        out[Nlmsghdr::SIZE..Nlmsghdr::SIZE + 4].copy_from_slice(&error.to_ne_bytes());
        request.write_to(&mut out[Nlmsghdr::SIZE + 4..]);
        out
    }

    #[test]
    fn error_ack_retains_the_original_payload_unless_the_socket_caps_it() {
        let request = request(b"full original request");
        let hdr = Nlmsghdr::parse(&request).unwrap();
        let mut uncapped = ack(&hdr, -22);
        shape(&mut uncapped, &request, false, false);
        assert_eq!(&uncapped[Nlmsghdr::SIZE + NLMSGERR_HEAD_LEN..], b"full original request");
        assert_eq!(Nlmsghdr::parse(&uncapped).unwrap().nlmsg_flags & flags::NLM_F_CAPPED, 0);

        let mut capped = ack(&hdr, -22);
        shape(&mut capped, &request, true, false);
        assert_eq!(capped.len(), Nlmsghdr::SIZE + NLMSGERR_HEAD_LEN);
        assert_ne!(Nlmsghdr::parse(&capped).unwrap().nlmsg_flags & flags::NLM_F_CAPPED, 0);
    }

    #[test]
    fn successful_ack_is_capped_even_without_the_option() {
        let request = request(b"ignored on success");
        let mut reply = ack(&Nlmsghdr::parse(&request).unwrap(), 0);
        shape(&mut reply, &request, false, false);
        assert_eq!(reply.len(), Nlmsghdr::SIZE + NLMSGERR_HEAD_LEN);
        assert_ne!(Nlmsghdr::parse(&reply).unwrap().nlmsg_flags & flags::NLM_F_CAPPED, 0);
    }

    #[test]
    fn socket_option_controls_the_dispatched_error_ack_width() {
        let request = request(b"request body reaches the error reply");
        let uncapped = NetlinkSocket::new(proto::NETLINK_ROUTE, &initial());
        uncapped.write(&request).unwrap();
        let (reply, _) = uncapped.dequeue().unwrap();
        assert_eq!(&reply[Nlmsghdr::SIZE + NLMSGERR_HEAD_LEN..],
            b"request body reaches the error reply");

        let capped = NetlinkSocket::new(proto::NETLINK_ROUTE, &initial());
        capped.flags.assign(crate::F_CAP_ACK, true);
        capped.write(&request).unwrap();
        let (reply, _) = capped.dequeue().unwrap();
        assert_eq!(reply.len(), Nlmsghdr::SIZE + NLMSGERR_HEAD_LEN);
        assert_ne!(Nlmsghdr::parse(&reply).unwrap().nlmsg_flags & flags::NLM_F_CAPPED, 0);
    }
}
