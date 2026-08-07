extern crate alloc;

use alloc::vec::Vec;

use crate::{msg, Nlmsghdr};
use crate::flags;

/// Build a NLMSG_ERROR reply (16 B nlmsghdr + 4 B errno + the
/// echoed request header). errno=0 means "ack" per Linux RTNL
/// convention.
/// # C: O(1)
pub(super) fn build_ack(req: &Nlmsghdr, err: i32) -> Vec<u8> {
    let total = Nlmsghdr::SIZE + 4 + Nlmsghdr::SIZE;
    let hdr = Nlmsghdr {
        nlmsg_len: total as u32,
        nlmsg_type: msg::NLMSG_ERROR,
        nlmsg_flags: 0,
        nlmsg_seq: req.nlmsg_seq,
        nlmsg_pid: req.nlmsg_pid,
    };
    let mut out: Vec<u8> = Vec::with_capacity(total);
    let mut hdr_buf = [0u8; Nlmsghdr::SIZE];
    hdr.write_to(&mut hdr_buf);
    out.extend_from_slice(&hdr_buf);
    out.extend_from_slice(&err.to_ne_bytes());
    let mut req_buf = [0u8; Nlmsghdr::SIZE];
    req.write_to(&mut req_buf);
    out.extend_from_slice(&req_buf);
    out
}

/// Public NLMSG_ERROR ack (err=0) for the dispatcher's default arm.
/// # C: O(1)
pub fn nlmsg_ack_pub(req: &Nlmsghdr, err: i32) -> Vec<u8> { build_ack(req, err) }

/// Build an error ACK carrying the exact byte offset of the rejected request
/// attribute. The socket-level shape step suppresses these TLVs unless the
/// requester enabled `NETLINK_EXT_ACK`. # C: O(1)
pub fn nlmsg_ack_bad_attr(req: &Nlmsghdr, err: i32, offset: u32) -> Vec<u8> {
    let mut out = build_ack(req, err);
    let mut hdr = Nlmsghdr::parse(&out).unwrap();
    hdr.nlmsg_flags |= flags::NLM_F_ACK_TLVS;
    let attr_len = 8u16;
    out.extend_from_slice(&attr_len.to_ne_bytes());
    out.extend_from_slice(&2u16.to_ne_bytes());
    out.extend_from_slice(&offset.to_ne_bytes());
    hdr.nlmsg_len = out.len() as u32;
    hdr.write_to(&mut out);
    out
}
