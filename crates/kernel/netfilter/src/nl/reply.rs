use alloc::vec::Vec;

use ::netlink::{flags, Nlmsghdr};

use crate::subsys;

pub(super) fn build_reply(seq: u32, pid: u32, cmd: u8, multi: bool, body: Vec<u8>) -> Vec<u8> {
    let nlmsg_type = ((subsys::NFNL_SUBSYS_NFTABLES as u16) << 8) | (cmd as u16);
    let total = Nlmsghdr::SIZE + body.len();
    let hdr = Nlmsghdr {
        nlmsg_len: total as u32,
        nlmsg_type,
        nlmsg_flags: if multi { flags::NLM_F_MULTI } else { 0 },
        nlmsg_seq: seq,
        nlmsg_pid: pid,
    };
    let mut out: Vec<u8> = Vec::with_capacity(total);
    let mut hdr_buf = [0u8; Nlmsghdr::SIZE];
    hdr.write_to(&mut hdr_buf);
    out.extend_from_slice(&hdr_buf);
    out.extend_from_slice(&body);
    while out.len() % 4 != 0 { out.push(0); }
    out
}

