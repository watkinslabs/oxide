// genetlink message framing: `nlmsghdr` + `genlmsghdr` + attribute stream.

extern crate alloc;

use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::{msg, Nlmsghdr};
use super::uapi::Genlmsghdr;

/// Start a genetlink message (`genlmsg_put`): reserve the netlink header and
/// write the family header. `nlmsg_len` is patched by `end`. # C: O(1)
pub fn start(portid: u32, seq: u32, family_id: u16, version: u8, flags: u16, cmd: u8) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(Nlmsghdr::SIZE + Genlmsghdr::SIZE);
    let mut hdr_buf = [0u8; Nlmsghdr::SIZE];
    Nlmsghdr {
        nlmsg_len: 0, nlmsg_type: family_id, nlmsg_flags: flags,
        nlmsg_seq: seq, nlmsg_pid: portid,
    }.write_to(&mut hdr_buf);
    out.extend_from_slice(&hdr_buf);
    let mut genl_buf = [0u8; Genlmsghdr::SIZE];
    Genlmsghdr { cmd, version, reserved: 0 }.write_to(&mut genl_buf);
    out.extend_from_slice(&genl_buf);
    out
}

/// Finalize a message begun at offset `at` (`genlmsg_end`): write its
/// `nlmsg_len` and pad the buffer to the next alignment boundary. # C: O(1)
pub fn end(out: &mut Vec<u8>, at: usize) {
    let len = (out.len() - at) as u32;
    out[at..at + 4].copy_from_slice(&len.to_ne_bytes());
    while out.len() % 4 != 0 { out.push(0); }
}

/// Append the message in `body` (already `end`-ed) to a multi-part reply,
/// stamping `NLM_F_MULTI` on its header. # C: O(len)
pub fn push_multi(reply: &mut Vec<u8>, mut body: Vec<u8>) {
    if let Some(hdr) = Nlmsghdr::parse(&body) {
        let mut multi = hdr;
        multi.nlmsg_flags = crate::flags::NLM_F_MULTI;
        multi.write_to(&mut body);
    }
    reply.extend_from_slice(&body);
}

/// Close a multi-part reply with `NLMSG_DONE`. # C: O(1)
pub fn push_done(reply: &mut Vec<u8>, seq: u32, portid: u32) {
    let mut done = Nlmsghdr::done(seq, portid);
    done.nlmsg_flags = crate::flags::NLM_F_MULTI;
    let mut buf = [0u8; Nlmsghdr::SIZE];
    done.write_to(&mut buf);
    reply.extend_from_slice(&buf);
}

/// `NLMSG_ERROR` reply carrying `-errno`; `Ok` acknowledges. # C: O(1)
pub fn error(req: &Nlmsghdr, err: Result<(), Errno>) -> Vec<u8> {
    let code: i32 = match err { Ok(()) => 0, Err(e) => -e.as_i32() };
    let total = Nlmsghdr::SIZE + core::mem::size_of::<i32>() + Nlmsghdr::SIZE;
    let mut out = Vec::with_capacity(total);
    let mut hdr_buf = [0u8; Nlmsghdr::SIZE];
    Nlmsghdr {
        nlmsg_len: total as u32, nlmsg_type: msg::NLMSG_ERROR, nlmsg_flags: 0,
        nlmsg_seq: req.nlmsg_seq, nlmsg_pid: req.nlmsg_pid,
    }.write_to(&mut hdr_buf);
    out.extend_from_slice(&hdr_buf);
    out.extend_from_slice(&code.to_ne_bytes());
    let mut req_buf = [0u8; Nlmsghdr::SIZE];
    req.write_to(&mut req_buf);
    out.extend_from_slice(&req_buf);
    out
}
