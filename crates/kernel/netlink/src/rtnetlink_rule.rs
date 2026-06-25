// RTM_GETRULE policy-rule dump. Linux publishes three default v4/v6 rules even
// without custom policy routing: local, main, default.

extern crate alloc;

use alloc::vec::Vec;

use crate::{flags, Nlmsghdr};
use crate::rtnetlink::{
    done_multi, put_nlattr_u32, AF_INET, AF_INET6, RTM_NEWRULE, RT_TABLE_DEFAULT, RT_TABLE_LOCAL,
    RT_TABLE_MAIN,
};

const FR_ACT_TO_TBL: u8 = 1;

pub mod fra {
    pub const FRA_PRIORITY: u16 = 6;
    pub const FRA_TABLE:    u16 = 15;
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct FibRuleHdr {
    pub family:  u8,
    pub dst_len: u8,
    pub src_len: u8,
    pub tos:     u8,
    pub table:   u8,
    pub res1:    u8,
    pub res2:    u8,
    pub action:  u8,
    pub flags:   u32,
}

impl FibRuleHdr {
    pub const SIZE: usize = 12;

    /// # C: O(1)
    pub fn write_to(&self, buf: &mut [u8]) {
        buf[0] = self.family;
        buf[1] = self.dst_len;
        buf[2] = self.src_len;
        buf[3] = self.tos;
        buf[4] = self.table;
        buf[5] = self.res1;
        buf[6] = self.res2;
        buf[7] = self.action;
        buf[8..12].copy_from_slice(&self.flags.to_ne_bytes());
    }
}

/// Build one RTM_NEWRULE reply.
/// # C: O(N attrs)
pub(crate) fn build_newrule_reply(seq: u32, pid: u32, family: u8, priority: u32, table: u8) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::with_capacity(32);
    let frh = FibRuleHdr {
        family,
        table,
        action: FR_ACT_TO_TBL,
        ..FibRuleHdr::default()
    };
    let mut frh_buf = [0u8; FibRuleHdr::SIZE];
    frh.write_to(&mut frh_buf);
    body.extend_from_slice(&frh_buf);
    put_nlattr_u32(&mut body, fra::FRA_PRIORITY, priority);
    put_nlattr_u32(&mut body, fra::FRA_TABLE, table as u32);

    let total = Nlmsghdr::SIZE + body.len();
    let hdr = Nlmsghdr {
        nlmsg_len: total as u32,
        nlmsg_type: RTM_NEWRULE,
        nlmsg_flags: flags::NLM_F_MULTI,
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

/// RTM_GETRULE dump of the built-in IPv4/IPv6 policy rules.
/// # C: O(1)
pub fn handle_getrule(req: &Nlmsghdr, full_msg: &[u8]) -> Vec<u8> {
    let family = match full_msg.get(Nlmsghdr::SIZE).copied().unwrap_or(AF_INET) {
        AF_INET6 => AF_INET6,
        _ => AF_INET,
    };
    let mut reply: Vec<u8> = Vec::with_capacity(128);
    for (priority, table) in [
        (0, RT_TABLE_LOCAL),
        (32766, RT_TABLE_MAIN),
        (32767, RT_TABLE_DEFAULT),
    ] {
        reply.extend_from_slice(&build_newrule_reply(req.nlmsg_seq, req.nlmsg_pid, family, priority, table));
    }
    reply.extend_from_slice(&done_multi(req.nlmsg_seq, req.nlmsg_pid));
    reply
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn fib_rule_hdr_size_matches_linux() {
        assert_eq!(FibRuleHdr::SIZE, 12);
    }

    #[test]
    fn build_newrule_reply_has_linux_defaults() {
        let bytes = build_newrule_reply(9, 42, AF_INET, 32766, RT_TABLE_MAIN);
        let hdr = Nlmsghdr::parse(&bytes).unwrap();
        assert_eq!(hdr.nlmsg_type, RTM_NEWRULE);
        assert_eq!(hdr.nlmsg_flags & flags::NLM_F_MULTI, flags::NLM_F_MULTI);
        assert_eq!((hdr.nlmsg_seq, hdr.nlmsg_pid), (9, 42));
        assert_eq!(bytes[Nlmsghdr::SIZE], AF_INET);
        assert_eq!(bytes[Nlmsghdr::SIZE + 4], RT_TABLE_MAIN);
        assert_eq!(bytes[Nlmsghdr::SIZE + 7], FR_ACT_TO_TBL);
    }

    #[test]
    fn getrule_dump_has_three_rules_and_done() {
        let req = Nlmsghdr {
            nlmsg_len: Nlmsghdr::SIZE as u32,
            nlmsg_type: crate::rtnetlink::RTM_GETRULE,
            nlmsg_flags: flags::NLM_F_DUMP,
            nlmsg_seq: 77,
            nlmsg_pid: 88,
        };
        let mut msg = vec![0u8; Nlmsghdr::SIZE + FibRuleHdr::SIZE];
        req.write_to(&mut msg[..Nlmsghdr::SIZE]);
        msg[Nlmsghdr::SIZE] = AF_INET;
        let reply = handle_getrule(&req, &msg);
        let mut off = 0;
        let mut rules = 0;
        loop {
            let hdr = Nlmsghdr::parse(&reply[off..]).unwrap();
            if hdr.nlmsg_type == crate::msg::NLMSG_DONE {
                assert_eq!((hdr.nlmsg_seq, hdr.nlmsg_pid), (77, 88));
                break;
            }
            assert_eq!(hdr.nlmsg_type, RTM_NEWRULE);
            rules += 1;
            off += crate::nlmsg_align(hdr.nlmsg_len as usize);
        }
        assert_eq!(rules, 3);
    }

    #[test]
    fn getrule_dump_honors_ipv6_family() {
        let req = Nlmsghdr {
            nlmsg_len: (Nlmsghdr::SIZE + FibRuleHdr::SIZE) as u32,
            nlmsg_type: crate::rtnetlink::RTM_GETRULE,
            nlmsg_flags: flags::NLM_F_DUMP,
            nlmsg_seq: 1,
            nlmsg_pid: 2,
        };
        let mut msg = vec![0u8; Nlmsghdr::SIZE + FibRuleHdr::SIZE];
        req.write_to(&mut msg[..Nlmsghdr::SIZE]);
        msg[Nlmsghdr::SIZE] = AF_INET6;
        let reply = handle_getrule(&req, &msg);
        assert_eq!(reply[Nlmsghdr::SIZE], AF_INET6);
    }
}
