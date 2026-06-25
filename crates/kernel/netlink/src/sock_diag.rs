extern crate alloc;

use alloc::vec::Vec;

use crate::{flags, Nlmsghdr};

pub const SOCK_DIAG_BY_FAMILY: u16 = 20;
pub const TCPDIAG_GETSOCK: u16 = 18;

const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const REQ_V2_SIZE: usize = 56;
const INET_DIAG_MSG_SIZE: usize = 72;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct InetDiagReq {
    family: u8,
    protocol: u8,
    states: u32,
}

fn parse_req(msg: &[u8]) -> Option<InetDiagReq> {
    if msg.len() < Nlmsghdr::SIZE + REQ_V2_SIZE {
        return None;
    }
    let body = &msg[Nlmsghdr::SIZE..];
    Some(InetDiagReq {
        family: body[0],
        protocol: body[1],
        states: u32::from_ne_bytes(body[4..8].try_into().ok()?),
    })
}

fn state_matches(mask: u32, state: u8) -> bool {
    mask == 0 || (state < 32 && (mask & (1u32 << state)) != 0)
}

fn family_matches(req: u8, got: u8) -> bool {
    req == 0 || req == got
}

#[allow(dead_code)]
fn write_ip(out: &mut [u8], ip: net::IpAddr) {
    match ip {
        net::IpAddr::V4(v4) => {
            out[0..4].copy_from_slice(&v4.octets());
            out[4..16].fill(0);
        }
        net::IpAddr::V6(v6) => out[0..16].copy_from_slice(&v6.0),
    }
}

#[allow(dead_code)]
fn append_diag_msg(out: &mut Vec<u8>, req: &Nlmsghdr, row: net::stack_diag::InetDiagSnapshot) {
    let total = Nlmsghdr::SIZE + INET_DIAG_MSG_SIZE;
    let hdr = Nlmsghdr {
        nlmsg_len: total as u32,
        nlmsg_type: SOCK_DIAG_BY_FAMILY,
        nlmsg_flags: flags::NLM_F_MULTI,
        nlmsg_seq: req.nlmsg_seq,
        nlmsg_pid: req.nlmsg_pid,
    };
    let start = out.len();
    out.resize(start + total, 0);
    hdr.write_to(&mut out[start..start + Nlmsghdr::SIZE]);
    let body = &mut out[start + Nlmsghdr::SIZE..start + total];
    body[0] = row.family;
    body[1] = row.state;
    body[2] = 0;
    body[3] = 0;
    body[4..6].copy_from_slice(&row.local_port.to_be_bytes());
    body[6..8].copy_from_slice(&row.remote_port.to_be_bytes());
    write_ip(&mut body[8..24], row.local_ip);
    write_ip(&mut body[24..40], row.remote_ip);
    body[40..44].copy_from_slice(&row.ifindex.to_ne_bytes());
    body[44..48].copy_from_slice(&u32::MAX.to_ne_bytes());
    body[48..52].copy_from_slice(&u32::MAX.to_ne_bytes());
    body[56..60].copy_from_slice(&row.rqueue.to_ne_bytes());
    body[60..64].copy_from_slice(&row.wqueue.to_ne_bytes());
}

/// Handle SOCK_DIAG_BY_FAMILY / TCPDIAG_GETSOCK inet_diag requests.
/// # C: O(open inet sockets)
pub fn handle(req: &Nlmsghdr, msg: &[u8]) -> Vec<u8> {
    let Some(diag_req) = parse_req(msg) else {
        return crate::rtnetlink::done_multi(req.nlmsg_seq, req.nlmsg_pid);
    };
    let protocol = match (req.nlmsg_type, diag_req.protocol) {
        (TCPDIAG_GETSOCK, _) => IPPROTO_TCP,
        (_, IPPROTO_TCP | IPPROTO_UDP) => diag_req.protocol,
        _ => return crate::rtnetlink::done_multi(req.nlmsg_seq, req.nlmsg_pid),
    };
    let mut reply = Vec::new();
    #[cfg(target_os = "oxide-kernel")]
    {
        for row in net::sock::stack().inet_diag_snapshot(protocol) {
            if family_matches(diag_req.family, row.family) && state_matches(diag_req.states, row.state) {
                append_diag_msg(&mut reply, req, row);
            }
        }
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    {
        let _ = (diag_req, protocol, family_matches as fn(u8, u8) -> bool, state_matches as fn(u32, u8) -> bool);
    }
    reply.extend_from_slice(&crate::rtnetlink::done_multi(req.nlmsg_seq, req.nlmsg_pid));
    reply
}

#[cfg(test)]
mod tests {
    use super::*;
    use net::{IpAddr, Ipv4Addr};

    #[test]
    fn diag_msg_writes_ports_network_order() {
        let req = Nlmsghdr { nlmsg_len: 0, nlmsg_type: SOCK_DIAG_BY_FAMILY, nlmsg_flags: 0, nlmsg_seq: 9, nlmsg_pid: 7 };
        let row = net::stack_diag::InetDiagSnapshot {
            family: AF_INET,
            protocol: IPPROTO_TCP,
            state: 1,
            local_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            local_port: 0x1234,
            remote_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            remote_port: 0xabcd,
            ifindex: 3,
            rqueue: 4,
            wqueue: 5,
        };
        let mut out = Vec::new();
        append_diag_msg(&mut out, &req, row);
        assert_eq!(&out[20..22], &[0x12, 0x34]);
        assert_eq!(&out[22..24], &[0xab, 0xcd]);
        assert_eq!(&out[24..28], &[127, 0, 0, 1]);
        assert_eq!(&out[40..44], &[10, 0, 0, 2]);
    }
}
