//! Namespace-aware rtnetlink link queries.

extern crate alloc;

use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::Nlmsghdr;

use super::dumps::{build_newlink_reply, done_multi};
use super::iface::ifaces_snapshot_in;
use super::uapi::{ifla, Ifinfomsg};

/// Handle an RTM_GETLINK request carrying no body — the dump form.
/// # C: O(N ifaces)
pub fn handle_getlink(req: &Nlmsghdr) -> Vec<u8> {
    let mut only_header = [0u8; Nlmsghdr::SIZE];
    req.write_to(&mut only_header);
    handle_getlink_in(net::netdev::current_net_ns(), req, &only_header, false)
}

/// Handle RTM_GETLINK in the socket's captured network namespace.
/// # C: O(N ifaces)
pub fn handle_getlink_in(ns: u64, req: &Nlmsghdr, full_msg: &[u8], strict: bool) -> Vec<u8> {
    handle_getlink_with_access(ns, req, full_msg, strict, |_| true)
}

/// Handle RTM_GETLINK with target-namespace access checking.
/// # C: O(N ifaces)
pub(crate) fn handle_getlink_with_access<F>(
    ns: u64, req: &Nlmsghdr, full_msg: &[u8], strict: bool, target_access: F,
) -> Vec<u8>
where
    F: Fn(&network_namespace::NetworkNamespaceRef) -> bool,
{
    if !super::dump_req::is_dump(req) {
        let target_nsid = super::dump_req::link_target_nsid(full_msg);
        let (target_ns, reply_nsid) = match target_namespace(ns, target_nsid, &target_access) {
            Ok(target) => target, Err(e) => return super::ack::build_ack(req, -(e.as_i32())),
        };
        return getlink_one(target_ns, req, full_msg, reply_nsid);
    }
    let target_nsid = match super::dump_req::validate_link_dump(strict, full_msg) {
        super::dump_req::LinkDump::All => None,
        super::dump_req::LinkDump::Target(nsid) => Some(nsid),
        super::dump_req::LinkDump::Err(e) => return super::ack::build_ack(req, -(e.as_i32())),
    };
    let (target_ns, reply_nsid) = match target_namespace(ns, target_nsid, &target_access) {
        Ok(target) => target, Err(e) => return super::ack::build_ack(req, -(e.as_i32())),
    };
    let entries = ifaces_snapshot_in(target_ns);
    let mut reply: Vec<u8> = Vec::with_capacity(256);
    for (id, name, mac, broadcast, mtu, is_lo, flags, stats) in entries.iter() {
        reply.extend_from_slice(&build_newlink_reply(
            req.nlmsg_seq, req.nlmsg_pid, *id as i32, name, *mac,
            &broadcast.bytes[..broadcast.len as usize], *mtu, *is_lo, *flags, *stats, true, reply_nsid,
        ));
    }
    reply.extend_from_slice(&done_multi(req.nlmsg_seq, req.nlmsg_pid));
    reply
}

fn target_namespace<F>(ns: u64, target_nsid: Option<i32>, target_access: &F) -> Result<(u64, Option<i32>), Errno>
where
    F: Fn(&network_namespace::NetworkNamespaceRef) -> bool,
{
    let Some(nsid) = target_nsid else { return Ok((ns, None)); };
    let caller = network_namespace::lookup_u64(ns).ok_or(Errno::Einval)?;
    let target = caller.peer_by_id(nsid).ok_or(Errno::Einval)?;
    if !target_access(&target) { return Err(Errno::Eacces); }
    Ok((target.id().as_u64(), Some(nsid)))
}

fn getlink_one(ns: u64, req: &Nlmsghdr, full_msg: &[u8], target_nsid: Option<i32>) -> Vec<u8> {
    let off = Nlmsghdr::SIZE;
    if full_msg.len() < off + Ifinfomsg::SIZE { return super::ack::build_ack(req, -(Errno::Einval.as_i32())); }
    let want_index = i32::from_ne_bytes(full_msg[off + 4..off + 8].try_into().unwrap());
    let want_name = ifname_attr(&full_msg[off + Ifinfomsg::SIZE..]);
    let entries = ifaces_snapshot_in(ns);
    let found = entries.iter().find(|(id, name, _, _, _, _, _, _)| {
        (want_index > 0 && *id as i32 == want_index) || want_name.as_deref().is_some_and(|w| w == name.as_str())
    });
    let Some((id, name, mac, broadcast, mtu, is_lo, flags, stats)) = found
        else { return super::ack::build_ack(req, -(Errno::Enodev.as_i32())) };
    build_newlink_reply(req.nlmsg_seq, req.nlmsg_pid, *id as i32, name, *mac,
        &broadcast.bytes[..broadcast.len as usize], *mtu, *is_lo, *flags, *stats, false, target_nsid)
}

fn ifname_attr(mut attrs: &[u8]) -> Option<alloc::string::String> {
    while attrs.len() >= 4 {
        let len = u16::from_ne_bytes([attrs[0], attrs[1]]) as usize;
        let kind = u16::from_ne_bytes([attrs[2], attrs[3]]) & 0x3fff;
        if len < 4 || len > attrs.len() { return None; }
        if kind == ifla::IFLA_IFNAME {
            let body = &attrs[4..len];
            let end = body.iter().position(|b| *b == 0).unwrap_or(body.len());
            return core::str::from_utf8(&body[..end]).ok().map(alloc::string::String::from);
        }
        let next = (len + 3) & !3;
        if next > attrs.len() { return None; }
        attrs = &attrs[next..];
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(flags: u16, ifindex: i32, name: Option<&str>) -> (Nlmsghdr, alloc::vec::Vec<u8>) {
        let mut body = alloc::vec![0u8; Ifinfomsg::SIZE];
        body[4..8].copy_from_slice(&ifindex.to_ne_bytes());
        if let Some(n) = name {
            let len = 4 + n.len() + 1;
            body.extend_from_slice(&(len as u16).to_ne_bytes());
            body.extend_from_slice(&ifla::IFLA_IFNAME.to_ne_bytes());
            body.extend_from_slice(n.as_bytes());
            body.push(0);
            while body.len() % 4 != 0 { body.push(0); }
        }
        let hdr = Nlmsghdr {
            nlmsg_len: (Nlmsghdr::SIZE + body.len()) as u32,
            nlmsg_type: super::super::RTM_GETLINK,
            nlmsg_flags: crate::wire::flags::NLM_F_REQUEST | flags,
            nlmsg_seq: 5, nlmsg_pid: 9,
        };
        let mut msg = alloc::vec![0u8; Nlmsghdr::SIZE];
        hdr.write_to(&mut msg[..]);
        msg.extend_from_slice(&body);
        (hdr, msg)
    }

    #[test]
    fn the_interface_name_attribute_is_parsed() {
        let (_h, msg) = request(0, 0, Some("eth0"));
        assert_eq!(ifname_attr(&msg[Nlmsghdr::SIZE + Ifinfomsg::SIZE..]).as_deref(), Some("eth0"));
    }

    #[test]
    fn an_absent_name_attribute_reads_as_none() {
        let (_h, msg) = request(0, 2, None);
        assert_eq!(ifname_attr(&msg[Nlmsghdr::SIZE + Ifinfomsg::SIZE..]), None);
    }

    #[test]
    fn a_malformed_attribute_header_is_refused() {
        assert_eq!(ifname_attr(&[3, 0, 3, 0]), None);
        assert_eq!(ifname_attr(&[255, 255, 3, 0]), None);
    }

    #[test]
    fn a_single_get_for_an_unknown_device_reports_enodev() {
        let (hdr, msg) = request(0, 0, Some("nosuchdev0"));
        let reply = getlink_one(0, &hdr, &msg, None);
        assert_eq!(u16::from_ne_bytes([reply[4], reply[5]]), crate::msg::NLMSG_ERROR);
        assert_eq!(i32::from_ne_bytes([reply[16], reply[17], reply[18], reply[19]]), -19);
    }

    #[test]
    fn a_truncated_single_get_is_einval() {
        let (hdr, _msg) = request(0, 1, None);
        let short = alloc::vec![0u8; Nlmsghdr::SIZE];
        let reply = getlink_one(0, &hdr, &short, None);
        assert_eq!(i32::from_ne_bytes([reply[16], reply[17], reply[18], reply[19]]), -22);
    }
}
