extern crate alloc;

use alloc::vec::Vec;

use crate::Nlmsghdr;

use super::ack::build_ack;
use super::addr6_ops::{handle_deladdr6_in, handle_newaddr6_in};
use super::addr_ops::{handle_deladdr4_in, handle_newaddr4_in};
use super::uapi::{AF_INET, AF_INET6, RTM_DELADDR, RTM_NEWADDR};

type Doit = fn(u64, &Nlmsghdr, &[u8]) -> Vec<u8>;

struct Handler {
    family: u8,
    msgtype: u16,
    doit: Doit,
}

const HANDLERS: &[Handler] = &[
    Handler { family: AF_INET,  msgtype: RTM_NEWADDR, doit: handle_newaddr4_in },
    Handler { family: AF_INET,  msgtype: RTM_DELADDR, doit: handle_deladdr4_in },
    Handler { family: AF_INET6, msgtype: RTM_NEWADDR, doit: handle_newaddr6_in },
    Handler { family: AF_INET6, msgtype: RTM_DELADDR, doit: handle_deladdr6_in },
];

const EOPNOTSUPP: i32 = -(vfs::VfsError::Eopnotsupp as i32);
const AF_UNSPEC: u8 = 0;

/// Select the family-specific RTM handler, falling back to PF_UNSPEC. # C: O(N handlers)
fn lookup(family: u8, msgtype: u16) -> Option<Doit> {
    HANDLERS.iter().find(|h| h.family == family && h.msgtype == msgtype)
        .or_else(|| HANDLERS.iter().find(|h| h.family == AF_UNSPEC && h.msgtype == msgtype))
        .map(|h| h.doit)
}

/// Dispatch one family-keyed RTM request. # C: O(N handlers + handler)
fn handle_in(ns: u64, req: &Nlmsghdr, full_msg: &[u8]) -> Vec<u8> {
    let Some(family) = full_msg.get(Nlmsghdr::SIZE).copied() else {
        return build_ack(req, -(vfs::VfsError::Einval as i32));
    };
    let Some(doit) = lookup(family, req.nlmsg_type) else { return build_ack(req, EOPNOTSUPP) };
    doit(ns, req, full_msg)
}

/// Dispatch RTM_NEWADDR in the current network namespace. # C: O(N handlers + handler)
pub fn handle_newaddr(req: &Nlmsghdr, full_msg: &[u8]) -> Vec<u8> {
    handle_newaddr_in(net::netdev::current_net_ns(), req, full_msg)
}

/// Dispatch RTM_NEWADDR in the socket's network namespace. # C: O(N handlers + handler)
pub fn handle_newaddr_in(ns: u64, req: &Nlmsghdr, full_msg: &[u8]) -> Vec<u8> {
    handle_in(ns, req, full_msg)
}

/// Dispatch RTM_DELADDR in the current network namespace. # C: O(N handlers + handler)
pub fn handle_deladdr(req: &Nlmsghdr, full_msg: &[u8]) -> Vec<u8> {
    handle_deladdr_in(net::netdev::current_net_ns(), req, full_msg)
}

/// Dispatch RTM_DELADDR in the socket's network namespace. # C: O(N handlers + handler)
pub fn handle_deladdr_in(ns: u64, req: &Nlmsghdr, full_msg: &[u8]) -> Vec<u8> {
    handle_in(ns, req, full_msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::uapi::RTM_SETLINK;

    const AF_PACKET: u8 = 17;

    #[test]
    fn lookup_is_keyed_by_family_and_message_type() {
        assert!(lookup(AF_INET, RTM_NEWADDR).is_some());
        assert!(lookup(AF_INET6, RTM_NEWADDR).is_some());
        assert!(lookup(AF_INET, RTM_DELADDR).is_some());
        assert!(lookup(AF_INET6, RTM_DELADDR).is_some());
        assert!(lookup(AF_PACKET, RTM_NEWADDR).is_none());
        assert!(lookup(AF_INET, RTM_SETLINK).is_none());
    }
}
