// Shared fixtures. The family registry and the multicast listener list are
// process-global exactly as they are in the kernel, so tests take distinct
// family names (hence distinct group ids) instead of resetting shared state.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use std::sync::Once;

use network_namespace::NetworkNamespaceRef;

use crate::genetlink::{self, family, mcast, uapi};
use crate::netlink_socket::NetlinkSocket;
use crate::proto;
use crate::Nlmsghdr;

static BOOT: Once = Once::new();
/// Per-test family-name counter.
static NEXT_FAMILY: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Bring the controller and every in-kernel family up once per test process.
pub(super) fn boot() { BOOT.call_once(genetlink::init); }

/// A `NETLINK_GENERIC` socket registered for multicast in `ns`.
pub(super) fn genl_socket(ns: &NetworkNamespaceRef) -> Arc<NetlinkSocket> {
    let sock = Arc::new(NetlinkSocket::new(proto::NETLINK_GENERIC, ns));
    mcast::register_genl_listener(&sock);
    sock
}

/// A socket subscribed to one group id.
pub(super) fn subscriber(ns: &NetworkNamespaceRef, group_id: u32) -> Arc<NetlinkSocket> {
    let sock = genl_socket(ns);
    sock.add_membership(group_id).unwrap();
    sock
}

/// Register a throwaway family whose name (and therefore group ids) cannot
/// collide with another test's.
pub(super) fn register_test_family(
    tag: &str, ops: Vec<family::GenlOp>, groups: usize,
) -> family::GenlFamily {
    let _serial = crate::test_serial::genl();
    register_unserialised(tag, ops, groups)
}

/// Registration without the serialisation guard, for a test that already holds
/// it across a wider window.
pub(super) fn register_unserialised(
    tag: &str, ops: Vec<family::GenlOp>, groups: usize,
) -> family::GenlFamily {
    boot();
    // Family names are capped at `GENL_NAMSIZ - 1`; a per-test counter keeps
    // them unique inside that budget.
    let n = NEXT_FAMILY.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let mut name = alloc::format!("t{}-{}", n, tag);
    name.truncate(uapi::GENL_NAMSIZ - 1);
    let name: &'static str = String::leak(name);
    let mcgrps: Vec<&'static str> = (0..groups)
        .map(|i| &*String::leak(alloc::format!("g{}", i)))
        .collect();
    let id = family::register_family(family::GenlFamilySpec {
        name, version: 1, hdrsize: 0, maxattr: 4, ops, mcgrps,
        netnsok: true, resv_start_op: 0,
    }).unwrap();
    family::find_by_id(id).unwrap()
}

/// One queued datagram's payload, dropping the source port the queue pairs
/// with it.
pub(super) fn recv(sock: &NetlinkSocket) -> Option<Vec<u8>> {
    sock.dequeue().map(|(payload, _src)| payload)
}

/// Build a request: `nlmsghdr` + `genlmsghdr` + attribute bytes.
pub(super) fn request(family_id: u16, cmd: u8, flags: u16, seq: u32, attrs: &[u8]) -> Vec<u8> {
    let mut out = crate::genetlink::message::start(0, seq, family_id, 1, flags, cmd);
    out.extend_from_slice(attrs);
    crate::genetlink::message::end(&mut out, 0);
    out
}

/// Full-permission credentials.
pub(super) fn root() -> genetlink::GenlCred {
    genetlink::GenlCred { init_ns_net_admin: true, sock_ns_net_admin: true }
}

/// Credentials holding no capability at all.
pub(super) fn unprivileged() -> genetlink::GenlCred { genetlink::GenlCred::default() }

/// The errno an `NLMSG_ERROR` reply carries, or `None` when the reply is not
/// one. Zero is an acknowledgement, not a failure.
pub(super) fn reply_errno(reply: &[u8]) -> Option<i32> {
    let hdr = Nlmsghdr::parse(reply)?;
    if hdr.nlmsg_type != crate::msg::NLMSG_ERROR { return None; }
    let raw = reply.get(Nlmsghdr::SIZE..Nlmsghdr::SIZE + 4)?;
    Some(-i32::from_ne_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

/// The genetlink command a reply's family header carries.
pub(super) fn reply_cmd(reply: &[u8]) -> Option<u8> {
    uapi::Genlmsghdr::parse(reply.get(Nlmsghdr::SIZE..)?).map(|g| g.cmd)
}

/// Attribute bytes of a genetlink reply message.
pub(super) fn reply_attrs(reply: &[u8]) -> &[u8] {
    let hdr = Nlmsghdr::parse(reply).unwrap();
    &reply[Nlmsghdr::SIZE + uapi::Genlmsghdr::SIZE..hdr.nlmsg_len as usize]
}

/// Split a multi-part reply into its individual messages.
pub(super) fn split_messages(reply: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut off = 0;
    while let Some(hdr) = Nlmsghdr::parse(&reply[off..]) {
        let len = hdr.nlmsg_len as usize;
        if len < Nlmsghdr::SIZE || off + len > reply.len() { break; }
        out.push(&reply[off..off + len]);
        off += crate::nlmsg_align(len);
    }
    out
}
