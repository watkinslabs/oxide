use core::sync::atomic::{AtomicU32, Ordering};
use alloc::vec;

use rtnl_link::{LinkKindOps, LinkMsg};
use syscall::errno::Errno;

use super::*;

static NEW_CALLS: AtomicU32 = AtomicU32::new(0);
static DEL_CALLS: AtomicU32 = AtomicU32::new(0);

struct NewKind;
struct DelKind;
static NEW_KIND: NewKind = NewKind;
static DEL_KIND: DelKind = DelKind;

impl LinkKindOps for NewKind {
    fn kind(&self) -> &'static str { "dispatch-new" }
    fn validate(&self, _msg: &LinkMsg<'_>) -> Result<(), Errno> { Ok(()) }
    fn newlink(&self, _msg: &LinkMsg<'_>) -> Result<u32, Errno> {
        NEW_CALLS.fetch_add(1, Ordering::SeqCst);
        Ok(77)
    }
    fn changelink(&self, _ifindex: u32, _msg: &LinkMsg<'_>) -> Result<(), Errno> { Ok(()) }
    fn dellink(&self, _ifindex: u32) -> Result<(), Errno> {
        DEL_CALLS.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn owns(&self, _ifindex: u32) -> bool { false }
}

impl LinkKindOps for DelKind {
    fn kind(&self) -> &'static str { "dispatch-del" }
    fn validate(&self, _msg: &LinkMsg<'_>) -> Result<(), Errno> { Ok(()) }
    fn newlink(&self, _msg: &LinkMsg<'_>) -> Result<u32, Errno> { Ok(78) }
    fn changelink(&self, _ifindex: u32, _msg: &LinkMsg<'_>) -> Result<(), Errno> { Ok(()) }
    fn dellink(&self, _ifindex: u32) -> Result<(), Errno> {
        DEL_CALLS.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn owns(&self, ifindex: u32) -> bool { ifindex == 77 }
}

fn frame(typ: u16, index: i32, kind: &str) -> (Nlmsghdr, Vec<u8>) {
    let mut body = Vec::new();
    body.extend_from_slice(&[0, 0, 0, 0]);
    body.extend_from_slice(&index.to_ne_bytes());
    body.extend_from_slice(&0u32.to_ne_bytes());
    body.extend_from_slice(&0u32.to_ne_bytes());
    let mut ifname = b"test0".to_vec();
    ifname.push(0);
    rtnl_link::nla::put(&mut body, rtnl_link::uapi::IFLA_IFNAME, &ifname);
    let at = rtnl_link::nla::nest_start(&mut body, rtnl_link::uapi::IFLA_LINKINFO);
    let mut name = kind.as_bytes().to_vec();
    name.push(0);
    rtnl_link::nla::put(&mut body, rtnl_link::uapi::IFLA_INFO_KIND, &name);
    rtnl_link::nla::nest_end(&mut body, at);
    let hdr = Nlmsghdr { nlmsg_len: (Nlmsghdr::SIZE + body.len()) as u32,
        nlmsg_type: typ, nlmsg_flags: crate::flags::NLM_F_REQUEST,
        nlmsg_seq: 19, nlmsg_pid: 31 };
    (hdr, body)
}

fn ack_error(reply: &[u8]) -> i32 {
    let off = Nlmsghdr::SIZE;
    i32::from_ne_bytes(reply[off..off + 4].try_into().unwrap())
}

#[test]
fn newlink_reaches_the_registered_kind_instead_of_flag_mutation() {
    NEW_CALLS.store(0, Ordering::SeqCst);
    assert!(rtnl_link::register(&NEW_KIND).is_ok());
    let (hdr, body) = frame(RTM_NEWLINK, 0, "dispatch-new");
    let mut wire = vec![0u8; Nlmsghdr::SIZE];
    hdr.write_to(&mut wire);
    wire.extend_from_slice(&body);
    let reply = super::super::iface::handle_link_in(0, &hdr, &wire);
    assert_eq!(ack_error(&reply), 0);
    assert_eq!(NEW_CALLS.load(Ordering::SeqCst), 1);
}

#[test]
fn dellink_resolves_the_registered_kind_before_teardown() {
    DEL_CALLS.store(0, Ordering::SeqCst);
    assert!(rtnl_link::register(&DEL_KIND).is_ok());
    let (hdr, body) = frame(RTM_DELLINK, 77, "dispatch-del");
    let mut wire = vec![0u8; Nlmsghdr::SIZE];
    hdr.write_to(&mut wire);
    wire.extend_from_slice(&body);
    let reply = super::super::iface::handle_link_in(0, &hdr, &wire);
    assert_eq!(ack_error(&reply), 0);
    assert_eq!(DEL_CALLS.load(Ordering::SeqCst), 1);
}
