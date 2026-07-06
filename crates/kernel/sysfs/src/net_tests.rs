use alloc::string::String;
use alloc::sync::Arc;

use net::{MacAddr, NetDev, NetResult, Pkt};
use netlink::{proto, NetlinkSocket};

use super::*;

struct TestNetDev;
impl NetDev for TestNetDev {
    fn name(&self) -> &str { "testnet0" }
    fn mac(&self) -> MacAddr { MacAddr::ZERO }
    fn mtu(&self) -> u32 { 1500 }
    fn xmit(&self, _pkt: Pkt) -> NetResult<()> { Ok(()) }
}

fn has_entry(msg: &[u8], needle: &[u8]) -> bool {
    msg.split(|b| *b == 0).any(|entry| entry == needle)
}

#[test]
fn net_uevent_replay_includes_interface_and_ifindex() {
    let listener = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT));
    listener.set_group_mask(1);
    netlink::register_uevent_listener(&listener);

    let dir = make_net_iface_inode(String::from("testnet0"), Arc::new(TestNetDev));
    let uevent = dir.lookup("uevent").expect("uevent attr");
    assert_eq!(uevent.write(0, b"change\n"), Ok("change\n".len()));

    let mut found = None;
    for _ in 0..16 {
        let Some((msg, _src)) = listener.dequeue() else { break; };
        if has_entry(&msg, b"DEVPATH=/devices/virtual/net/testnet0") {
            found = Some(msg);
            break;
        }
    }
    let msg = found.expect("net uevent delivered");
    assert!(has_entry(&msg, b"ACTION=change"));
    assert!(has_entry(&msg, b"SUBSYSTEM=net"));
    assert!(has_entry(&msg, b"DEVTYPE="));
    assert!(has_entry(&msg, b"INTERFACE=testnet0"));
    assert!(has_entry(&msg, b"IFINDEX=0"));
}
