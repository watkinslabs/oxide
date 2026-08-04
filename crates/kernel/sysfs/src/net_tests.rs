use alloc::string::String;
use alloc::sync::Arc;

use net::{MacAddr, NamespaceDropAction, NetDev, NetResult, Pkt};
use netlink::{proto, NetlinkSocket};

use super::*;

struct TestNetDev;
impl NetDev for TestNetDev {
    fn name(&self) -> &str { "testnet0" }
    fn mac(&self) -> MacAddr { MacAddr::ZERO }
    fn mtu(&self) -> u32 { 1500 }
    fn retire_namespace(&self) {}
    fn namespace_drop_action(&self) -> NamespaceDropAction {
        NamespaceDropAction::MoveToInitial
    }
    fn xmit(&self, _pkt: Pkt) -> NetResult<()> { Ok(()) }
}

fn has_entry(msg: &[u8], needle: &[u8]) -> bool {
    msg.split(|b| *b == 0).any(|entry| entry == needle)
}

#[test]
fn net_uevent_replay_includes_interface_and_ifindex() {
    let listener = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT, &network_namespace::initial()));
    listener.set_group_mask(1);
    netlink::register_uevent_listener(&listener);

    let dir = make_net_iface_inode(String::from("testnet0"), Arc::new(TestNetDev), None);
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
    // Physical/ethernet NIC emits NO DEVTYPE (Linux: only virtual net devices do).
    assert!(!has_entry(&msg, b"DEVTYPE="), "no empty DEVTYPE for a physical NIC");
    assert!(has_entry(&msg, b"INTERFACE=testnet0"));
    assert!(has_entry(&msg, b"IFINDEX=0"));
}

// The iface dir must carry a `subsystem` symlink → /sys/class/net (Linux
// `net_class`). Without it `udevadm trigger` cannot classify the device as
// SUBSYSTEM=net, never writes its uevent, and NetworkManager leaves it
// unmanaged (the N22 no-DHCP root cause).
#[test]
fn net_iface_dir_exposes_subsystem_symlink() {
    let dir = make_net_iface_inode(String::from("testnet0"), Arc::new(TestNetDev), None);
    let sub = dir.lookup("subsystem").expect("subsystem symlink present");
    assert_eq!(sub.readlink().expect("readlink"), b"../../../../class/net".to_vec());
    // The uevent trigger must still be present alongside it.
    assert!(dir.lookup("uevent").is_ok(), "uevent attr still present");
}

#[test]
fn physical_net_iface_uses_its_driver_model_parent() {
    let root = Arc::new(drv::Device::new(
        "pci", String::from("0000:00:17.0"), 0x1af4, 0x1041, 0x020000));
    drv::try_device_add(Arc::clone(&root)).expect("pci parent registration");
    let transport = Arc::new(drv::Device::new(
        "virtio", String::from("virtio77"), 0x1af4, 1, 0)
        .with_parent("pci", String::from("0000:00:17.0")));
    drv::try_device_add_with_parent(Arc::clone(&transport), &root)
        .expect("virtio transport registration");

    let dir = make_net_iface_inode(
        String::from("eth77"), Arc::new(TestNetDev), Some(Arc::clone(&transport)));
    assert_eq!(
        crate::net_class::class_target("eth77", Some(&transport)).expect("physical class target"),
        "../../devices/pci0000:00/0000:00:17.0/virtio77/net/eth77",
    );
    let device = dir.lookup("device").expect("physical device link");
    assert_eq!(device.readlink().expect("device target"), b"../..".to_vec());
    assert_eq!(dir.lookup("driver").err(), Some(VfsError::Enoent),
        "the interface points at the transport; its driver remains there");

    let listener = Arc::new(NetlinkSocket::new(proto::NETLINK_KOBJECT_UEVENT,
        &network_namespace::initial()));
    listener.set_group_mask(1);
    netlink::register_uevent_listener(&listener);
    let uevent = dir.lookup("uevent").expect("physical uevent attr");
    assert_eq!(uevent.write(0, b"change\n"), Ok("change\n".len()));
    let expected = b"DEVPATH=/devices/pci0000:00/0000:00:17.0/virtio77/net/eth77";
    assert!((0..16).filter_map(|_| listener.dequeue()).any(|(msg, _)| has_entry(&msg, expected)),
        "physical net uevent uses the driver-model path");

    drv::device_del(&transport);
    drv::device_del(&root);
}
