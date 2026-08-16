extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;

use net::addr::{MacAddr, NetIfaceId};
use net::netdev::NetDev;
use syscall::errno::Errno;

use super::support::{eth_frame, plain_caps, FakeDev, REAL_MAC};
use crate::dev::VlanDev;
use crate::registry::{Demux, VlanKey, VlanTable};
use crate::tci::{encode, insert};
use crate::uapi::{ETH_P_8021AD, ETH_P_8021Q};

const DST: [u8; 6] = [0x02, 1, 1, 1, 1, 1];
const IPV4: u16 = 0x0800;
const ETH0: NetIfaceId = NetIfaceId(1);
const ETH1: NetIfaceId = NetIfaceId(2);

fn dev_on(real: &Arc<FakeDev>, real_id: NetIfaceId, vlan_id: u16, proto: u16) -> Arc<VlanDev> {
    let dev = Arc::new(VlanDev::new(String::from("vlan"), vlan_id, proto, real_id,
                                    real.clone() as Arc<dyn NetDev>, plain_caps(1500),
                                    MacAddr::ZERO));
    dev.admin_up_changed(true);
    dev
}

#[test]
fn one_tag_is_claimed_once() {
    let real = FakeDev::new("eth0", REAL_MAC, 1500);
    let table = VlanTable::new();
    assert!(table.insert(NetIfaceId(10), dev_on(&real, ETH0, 5, ETH_P_8021Q)).is_ok());
    assert_eq!(table.insert(NetIfaceId(11), dev_on(&real, ETH0, 5, ETH_P_8021Q)),
               Err(Errno::Eexist));
}

#[test]
fn the_same_identifier_on_another_lower_interface_is_a_different_tag() {
    let real = FakeDev::new("eth0", REAL_MAC, 1500);
    let table = VlanTable::new();
    assert!(table.insert(NetIfaceId(10), dev_on(&real, ETH0, 5, ETH_P_8021Q)).is_ok());
    assert!(table.insert(NetIfaceId(11), dev_on(&real, ETH1, 5, ETH_P_8021Q)).is_ok());
    assert!(table.insert(NetIfaceId(12), dev_on(&real, ETH0, 5, ETH_P_8021AD)).is_ok(),
            "a service tag is not a customer tag");
}

#[test]
fn releasing_a_tag_frees_it() {
    let real = FakeDev::new("eth0", REAL_MAC, 1500);
    let table = VlanTable::new();
    table.insert(NetIfaceId(10), dev_on(&real, ETH0, 5, ETH_P_8021Q)).unwrap();
    assert!(table.contains(&VlanKey::new(ETH0, ETH_P_8021Q, 5)));
    assert!(table.remove(NetIfaceId(10)).is_some());
    assert!(!table.contains(&VlanKey::new(ETH0, ETH_P_8021Q, 5)));
    assert!(table.insert(NetIfaceId(11), dev_on(&real, ETH0, 5, ETH_P_8021Q)).is_ok());
}

#[test]
fn every_interface_on_one_lower_interface_is_findable() {
    let real = FakeDev::new("eth0", REAL_MAC, 1500);
    let table = VlanTable::new();
    table.insert(NetIfaceId(10), dev_on(&real, ETH0, 5, ETH_P_8021Q)).unwrap();
    table.insert(NetIfaceId(11), dev_on(&real, ETH0, 6, ETH_P_8021Q)).unwrap();
    table.insert(NetIfaceId(12), dev_on(&real, ETH1, 7, ETH_P_8021Q)).unwrap();
    let mut ids: alloc::vec::Vec<u32> =
        table.on_real(ETH0).iter().map(|(i, _)| i.raw()).collect();
    ids.sort_unstable();
    assert_eq!(ids, alloc::vec![10u32, 11]);
}

#[test]
fn a_received_frame_reaches_the_interface_that_claims_its_tag() {
    let real = FakeDev::new("eth0", REAL_MAC, 1500);
    let table = VlanTable::new();
    let five = dev_on(&real, ETH0, 5, ETH_P_8021Q);
    let six = dev_on(&real, ETH0, 6, ETH_P_8021Q);
    five.with_maps(|m| m.set_ingress(50, 1));
    six.with_maps(|m| m.set_ingress(60, 1));
    table.insert(NetIfaceId(10), five).unwrap();
    table.insert(NetIfaceId(11), six).unwrap();

    let original = eth_frame(DST, REAL_MAC, IPV4, 20);
    let tagged = insert(&original, ETH_P_8021Q, encode(6, 1)).unwrap();
    match table.demux(ETH0, &tagged) {
        Demux::Deliver { iface, frame, priority } => {
            assert_eq!(iface, NetIfaceId(11), "identifier 6, not 5");
            assert_eq!(priority, 60, "and its own ingress map");
            assert_eq!(frame, original);
        }
        other => panic!("expected delivery, got {other:?}"),
    }
}

#[test]
fn a_tag_nobody_claims_is_not_ours() {
    let real = FakeDev::new("eth0", REAL_MAC, 1500);
    let table = VlanTable::new();
    table.insert(NetIfaceId(10), dev_on(&real, ETH0, 5, ETH_P_8021Q)).unwrap();
    let tagged = insert(&eth_frame(DST, REAL_MAC, IPV4, 8), ETH_P_8021Q, encode(9, 0)).unwrap();
    assert_eq!(table.demux(ETH0, &tagged), Demux::NotOurs);
}

#[test]
fn a_tag_on_another_lower_interface_is_not_ours() {
    let real = FakeDev::new("eth0", REAL_MAC, 1500);
    let table = VlanTable::new();
    table.insert(NetIfaceId(10), dev_on(&real, ETH0, 5, ETH_P_8021Q)).unwrap();
    let tagged = insert(&eth_frame(DST, REAL_MAC, IPV4, 8), ETH_P_8021Q, encode(5, 0)).unwrap();
    assert_eq!(table.demux(ETH1, &tagged), Demux::NotOurs);
}

#[test]
fn a_tag_of_the_other_protocol_is_not_ours() {
    let real = FakeDev::new("eth0", REAL_MAC, 1500);
    let table = VlanTable::new();
    table.insert(NetIfaceId(10), dev_on(&real, ETH0, 5, ETH_P_8021Q)).unwrap();
    let tagged = insert(&eth_frame(DST, REAL_MAC, IPV4, 8), ETH_P_8021AD, encode(5, 0)).unwrap();
    assert_eq!(table.demux(ETH0, &tagged), Demux::NotOurs);
}

#[test]
fn an_untagged_frame_is_not_ours() {
    let real = FakeDev::new("eth0", REAL_MAC, 1500);
    let table = VlanTable::new();
    table.insert(NetIfaceId(10), dev_on(&real, ETH0, 5, ETH_P_8021Q)).unwrap();
    assert_eq!(table.demux(ETH0, &eth_frame(DST, REAL_MAC, IPV4, 40)), Demux::NotOurs);
    assert_eq!(table.demux(ETH0, &[0u8; 4]), Demux::NotOurs);
}

#[test]
fn a_down_interface_takes_the_frame_and_drops_it() {
    let real = FakeDev::new("eth0", REAL_MAC, 1500);
    let table = VlanTable::new();
    let dev = dev_on(&real, ETH0, 5, ETH_P_8021Q);
    dev.admin_up_changed(false);
    table.insert(NetIfaceId(10), dev).unwrap();
    let tagged = insert(&eth_frame(DST, REAL_MAC, IPV4, 8), ETH_P_8021Q, encode(5, 0)).unwrap();
    assert_eq!(table.demux(ETH0, &tagged), Demux::Dropped);
}

#[test]
fn an_interface_is_reachable_by_its_handle() {
    let real = FakeDev::new("eth0", REAL_MAC, 1500);
    let table = VlanTable::new();
    table.insert(NetIfaceId(10), dev_on(&real, ETH0, 5, ETH_P_8021Q)).unwrap();
    assert_eq!(table.by_iface(NetIfaceId(10)).unwrap().vlan_id(), 5);
    assert!(table.by_iface(NetIfaceId(99)).is_none());
}
