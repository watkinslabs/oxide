use net::addr::MacAddr;
use syscall::errno::Errno;

use super::support::{plain_caps, FakeDev, REAL_MAC};
use crate::caps::*;
use crate::uapi::{ARPHRD_ETHER, VLAN_HLEN};

#[test]
fn plain_ethernet_carries_vlans() {
    assert_eq!(check_real_dev(&plain_caps(1500)), Ok(()));
}

#[test]
fn a_non_ethernet_lower_interface_is_refused() {
    let mut caps = plain_caps(1500);
    caps.hardware_type = ARPHRD_ETHER + 1;
    assert_eq!(check_real_dev(&caps), Err(Errno::Eopnotsupp));
}

#[test]
fn an_interface_that_cannot_carry_tags_is_refused() {
    let mut caps = plain_caps(1500);
    caps.vlan_challenged = true;
    assert_eq!(check_real_dev(&caps), Err(Errno::Eopnotsupp));
}

#[test]
fn the_ceiling_is_the_lower_interfaces_own_size() {
    assert_eq!(max_mtu(&plain_caps(1500)), 1500);
    assert_eq!(max_mtu(&plain_caps(9000)), 9000);
}

#[test]
fn an_interface_spending_the_tag_bytes_lowers_the_ceiling() {
    let mut caps = plain_caps(1500);
    caps.reduces_vlan_mtu = true;
    assert_eq!(max_mtu(&caps), 1500 - VLAN_HLEN as u32);
}

#[test]
fn a_size_above_the_ceiling_is_out_of_range() {
    let caps = plain_caps(1500);
    assert_eq!(check_mtu(&caps, 1500), Ok(1500));
    assert_eq!(check_mtu(&caps, 1501), Err(Errno::Erange));
    assert_eq!(check_mtu(&caps, 68), Ok(68));
}

#[test]
fn the_address_comes_from_below_when_none_was_asked_for() {
    let caps = plain_caps(1500);
    assert_eq!(inherit_mac(MacAddr::ZERO, &caps), MacAddr(REAL_MAC));
    let own = MacAddr([0x02, 9, 9, 9, 9, 9]);
    assert_eq!(inherit_mac(own, &caps), own);
}

#[test]
fn properties_are_read_from_the_live_interface() {
    let dev = FakeDev::new("eth0", REAL_MAC, 9000);
    let caps = RealDevCaps::from_netdev(dev.as_ref());
    assert_eq!(caps.mtu, 9000);
    assert_eq!(caps.mac, MacAddr(REAL_MAC));
    assert_eq!(caps.hardware_type, ARPHRD_ETHER);
    assert!(!caps.hw_tag_insert, "no driver here inserts tags itself");
}
