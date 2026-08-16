// The kind is actually registered and resolvable by the string userspace
// sends. Without this the whole crate is machinery no message can reach.


use crate::link_kind::init;
use crate::uapi::VLAN_LINK_KIND;

#[test]
fn the_kind_registers_under_the_name_userspace_sends() {
    assert!(init(), "first registration succeeds");
    assert_eq!(VLAN_LINK_KIND, "vlan");
    let ops = rtnl_link::lookup(VLAN_LINK_KIND).expect("resolvable by its kind string");
    assert_eq!(ops.kind(), VLAN_LINK_KIND);
    assert!(ops.needs_lower(), "a VLAN interface must name the interface it tags");
    // A second registration is refused rather than shadowing the first.
    assert!(!init());
    assert!(rtnl_link::kinds().contains(&VLAN_LINK_KIND));
}
