// The bond kind is registered and resolvable, so `ip link add bond0 type bond`
// has somewhere to land. Without this the option table, the modes and the
// monitors are machinery no message can reach.

use rtnl_link::LinkKindOps;

use crate::link_kind::{init, BOND_LINK_KIND_OPS};
use crate::uapi::BOND_LINK_KIND;

#[test]
fn the_kind_registers_under_the_name_userspace_sends() {
    assert!(init(), "first registration succeeds");
    assert_eq!(BOND_LINK_KIND, "bond");
    let ops = rtnl_link::lookup(BOND_LINK_KIND).expect("resolvable by its kind string");
    assert_eq!(ops.kind(), BOND_LINK_KIND);
    assert!(!ops.needs_lower(), "a bond is built empty and enslaved afterwards");
    assert!(!init(), "a second registration must not shadow the first");
    assert_eq!(BOND_LINK_KIND_OPS.kind(), BOND_LINK_KIND);
}
