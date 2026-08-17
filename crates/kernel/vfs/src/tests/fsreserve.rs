//! The reserved-pool probe answers only what an installer told it.
//!
//! One test, not three: the probe is process-wide state, so separate tests
//! would race each other's install and clear under the default parallel runner.

use super::*;

fn probe(res_gid: u32) -> ReservedCaller {
    ReservedCaller { fsuid: 4242, in_res_group: res_gid == 77, cap_sys_resource: true }
}

#[test]
fn the_probe_is_the_only_source_of_a_reserved_caller() {
    clear_reserved_caller_hook();
    assert_eq!(reserved_caller(0), None, "no probe means no task to ask");

    set_reserved_caller_hook(probe);
    let c = reserved_caller(77).expect("probe installed");
    assert_eq!(c.fsuid, 4242);
    assert!(c.in_res_group, "asked about the group the probe recognises");
    assert!(c.cap_sys_resource);

    let other = reserved_caller(78).expect("probe installed");
    assert!(!other.in_res_group, "the group under test reaches the probe");

    clear_reserved_caller_hook();
    assert_eq!(reserved_caller(77), None, "clearing returns to kernel context");
}
