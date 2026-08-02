// What the sysfs ROOT does and does not publish.

use crate::root::sys_root;

// `/sys/subsystem` is a proposed unification that was never implemented: no
// kobject creates it, and a conforming enumerator treats its presence as the
// promise that it holds EVERY bus, class and block device in one flat
// `<name>/devices/` layout — on seeing it, such an enumerator stops scanning
// `/sys/bus`, `/sys/class` and `/sys/block` entirely.
//
// Publishing a partial one therefore SUPPRESSES the enumeration that works
// today rather than adding to it. The classification roots we do publish are
// the ones the contract actually names.
#[test]
fn the_sysfs_root_publishes_no_subsystem_unification_directory() {
    assert!(sys_root().lookup_path("subsystem").is_none(),
        "publishing /sys/subsystem tells enumerators to ignore /sys/class and /sys/bus");
}
