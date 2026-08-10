// `/proc/device-tree` — the older userspace ABI for the unflattened device
// tree. It is a SYMLINK to where sysfs publishes the tree, never a second copy
// of it: one tree, two names, so the two can never disagree about what this
// machine looks like.
//
// The entry exists only on a machine that retained a device tree. A dangling
// symlink would be worse than nothing — every tool that probes for the path
// would conclude the platform is device-tree based and then fail reading it.

use fdt::uapi::{OF_PROC_NAME, OF_SYSFS_BASE};

/// Name of the `/proc` entry.
pub const PROC_DEVICE_TREE: &str = OF_PROC_NAME;

/// Target of the `/proc/device-tree` symlink, or `None` when no device tree was
/// retained — in which case `/proc` must not carry the entry at all.
/// # C: O(1)
pub fn devicetree_link_target(retained: bool) -> Option<&'static str> {
    if retained { Some(OF_SYSFS_BASE) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_machine_without_a_device_tree_gets_no_entry() {
        assert_eq!(devicetree_link_target(false), None);
    }

    /// The symlink must land on the directory the sysfs exporter actually
    /// creates. Both sides read one constant, and this is the check that the
    /// procfs side still reads it.
    #[test]
    fn the_target_is_the_sysfs_device_tree_root() {
        assert_eq!(devicetree_link_target(true), Some("/sys/firmware/devicetree/base"));
        assert_eq!(devicetree_link_target(true), Some(fdt::uapi::OF_SYSFS_BASE));
    }

    #[test]
    fn the_entry_name_is_a_single_absolute_free_component() {
        assert_eq!(PROC_DEVICE_TREE, "device-tree");
        assert!(!PROC_DEVICE_TREE.contains('/'));
    }
}
