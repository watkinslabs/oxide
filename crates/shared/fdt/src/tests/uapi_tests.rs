use crate::uapi::*;

/// `OF_SYSFS_BASE` must be exactly the root node's directory inside the
/// kset — the procfs symlink and the sysfs exporter derive it separately,
/// and a mismatch is a dangling `/proc/device-tree`.
#[test]
fn the_base_path_is_the_root_directory_inside_the_kset() {
    assert_eq!(OF_SYSFS_BASE, alloc::format!("{OF_SYSFS_KSET}/{OF_ROOT_DIR}"));
}

#[test]
fn every_published_path_is_absolute_and_under_sys_firmware() {
    for p in [OF_SYSFS_RAW, OF_SYSFS_KSET, OF_SYSFS_BASE] {
        assert!(p.starts_with("/sys/firmware/"), "{p}");
    }
    assert!(!OF_PROC_NAME.contains('/'), "the procfs entry is one component");
}

/// A `security-` property is root-only AND withheld; an ordinary one is
/// world-readable. Pinning both so a later edit cannot quietly publish a
/// secure property to every reader.
#[test]
fn secure_properties_are_root_only_and_ordinary_ones_are_not() {
    assert_eq!(OF_PROP_MODE, 0o444);
    assert_eq!(OF_SECURE_PROP_MODE, 0o400);
    assert_eq!(OF_RAW_MODE, 0o400);
}
