// Durable provenance for `mount_setattr(2)` / `open_tree_attr(2)` idmap
// request shaping: which syscall may remove an idmap, and exactly when the
// `userns_fd` field is read.

use super::*;

const IDMAP: u64 = MOUNT_ATTR_IDMAP;
const RDONLY: u64 = vfs::mount::MOUNT_ATTR_RDONLY;
/// A descriptor value no table can hold; used to prove the field went unread.
const FD_OUT_OF_RANGE: u64 = USERNS_FD_MAX + 1;

#[test]
fn mount_setattr_never_gets_the_replace_mode() {
    assert_eq!(kflags_for_mount_setattr(false), 0);
    assert_eq!(kflags_for_mount_setattr(true), MOUNT_KATTR_RECURSE);
    assert!(!idmap_replace(kflags_for_mount_setattr(true)));
}

#[test]
fn open_tree_attr_gets_replace_only_when_it_clones() {
    assert_eq!(kflags_for_open_tree_attr(false, false), 0);
    assert_eq!(kflags_for_open_tree_attr(true, false), MOUNT_KATTR_IDMAP_REPLACE);
    assert_eq!(kflags_for_open_tree_attr(false, true), MOUNT_KATTR_RECURSE);
    assert_eq!(kflags_for_open_tree_attr(true, true),
               MOUNT_KATTR_IDMAP_REPLACE | MOUNT_KATTR_RECURSE);
}

#[test]
fn recurse_and_replace_are_independent_bits() {
    assert_ne!(MOUNT_KATTR_RECURSE, MOUNT_KATTR_IDMAP_REPLACE);
    assert!(recurse(MOUNT_KATTR_RECURSE) && !idmap_replace(MOUNT_KATTR_RECURSE));
    assert!(idmap_replace(MOUNT_KATTR_IDMAP_REPLACE) && !recurse(MOUNT_KATTR_IDMAP_REPLACE));
}

#[test]
fn a_block_naming_no_idmap_bit_leaves_the_idmap_alone() {
    assert_eq!(build_mount_idmapped(RDONLY, 0, 0, 0), Ok(IdmapPlan::Leave));
    assert_eq!(build_mount_idmapped(0, RDONLY, 0, 0), Ok(IdmapPlan::Leave));
    assert_eq!(build_mount_idmapped(0, 0, 0, MOUNT_KATTR_IDMAP_REPLACE), Ok(IdmapPlan::Leave));
}

#[test]
fn an_idmap_free_block_never_validates_the_userns_fd_field() {
    // The field is uninitialised padding for every caller that is not asking
    // for an idmap, so an unusable value in it must not become an error.
    assert_eq!(build_mount_idmapped(RDONLY, 0, FD_OUT_OF_RANGE, 0), Ok(IdmapPlan::Leave));
    assert_eq!(build_mount_idmapped(0, 0, u64::MAX, 0), Ok(IdmapPlan::Leave));
}

#[test]
fn clearing_the_idmap_is_einval_without_the_replace_mode() {
    assert_eq!(build_mount_idmapped(0, IDMAP, 3, 0), Err(Errno::Einval));
    assert_eq!(build_mount_idmapped(IDMAP, IDMAP, 3, 0), Err(Errno::Einval));
    // Recursion alone does not unlock it.
    assert_eq!(build_mount_idmapped(0, IDMAP, 3, MOUNT_KATTR_RECURSE), Err(Errno::Einval));
    // ... which is exactly what `mount_setattr(2)` derives.
    assert_eq!(build_mount_idmapped(0, IDMAP, 3, kflags_for_mount_setattr(true)),
               Err(Errno::Einval));
}

#[test]
fn clearing_without_setting_resolves_to_the_identity_map() {
    let kflags = kflags_for_open_tree_attr(true, false);
    assert_eq!(build_mount_idmapped(0, IDMAP, 3, kflags), Ok(IdmapPlan::Identity));
    assert_eq!(build_mount_idmapped(RDONLY, IDMAP, 3, kflags), Ok(IdmapPlan::Identity));
}

#[test]
fn the_identity_plan_does_not_read_the_userns_fd_field() {
    // Removal resolves before the fd range rule, so an fd that could never be
    // valid still yields a successful removal request.
    let kflags = kflags_for_open_tree_attr(true, true);
    assert_eq!(build_mount_idmapped(0, IDMAP, FD_OUT_OF_RANGE, kflags),
               Ok(IdmapPlan::Identity));
    assert_eq!(build_mount_idmapped(0, IDMAP, u64::MAX, kflags), Ok(IdmapPlan::Identity));
}

#[test]
fn setting_alongside_clearing_replaces_from_the_fd() {
    let kflags = kflags_for_open_tree_attr(true, false);
    assert_eq!(build_mount_idmapped(IDMAP, IDMAP, 7, kflags),
               Ok(IdmapPlan::FromUserNsFd(7)));
}

#[test]
fn setting_alone_installs_from_the_fd_in_either_mode() {
    assert_eq!(build_mount_idmapped(IDMAP, 0, 7, 0), Ok(IdmapPlan::FromUserNsFd(7)));
    assert_eq!(build_mount_idmapped(IDMAP, 0, 7, MOUNT_KATTR_IDMAP_REPLACE),
               Ok(IdmapPlan::FromUserNsFd(7)));
    assert_eq!(build_mount_idmapped(IDMAP, RDONLY, 0, 0), Ok(IdmapPlan::FromUserNsFd(0)));
}

#[test]
fn an_out_of_range_userns_fd_is_einval_on_the_install_plan() {
    assert_eq!(build_mount_idmapped(IDMAP, 0, FD_OUT_OF_RANGE, 0), Err(Errno::Einval));
    assert_eq!(build_mount_idmapped(IDMAP, 0, u64::MAX, 0), Err(Errno::Einval));
    assert_eq!(build_mount_idmapped(IDMAP, IDMAP, FD_OUT_OF_RANGE,
                                    MOUNT_KATTR_IDMAP_REPLACE), Err(Errno::Einval));
    // The boundary itself is accepted.
    assert_eq!(build_mount_idmapped(IDMAP, 0, USERNS_FD_MAX, 0),
               Ok(IdmapPlan::FromUserNsFd(i32::MAX)));
}

#[test]
fn the_replace_refusal_precedes_the_fd_range_rule() {
    // Without the replace mode a clear is EINVAL for a reason that has nothing
    // to do with the fd; both rungs are EINVAL, but only one of them can also
    // have produced Identity, so the refusal must come first.
    assert_eq!(build_mount_idmapped(0, IDMAP, u64::MAX, 0), Err(Errno::Einval));
    assert_eq!(build_mount_idmapped(0, IDMAP, u64::MAX, MOUNT_KATTR_IDMAP_REPLACE),
               Ok(IdmapPlan::Identity));
}
