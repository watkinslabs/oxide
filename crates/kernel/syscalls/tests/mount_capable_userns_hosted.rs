// `mount_capable` — the namespace dimension of superblock creation, shared by
// `mount(2)` and `fsconfig(FSCONFIG_CMD_CREATE)`.
//
// This is the one rung of either syscall whose answer depends on WHICH user
// namespace the caller is privileged in, and both call sites are in
// `#![cfg(target_os = "oxide-kernel")]` files, so nothing could exercise it.
// The predicate itself is ungated, and these drive it directly.

use syscalls::mount_capable::{mount_capable, MountCaps};
use vfs::fs::FsFlags;

/// A caller inside an unprivileged user namespace: CAP_SYS_ADMIN there by
/// construction — so `may_mount()` says yes — and nothing in the initial one.
const IN_USERNS: MountCaps = MountCaps { init_user_ns: false, mnt_user_ns: true };
const REAL_ROOT: MountCaps = MountCaps { init_user_ns: true, mnt_user_ns: true };
const NOBODY: MountCaps = MountCaps { init_user_ns: false, mnt_user_ns: false };

// The defect this predicate exists to prevent: `FS_USERNS_MOUNT` was declared,
// set on the pseudo-filesystems, and read by nothing — so an unprivileged
// user-namespace holder could instantiate ext4, tmpfs, devtmpfs, devpts, fuse,
// every type reserved for the initial user namespace.
#[test]
fn a_type_without_the_userns_flag_needs_privilege_in_the_initial_user_namespace() {
    assert!(!mount_capable(FsFlags::empty(), IN_USERNS),
        "passing may_mount() inside a user namespace is not enough");
    assert!(mount_capable(FsFlags::empty(), REAL_ROOT));
    assert!(!mount_capable(FsFlags::empty(), NOBODY));
}

#[test]
fn a_type_with_the_userns_flag_settles_for_the_mount_namespaces_owner() {
    assert!(mount_capable(FsFlags::FS_USERNS_MOUNT, IN_USERNS));
    assert!(mount_capable(FsFlags::FS_USERNS_MOUNT, REAL_ROOT));
    assert!(!mount_capable(FsFlags::FS_USERNS_MOUNT, NOBODY));
}

// Privilege in the initial user namespace does NOT substitute for `may_mount()`
// on a flagged type: the question is authority over the mount namespace being
// modified, and a task that entered a foreign mount namespace has none.
#[test]
fn initial_namespace_privilege_does_not_substitute_for_may_mount() {
    let init_only = MountCaps { init_user_ns: true, mnt_user_ns: false };
    assert!(!mount_capable(FsFlags::FS_USERNS_MOUNT, init_only));
    assert!(mount_capable(FsFlags::empty(), init_only));
}

// Other `FsFlags` must not shift the answer — the predicate reads exactly one
// bit, and a mask test that caught a neighbour would silently relax the rule
// for whichever type happened to carry it.
#[test]
fn no_other_filesystem_flag_changes_the_verdict() {
    for extra in [FsFlags::empty(), FsFlags::all() - FsFlags::FS_USERNS_MOUNT] {
        assert_eq!(mount_capable(extra, IN_USERNS), false, "{extra:?}");
        assert_eq!(mount_capable(extra | FsFlags::FS_USERNS_MOUNT, IN_USERNS), true, "{extra:?}");
    }
}
