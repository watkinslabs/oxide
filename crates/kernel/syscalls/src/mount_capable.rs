// `mount_capable` — which caller may create a NEW superblock instance of a
// given filesystem type. The one predicate `mount(2)` and
// `fsconfig(FSCONFIG_CMD_CREATE)` share, so the two entry points to superblock
// creation cannot disagree.
//
// Ungated on purpose. Both callers live in `#![cfg(target_os =
// "oxide-kernel")]` files, and this is the only rung of either whose answer
// depends on the caller's USER NAMESPACES — precisely the dimension a hosted
// test can cover and a kernel-gated one cannot (docs/53, CLAUDE.md phantom-test
// rule).

use vfs::fs::FsFlags;

/// The two capability facts `mount_capable` chooses between, sampled by the
/// caller (`mount_perm::sample_mount_caps`) so this module stays free of
/// `sched`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct MountCaps {
    /// `capable(CAP_SYS_ADMIN)` — held in the INITIAL user namespace.
    pub init_user_ns: bool,
    /// `may_mount()` — `ns_capable(mnt_ns->user_ns, CAP_SYS_ADMIN)`.
    pub mnt_user_ns: bool,
}

/// A filesystem WITHOUT `FS_USERNS_MOUNT` may only be instantiated by a caller
/// privileged in the INITIAL user namespace; one WITH the flag settles for
/// privilege in the mount namespace's owning user namespace.
///
/// The flag was declared and set on the pseudo-filesystems and NOTHING read it,
/// so an unprivileged user-namespace holder — who by construction holds
/// CAP_SYS_ADMIN inside its own user namespace and therefore passes `may_mount`
/// — could instantiate ext4, tmpfs, devtmpfs, devpts, fuse: every type reserved
/// for the initial user namespace. # C: O(1)
pub fn mount_capable(fs_flags: FsFlags, caps: MountCaps) -> bool {
    if !fs_flags.contains(FsFlags::FS_USERNS_MOUNT) { caps.init_user_ns } else { caps.mnt_user_ns }
}
