// fsmount(2) 432: the flag words, the privilege model they SELECT, and the two
// post-creation superblock checks — every decision `do_fsmount` makes that does
// not need a mount tree.
//
// Ungated on purpose: `432_fsmount.rs` is `#![cfg(target_os = "oxide-kernel")]`,
// so a `#[cfg(test)]` block inside it compiles out silently (docs/53, CLAUDE.md
// phantom-test rule). The ORDER of these rungs is the only observable part of a
// rejected call, and the privilege model is the only part that varies with the
// caller's namespaces, so both belong where a hosted test can drive them.

use syscall::errno::Errno;

/// `FSMOUNT_*`.
pub const FSMOUNT_CLOEXEC:   u64 = 0x0000_0001;
/// Create the mount inside a NEW mount namespace and return a namespace fd for
/// it, instead of an `O_PATH` fd over a mount in an anonymous namespace.
pub const FSMOUNT_NAMESPACE: u64 = 0x0000_0002;
pub const FSMOUNT_FLAGS_VALID: u64 = FSMOUNT_CLOEXEC | FSMOUNT_NAMESPACE;

/// `MOUNT_ATTR_*` settable through `fsmount(2)`. `MOUNT_ATTR_IDMAP` is NOT in
/// this set — only `mount_setattr(2)` installs an idmap.
pub const MOUNT_ATTR_RDONLY:      u64 = 0x00_0001;
pub const MOUNT_ATTR_NOSUID:      u64 = 0x00_0002;
pub const MOUNT_ATTR_NODEV:       u64 = 0x00_0004;
pub const MOUNT_ATTR_NOEXEC:      u64 = 0x00_0008;
/// Sub-field, not a bit: exactly one atime mode must be named.
pub const MOUNT_ATTR__ATIME:      u64 = 0x00_0070;
pub const MOUNT_ATTR_RELATIME:    u64 = 0x00_0000;
pub const MOUNT_ATTR_NOATIME:     u64 = 0x00_0010;
pub const MOUNT_ATTR_STRICTATIME: u64 = 0x00_0020;
pub const MOUNT_ATTR_NODIRATIME:  u64 = 0x00_0080;
pub const MOUNT_ATTR_NOSYMFOLLOW: u64 = 0x20_0000;

/// The whole settable attribute space.
pub const FSMOUNT_ATTRS_VALID: u64 = MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV
    | MOUNT_ATTR_NOEXEC | MOUNT_ATTR__ATIME | MOUNT_ATTR_NODIRATIME | MOUNT_ATTR_NOSYMFOLLOW;

/// Which privilege the call demands, chosen by `FSMOUNT_NAMESPACE`.
///
/// The two are NOT interchangeable. Placing the new mount in a namespace the
/// caller is about to own asks only for authority over the caller's CURRENT
/// user namespace; placing it in an anonymous namespace destined for the
/// caller's mount tree asks for authority over the user namespace that OWNS
/// that mount namespace. A caller inside an unprivileged user namespace holds
/// the first and not the second.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Privilege {
    /// `ns_capable(current_user_ns(), CAP_SYS_ADMIN)` — the `FSMOUNT_NAMESPACE` form.
    CapSysAdminCurrentUserNs,
    /// `may_mount()` — `ns_capable(mnt_ns->user_ns, CAP_SYS_ADMIN)`.
    MayMount,
}

/// The two capability facts, sampled once by the caller so this module stays
/// free of `sched`.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct FsmountCaps {
    pub cap_sys_admin_current_user_ns: bool,
    pub may_mount: bool,
}

impl FsmountCaps {
    /// # C: O(1)
    pub fn holds(self, p: Privilege) -> bool {
        match p {
            Privilege::CapSysAdminCurrentUserNs => self.cap_sys_admin_current_user_ns,
            Privilege::MayMount                 => self.may_mount,
        }
    }
}

/// What an admitted `fsmount(2)` asked for.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Admitted {
    pub cloexec:   bool,
    /// Return a mount-namespace fd rather than an `O_PATH` fd over the mount.
    pub namespace: bool,
    /// The validated `MOUNT_ATTR_*` word, to be mapped into the `MNT_*` space.
    pub attrs:     u64,
}

/// `do_fsmount`'s prologue, in the reference's ORDER.
///
/// The flag word is validated BEFORE any privilege test, so a malformed call
/// reports EINVAL regardless of who made it and an unprivileged caller cannot
/// read its own privilege out of the errno. The privilege test comes next
/// because which privilege applies is chosen by a flag. The attribute word is
/// validated LAST, and its atime sub-field must name exactly one mode — an
/// unknown-bit mask alone would accept `NOATIME|STRICTATIME`.
/// # C: O(1)
pub fn admit(flags: u64, attr_flags: u64, caps: FsmountCaps) -> Result<Admitted, Errno> {
    if flags & !FSMOUNT_FLAGS_VALID != 0 { return Err(Errno::Einval); }
    let namespace = flags & FSMOUNT_NAMESPACE != 0;
    if !caps.holds(privilege_for(namespace)) { return Err(Errno::Eperm); }
    if attr_flags & !FSMOUNT_ATTRS_VALID != 0 { return Err(Errno::Einval); }
    match attr_flags & MOUNT_ATTR__ATIME {
        MOUNT_ATTR_RELATIME | MOUNT_ATTR_NOATIME | MOUNT_ATTR_STRICTATIME => {}
        _ => return Err(Errno::Einval),
    }
    Ok(Admitted { cloexec: flags & FSMOUNT_CLOEXEC != 0, namespace, attrs: attr_flags })
}

/// Which privilege `flags` selects. # C: O(1)
pub fn privilege_for(namespace: bool) -> Privilege {
    if namespace { Privilege::CapSysAdminCurrentUserNs } else { Privilege::MayMount }
}

/// `if (new_mnt->mnt_sb->s_flags & SB_NOUSER) { mntput(new_mnt); return -EINVAL; }`
///
/// Checked AFTER the mount is created, not before: `SB_NOUSER` is set by the
/// filesystem while filling the superblock, so nothing earlier in the call can
/// know it. A superblock that says "no user mount" reached through
/// `fsopen`+`fsconfig(CMD_CREATE)` would otherwise become a mountable tree the
/// `mount(2)` path refuses. # C: O(1)
pub fn admit_created_sb(s_flags: u64) -> Result<(), Errno> {
    if s_flags & vfs::superblock::SB_NOUSER != 0 { return Err(Errno::Einval); }
    Ok(())
}

/// `if (fc->sb_flags & SB_MANDLOCK) warn_mandlock();`
///
/// Mandatory locking is a no-op that the kernel still has to announce: a
/// filesystem mounted `-o mand` behaves as if the option were absent, and a
/// silent accept would let an administrator believe the semantics are in force.
/// The mount SUCCEEDS — this is a warning, not a rung. # C: O(1)
pub fn warns_mandlock(sb_flags: u64) -> bool {
    sb_flags & vfs::superblock::SB_MANDLOCK != 0
}

/// The mandatory-locking announcement, recorded on the context's warning
/// channel so the caller that asked for the option is the party that reads it.
/// # C: O(1)
pub const MANDLOCK_MSG: &str = "VFS: \"mand\" mount option ignored, mandatory locking is not enforced";

/// The diagnostic `do_fsmount` records on the context log before returning
/// EPERM for a too-revealing mount. Reading it back is the only way a caller
/// learns WHICH rung refused, since the errno is shared with the privilege
/// tests. # C: O(1)
pub const TOO_REVEALING_MSG: &str = "VFS: Mount too revealing";
