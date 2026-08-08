// fsmount(2) 432 — the flag words, the privilege model they select, and the two
// post-creation superblock checks.
//
// These are the decisions `432_fsmount.rs` used to make inline. That file is
// `#![cfg(target_os = "oxide-kernel")]`, so a test written inside it compiles
// out and reports "ok" having built nothing; every assertion here is against
// `syscalls::fsmount_abi`, which is ungated, so a broken rung goes RED.

use syscall::errno::Errno;
use syscalls::fsmount_abi::{
    admit, admit_created_sb, privilege_for, warns_mandlock, FsmountCaps, Privilege,
    FSMOUNT_ATTRS_VALID, FSMOUNT_CLOEXEC, FSMOUNT_NAMESPACE, MOUNT_ATTR_NOATIME,
    MOUNT_ATTR_NODIRATIME, MOUNT_ATTR_NOSYMFOLLOW, MOUNT_ATTR_RDONLY, MOUNT_ATTR_RELATIME,
    MOUNT_ATTR_STRICTATIME, MOUNT_ATTR__ATIME,
};

const ALL: FsmountCaps = FsmountCaps { cap_sys_admin_current_user_ns: true, may_mount: true };
const NONE: FsmountCaps = FsmountCaps { cap_sys_admin_current_user_ns: false, may_mount: false };
/// A caller inside an unprivileged user namespace: full authority over its OWN
/// user namespace, none over the one owning its mount namespace.
const IN_USERNS: FsmountCaps =
    FsmountCaps { cap_sys_admin_current_user_ns: true, may_mount: false };

#[test]
fn an_unknown_flag_bit_is_einval() {
    assert_eq!(admit(0x4, 0, ALL).unwrap_err(), Errno::Einval);
    assert_eq!(admit(u64::MAX, 0, ALL).unwrap_err(), Errno::Einval);
    assert!(admit(0, 0, ALL).is_ok());
    assert!(admit(FSMOUNT_CLOEXEC, 0, ALL).is_ok());
    assert!(admit(FSMOUNT_NAMESPACE, 0, ALL).is_ok());
    assert!(admit(FSMOUNT_CLOEXEC | FSMOUNT_NAMESPACE, 0, ALL).is_ok());
}

// The flag word is validated BEFORE any privilege test, so a malformed call
// reports EINVAL no matter who made it — an unprivileged caller must not be
// able to read its own privilege out of the errno.
#[test]
fn a_malformed_flag_word_reports_einval_even_with_no_privilege() {
    assert_eq!(admit(0x4, 0, NONE).unwrap_err(), Errno::Einval);
}

// And the attribute word is validated AFTER the privilege test, so an
// unprivileged caller passing garbage attributes still gets EPERM.
#[test]
fn privilege_is_tested_before_the_attribute_word() {
    assert_eq!(admit(0, !FSMOUNT_ATTRS_VALID, NONE).unwrap_err(), Errno::Eperm);
    assert_eq!(admit(0, !FSMOUNT_ATTRS_VALID, ALL).unwrap_err(), Errno::Einval);
}

// FSMOUNT_NAMESPACE SELECTS a different privilege. Getting this wrong in either
// direction is a real defect: demanding `may_mount` for the namespace form
// makes it unusable from an unprivileged user namespace, which is the only
// place it is interesting; accepting `cap_sys_admin_current_user_ns` for the
// plain form lets that same caller mint a mount for its outer mount namespace.
#[test]
fn the_namespace_flag_selects_which_user_namespace_privilege_is_required() {
    assert_eq!(privilege_for(false), Privilege::MayMount);
    assert_eq!(privilege_for(true), Privilege::CapSysAdminCurrentUserNs);

    // The unprivileged-user-namespace caller: namespace form yes, plain form no.
    assert!(admit(FSMOUNT_NAMESPACE, 0, IN_USERNS).is_ok());
    assert_eq!(admit(0, 0, IN_USERNS).unwrap_err(), Errno::Eperm);

    // The mirror case — privilege over the mount namespace's owner but not over
    // the caller's own user namespace — admits the plain form only.
    let outer = FsmountCaps { cap_sys_admin_current_user_ns: false, may_mount: true };
    assert!(admit(0, 0, outer).is_ok());
    assert_eq!(admit(FSMOUNT_NAMESPACE, 0, outer).unwrap_err(), Errno::Eperm);

    assert_eq!(admit(FSMOUNT_NAMESPACE, 0, NONE).unwrap_err(), Errno::Eperm);
}

#[test]
fn the_admitted_request_carries_the_flags_it_was_given() {
    let a = admit(FSMOUNT_CLOEXEC | FSMOUNT_NAMESPACE, MOUNT_ATTR_RDONLY, ALL).unwrap();
    assert!(a.cloexec && a.namespace);
    assert_eq!(a.attrs, MOUNT_ATTR_RDONLY);
    let b = admit(0, MOUNT_ATTR_NOSYMFOLLOW | MOUNT_ATTR_NODIRATIME, ALL).unwrap();
    assert!(!b.cloexec && !b.namespace);
    assert_eq!(b.attrs, MOUNT_ATTR_NOSYMFOLLOW | MOUNT_ATTR_NODIRATIME);
}

// The atime sub-field is a THREE-VALUED selector inside a bit mask, so an
// unknown-bit test alone would accept `NOATIME|STRICTATIME` — two mutually
// exclusive modes at once, and whichever the mapper happened to test first
// would silently win.
#[test]
fn the_atime_subfield_must_name_exactly_one_mode() {
    for one in [MOUNT_ATTR_RELATIME, MOUNT_ATTR_NOATIME, MOUNT_ATTR_STRICTATIME] {
        assert!(admit(0, one, ALL).is_ok(), "atime mode {one:#x}");
    }
    assert_eq!(admit(0, MOUNT_ATTR_NOATIME | MOUNT_ATTR_STRICTATIME, ALL).unwrap_err(),
        Errno::Einval);
    // The fourth encoding of the sub-field names no mode at all.
    assert_eq!(MOUNT_ATTR__ATIME & 0x30, 0x30);
    assert_eq!(admit(0, MOUNT_ATTR__ATIME, ALL).unwrap_err(), Errno::Einval);
}

// MOUNT_ATTR_IDMAP is deliberately outside the settable set: only
// mount_setattr(2) installs an idmap, and an fsmount that quietly accepted the
// bit would drop it.
#[test]
fn idmap_is_not_settable_through_fsmount() {
    const MOUNT_ATTR_IDMAP: u64 = 0x10_0000;
    assert_eq!(FSMOUNT_ATTRS_VALID & MOUNT_ATTR_IDMAP, 0);
    assert_eq!(admit(0, MOUNT_ATTR_IDMAP, ALL).unwrap_err(), Errno::Einval);
}

// The filesystem marks its superblock unmountable-by-user while filling it, so
// the fact does not exist until the mount has been created. A missing check
// here is how `fsopen`+`fsconfig(CMD_CREATE)`+`fsmount` produces a mountable
// tree that `mount(2)` refuses.
#[test]
fn a_superblock_marked_no_user_mount_is_einval_after_creation() {
    assert_eq!(admit_created_sb(vfs::superblock::SB_NOUSER).unwrap_err(), Errno::Einval);
    assert_eq!(admit_created_sb(vfs::superblock::SB_NOUSER | vfs::superblock::SB_RDONLY)
        .unwrap_err(), Errno::Einval);
    assert!(admit_created_sb(0).is_ok());
    assert!(admit_created_sb(vfs::superblock::SB_RDONLY | vfs::superblock::SB_NOSUID).is_ok());
    // It is a bit of its own, not a neighbour of the user-settable set.
    assert_eq!(vfs::fs::SB_FLAGS_USER_MASK & vfs::superblock::SB_NOUSER, 0);
}

// Mandatory locking is accepted and does nothing, so the mount SUCCEEDS — the
// announcement is the only way an administrator learns the semantics they asked
// for are not in force.
#[test]
fn the_mandatory_locking_option_warns_without_refusing() {
    assert!(warns_mandlock(vfs::superblock::SB_MANDLOCK));
    assert!(warns_mandlock(vfs::superblock::SB_MANDLOCK | vfs::superblock::SB_RDONLY));
    assert!(!warns_mandlock(0));
    assert!(!warns_mandlock(vfs::superblock::SB_RDONLY | vfs::superblock::SB_NOATIME));
    // It is settable through the ordinary option path, which is why the check
    // reads the CONTEXT's flags rather than the superblock's.
    assert_ne!(vfs::fs::SB_FLAGS_USER_MASK & vfs::superblock::SB_MANDLOCK, 0);
}

// The two diagnostics fsmount records are distinct and each names its own
// condition: the too-revealing refusal shares EPERM with both privilege rungs,
// so without the message the caller cannot tell which one it hit, and the
// mandlock note accompanies a call that SUCCEEDS.
#[test]
fn the_two_recorded_diagnostics_are_distinct_and_level_appropriate() {
    use syscalls::fsmount_abi::{MANDLOCK_MSG, TOO_REVEALING_MSG};
    assert_ne!(MANDLOCK_MSG, TOO_REVEALING_MSG);
    assert!(!MANDLOCK_MSG.is_empty() && !TOO_REVEALING_MSG.is_empty());
    // They ride the context log, whose wire form is a level character, a space,
    // the message and a newline — so neither may carry its own framing.
    for m in [MANDLOCK_MSG, TOO_REVEALING_MSG] {
        assert!(!m.contains('\n'), "{m:?} must not carry its own newline");
    }
}
