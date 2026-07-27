// Linux-conformance tests for the xattr decision layer. Every case cites the
// `fs/xattr.c` / `security/commoncap.c` / `fs/posix_acl.c` rule it pins.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use syscall::errno::Errno;
use vfs::{FileType, InodeRef};

use super::acl;
use super::ops::{vfs_getxattr, vfs_listxattr, vfs_removexattr, vfs_setxattr};
use super::policy::*;

fn e(x: Errno) -> i64 { -(x.as_i32() as i64) }

fn inode_of(ft: FileType, perm: u16, uid: u32, store: bool) -> InodeRef {
    let b = vfs::InodeBuilder::new(1, vfs::mk_mode(ft, perm), vfs::default_inode_ops(),
                                   vfs::default_file_ops()).owner(uid, uid);
    if store { b.xattrs(vfs::SimpleXattrs::new()).build() } else { b.build() }
}

fn file() -> InodeRef { inode_of(FileType::Regular, 0o644, 0, true) }

fn cred_of(uid: u32, sys_admin: bool, setfcap: bool) -> XattrCred {
    XattrCred {
        cred: vfs::Cred { uid, gid: uid, cap_dac_override: false, cap_dac_read_search: false,
                          cap_fowner: false, cap_chown: false, cap_fsetid: false,
                          groups: vfs::GroupList::empty() },
        sys_admin, setfcap,
    }
}

fn root() -> XattrCred { XattrCred::root() }

fn set(i: &InodeRef, n: &str, v: &[u8], f: u32, c: &XattrCred) -> Result<(), i64> {
    vfs_setxattr(i, n, v.to_vec(), f, c)
}

// --- `setxattr_copy`: flags, name and value limits ------------------------

#[test]
fn set_flags_reject_unknown_bits_but_allow_create_plus_replace() {
    // `setxattr_copy`: `flags & ~(XATTR_CREATE|XATTR_REPLACE)` is EINVAL.
    assert_eq!(check_set_flags(0), Ok(()));
    assert_eq!(check_set_flags(XATTR_CREATE), Ok(()));
    assert_eq!(check_set_flags(XATTR_CREATE | XATTR_REPLACE), Ok(()));
    assert_eq!(check_set_flags(4), Err(e(Errno::Einval)));
    assert_eq!(check_set_flags(0xffff_ffff), Err(e(Errno::Einval)));
}

#[test]
fn create_and_replace_flags_follow_simple_xattr_set() {
    let i = file();
    let c = root();
    assert_eq!(set(&i, "user.a", b"1", XATTR_REPLACE, &c), Err(e(Errno::Enodata)));
    assert_eq!(set(&i, "user.a", b"1", XATTR_CREATE, &c), Ok(()));
    assert_eq!(set(&i, "user.a", b"2", XATTR_CREATE, &c), Err(e(Errno::Eexist)));
    assert_eq!(set(&i, "user.a", b"2", XATTR_REPLACE, &c), Ok(()));
    // Both flags together is NOT EINVAL in Linux: the store answers first.
    assert_eq!(set(&i, "user.a", b"3", XATTR_CREATE | XATTR_REPLACE, &c), Err(e(Errno::Eexist)));
    assert_eq!(set(&i, "user.b", b"3", XATTR_CREATE | XATTR_REPLACE, &c), Err(e(Errno::Enodata)));
    assert_eq!(vfs_getxattr(&i, "user.a", &c), Ok(b"2".to_vec()));
}

#[test]
fn name_and_value_limits_are_erange_and_e2big() {
    // `import_xattr_name`: empty or >XATTR_NAME_MAX is ERANGE (never ENAMETOOLONG).
    assert_eq!(check_name(""), Err(e(Errno::Erange)));
    let long = String::from_utf8(alloc::vec![b'a'; XATTR_NAME_MAX + 1]).unwrap();
    assert_eq!(check_name(&long), Err(e(Errno::Erange)));
    assert_eq!(check_name(&long[..XATTR_NAME_MAX]), Ok(()));
    // Raw (non-UTF8) name bytes count too.
    let raw = vfs::path_from_bytes(&alloc::vec![0xffu8; XATTR_NAME_MAX + 1]);
    assert_eq!(check_name(&raw), Err(e(Errno::Erange)));
    // `setxattr_copy`: size > XATTR_SIZE_MAX is E2BIG, checked before any copy.
    assert_eq!(check_value_size(XATTR_SIZE_MAX), Ok(()));
    assert_eq!(check_value_size(XATTR_SIZE_MAX + 1), Err(e(Errno::E2big)));
}

// --- `xattr_resolve_name`: which namespaces have a handler ----------------

#[test]
fn unknown_namespace_is_eopnotsupp_and_bare_prefix_is_einval() {
    assert_eq!(resolve_name("user.x"), Ok(()));
    assert_eq!(resolve_name("trusted.x"), Ok(()));
    assert_eq!(resolve_name("security.x"), Ok(()));
    assert_eq!(resolve_name("system.posix_acl_access"), Ok(()));
    assert_eq!(resolve_name("user."), Err(e(Errno::Einval)));
    assert_eq!(resolve_name("trusted."), Err(e(Errno::Einval)));
    assert_eq!(resolve_name("system.foo"), Err(e(Errno::Eopnotsupp)));
    assert_eq!(resolve_name("btrfs.x"), Err(e(Errno::Eopnotsupp)));
    assert_eq!(resolve_name("noprefix"), Err(e(Errno::Eopnotsupp)));

    let i = file();
    let c = root();
    assert_eq!(set(&i, "system.foo", b"v", 0, &c), Err(e(Errno::Eopnotsupp)));
    // A READ of an unsupported namespace is EOPNOTSUPP, NOT ENODATA.
    assert_eq!(vfs_getxattr(&i, "btrfs.x", &c), Err(e(Errno::Eopnotsupp)));
    assert_eq!(vfs_removexattr(&i, "btrfs.x", &c), Err(e(Errno::Eopnotsupp)));
}

// --- `xattr_permission` ---------------------------------------------------

#[test]
fn trusted_namespace_needs_cap_sys_admin_and_hides_on_read() {
    let i = file();
    let admin = root();
    assert_eq!(set(&i, "trusted.t", b"v", 0, &admin), Ok(()));

    let user = cred_of(0, false, false); // owner, but no CAP_SYS_ADMIN
    assert_eq!(set(&i, "trusted.t", b"w", 0, &user), Err(e(Errno::Eperm)));
    assert_eq!(vfs_removexattr(&i, "trusted.t", &user), Err(e(Errno::Eperm)));
    // A denied READ reports ENODATA (xattr_permission_error), not EPERM.
    assert_eq!(vfs_getxattr(&i, "trusted.t", &user), Err(e(Errno::Enodata)));
    // ... and the name is invisible in listxattr (simple_xattr_list).
    assert_eq!(vfs_listxattr(&i, &user), Ok(Vec::new()));
    assert_eq!(vfs_listxattr(&i, &admin), Ok(b"trusted.t\0".to_vec()));
}

#[test]
fn user_namespace_file_type_rules_match_xattr_permission() {
    let c = cred_of(0, false, false);
    // Regular files and sockets are eligible; symlinks/fifos/devices are not.
    for ft in [FileType::Regular, FileType::Socket] {
        let i = inode_of(ft, 0o644, 0, true);
        assert_eq!(set(&i, "user.a", b"v", 0, &c), Ok(()), "user.* allowed on {:?}", ft);
    }
    for ft in [FileType::Symlink, FileType::Fifo, FileType::CharDev, FileType::BlockDev] {
        let i = inode_of(ft, 0o644, 0, true);
        assert_eq!(set(&i, "user.a", b"v", 0, &c), Err(e(Errno::Eperm)), "user.* on {:?}", ft);
        // The read side hides existence instead of reporting EPERM.
        assert_eq!(vfs_getxattr(&i, "user.a", &c), Err(e(Errno::Enodata)), "read on {:?}", ft);
        // security.* stays reachable on those inodes (systemd labels symlinks).
        assert_eq!(set(&i, "security.selinux", b"l", 0, &XattrCred::root()), Ok(()));
    }
}

#[test]
fn user_namespace_takes_dac_not_ownership() {
    // A file owned by uid 0, group/other-writable: a NON-owner with write
    // permission may set user.* (Linux falls through to inode_permission).
    let i = inode_of(FileType::Regular, 0o666, 0, true);
    let other = cred_of(1000, false, false);
    assert_eq!(set(&i, "user.a", b"v", 0, &other), Ok(()));
    // Without write permission the same caller gets EACCES (not EPERM).
    let ro = inode_of(FileType::Regular, 0o644, 0, true);
    assert_eq!(set(&ro, "user.a", b"v", 0, &other), Err(e(Errno::Eacces)));
    // A read needs MAY_READ.
    let unreadable = inode_of(FileType::Regular, 0o600, 0, true);
    assert_eq!(vfs_getxattr(&unreadable, "user.a", &other), Err(e(Errno::Eacces)));
}

#[test]
fn sticky_directory_restricts_user_xattr_writes_to_the_owner() {
    let other = cred_of(1000, false, false);
    // Non-sticky, world-writable dir: any writer may set user.*.
    let plain = inode_of(FileType::Directory, 0o777, 0, true);
    assert_eq!(set(&plain, "user.a", b"v", 0, &other), Ok(()));
    // Sticky (/tmp): only the owner (or CAP_FOWNER) may write.
    let sticky = inode_of(FileType::Directory, 0o1777, 0, true);
    assert_eq!(set(&sticky, "user.a", b"v", 0, &other), Err(e(Errno::Eperm)));
    assert_eq!(set(&sticky, "user.a", b"v", 0, &cred_of(0, false, false)), Ok(()));
    // Reads are unaffected by the sticky rule.
    assert_eq!(vfs_getxattr(&sticky, "user.a", &other), Ok(b"v".to_vec()));
}

#[test]
fn immutable_and_append_only_inodes_reject_every_xattr_write() {
    for flag in [vfs::S_IMMUTABLE, vfs::S_APPEND] {
        let i = file();
        assert_eq!(set(&i, "user.a", b"v", 0, &root()), Ok(()));
        i.set_i_flags(flag);
        assert_eq!(set(&i, "user.a", b"w", 0, &root()), Err(e(Errno::Eperm)));
        assert_eq!(set(&i, "security.x", b"w", 0, &root()), Err(e(Errno::Eperm)));
        assert_eq!(vfs_removexattr(&i, "user.a", &root()), Err(e(Errno::Eperm)));
        // Reads stay allowed.
        assert_eq!(vfs_getxattr(&i, "user.a", &root()), Ok(b"v".to_vec()));
    }
}

// --- `security/commoncap.c` gate ------------------------------------------

#[test]
fn security_namespace_needs_cap_sys_admin_except_file_caps() {
    let i = file();
    let plain = cred_of(0, false, false);
    assert_eq!(set(&i, "security.selinux", b"v", 0, &plain), Err(e(Errno::Eperm)));
    assert_eq!(vfs_removexattr(&i, "security.selinux", &plain), Err(e(Errno::Eperm)));
    assert_eq!(set(&i, "security.selinux", b"v", 0, &cred_of(0, true, false)), Ok(()));
    // Reading security.* needs no capability at all (xattr_permission returns 0).
    assert_eq!(vfs_getxattr(&i, "security.selinux", &plain), Ok(b"v".to_vec()));
}

#[test]
fn file_capability_blob_is_validated_then_gated_on_cap_setfcap() {
    let i = file();
    let mut v2 = alloc::vec![0u8; 20];
    v2[..4].copy_from_slice(&0x0200_0000u32.to_le_bytes());
    let mut v3 = alloc::vec![0u8; 24];
    v3[..4].copy_from_slice(&0x0300_0000u32.to_le_bytes());
    // `cap_convert_nscap`: bad magic/size is EINVAL, and EINVAL precedes EPERM.
    let no_caps = cred_of(0, true, false);
    assert_eq!(set(&i, "security.capability", b"junk", 0, &no_caps), Err(e(Errno::Einval)));
    assert_eq!(set(&i, "security.capability", &v2[..19], 0, &no_caps), Err(e(Errno::Einval)));
    // Well-formed blob, but no CAP_SETFCAP (CAP_SYS_ADMIN does not substitute).
    assert_eq!(set(&i, "security.capability", &v2, 0, &no_caps), Err(e(Errno::Eperm)));
    assert_eq!(set(&i, "security.capability", &v2, 0, &cred_of(0, false, true)), Ok(()));
    assert_eq!(set(&i, "security.capability", &v3, 0, &cred_of(0, false, true)), Ok(()));
    // Removal is CAP_SETFCAP too, not CAP_SYS_ADMIN.
    assert_eq!(vfs_removexattr(&i, "security.capability", &no_caps), Err(e(Errno::Eperm)));
    assert_eq!(vfs_removexattr(&i, "security.capability", &cred_of(0, false, true)), Ok(()));
}

// --- get/list buffer semantics --------------------------------------------

#[test]
fn size_zero_probes_and_short_buffers_are_erange() {
    // `do_getxattr`: size is capped at XATTR_SIZE_MAX, then a short buffer is
    // ERANGE — unless the cap caused it, which Linux reports as E2BIG.
    // `size == 0` never reaches check_fit: it is the PROBE path, which returns
    // the length with no copy (see `user::copy_out`).
    assert_eq!(check_fit(3, 3, XATTR_SIZE_MAX), Ok(()));
    assert_eq!(check_fit(3, 2, XATTR_SIZE_MAX), Err(e(Errno::Erange)));
    assert_eq!(check_fit(3, usize::MAX, XATTR_SIZE_MAX), Ok(()));
    assert_eq!(check_fit(XATTR_SIZE_MAX + 1, usize::MAX, XATTR_SIZE_MAX), Err(e(Errno::E2big)));
    assert_eq!(check_fit(XATTR_LIST_MAX + 1, XATTR_LIST_MAX, XATTR_LIST_MAX), Err(e(Errno::E2big)));
}

#[test]
fn probe_and_short_buffer_paths_never_touch_the_user_buffer() {
    use super::user::{copy_out, import_xattr_args};
    let payload = b"user.a\0user.bb\0";
    // `size == 0` returns the length with NO copy, so a null buffer is legal.
    assert_eq!(copy_out(0, 0, payload, XATTR_LIST_MAX), payload.len() as i64);
    // A short buffer is ERANGE, decided before any copy is attempted.
    assert_eq!(copy_out(0, payload.len() - 1, payload, XATTR_LIST_MAX), e(Errno::Erange));
    assert_eq!(copy_out(0, 1, b"abc", XATTR_SIZE_MAX), e(Errno::Erange));
    // An empty payload copies nothing and reports 0.
    assert_eq!(copy_out(0, 16, b"", XATTR_LIST_MAX), 0);
    // `copy_struct_from_user` bounds on `struct xattr_args` (slots 463/464).
    assert_eq!(import_xattr_args(0, 8, false), Err(e(Errno::Einval)));
    assert_eq!(import_xattr_args(0, 1 << 20, false), Err(e(Errno::E2big)));
}

#[test]
fn listxattr_payload_is_nul_separated_and_nul_terminated() {
    let i = file();
    let c = root();
    assert_eq!(set(&i, "user.a", b"1", 0, &c), Ok(()));
    assert_eq!(set(&i, "user.bb", b"2", 0, &c), Ok(()));
    assert_eq!(vfs_listxattr(&i, &c), Ok(b"user.a\0user.bb\0".to_vec()));
    // Raw (non-UTF8) name bytes survive the framing unchanged.
    let raw = vfs::path_from_bytes(b"user.raw-\xff");
    assert_eq!(list_payload(&alloc::vec![raw], true), b"user.raw-\xff\0".to_vec());
}

#[test]
fn empty_value_is_legal_and_distinct_from_absent() {
    let i = file();
    let c = root();
    assert_eq!(vfs_getxattr(&i, "user.e", &c), Err(e(Errno::Enodata)));
    assert_eq!(set(&i, "user.e", b"", 0, &c), Ok(()));
    assert_eq!(vfs_getxattr(&i, "user.e", &c), Ok(Vec::new()));
    assert_eq!(vfs_listxattr(&i, &c), Ok(b"user.e\0".to_vec()));
    // Removal takes it back to ENODATA; a second removal is ENODATA too.
    assert_eq!(vfs_removexattr(&i, "user.e", &c), Ok(()));
    assert_eq!(vfs_getxattr(&i, "user.e", &c), Err(e(Errno::Enodata)));
    assert_eq!(vfs_removexattr(&i, "user.e", &c), Err(e(Errno::Enodata)));
}

#[test]
fn filesystem_without_a_store_reports_eopnotsupp_but_lists_empty() {
    // `xattr_resolve_name` has no handler → EOPNOTSUPP for get/set/remove...
    let i = inode_of(FileType::Regular, 0o644, 0, false);
    let c = root();
    assert_eq!(set(&i, "user.a", b"v", 0, &c), Err(e(Errno::Eopnotsupp)));
    assert_eq!(vfs_getxattr(&i, "user.a", &c), Err(e(Errno::Eopnotsupp)));
    assert_eq!(vfs_removexattr(&i, "user.a", &c), Err(e(Errno::Eopnotsupp)));
    // ... but `vfs_listxattr` has no i_op hook to call and answers 0 (empty).
    assert_eq!(vfs_listxattr(&i, &c), Ok(Vec::new()));
}

// --- POSIX ACL detour ------------------------------------------------------

fn acl_blob(entries: &[(u16, u16, u32)]) -> Vec<u8> {
    let mut v = 2u32.to_le_bytes().to_vec();
    for (tag, perm, id) in entries {
        v.extend_from_slice(&tag.to_le_bytes());
        v.extend_from_slice(&perm.to_le_bytes());
        v.extend_from_slice(&id.to_le_bytes());
    }
    v
}
const T_USER_OBJ:  u16 = 0x01;
const T_USER:      u16 = 0x02;
const T_GROUP_OBJ: u16 = 0x04;
const T_MASK:      u16 = 0x10;
const T_OTHER:     u16 = 0x20;

#[test]
fn acl_blob_framing_and_version_are_validated() {
    let i = file();
    let c = root();
    assert_eq!(set(&i, "system.posix_acl_access", b"ab", 0, &c), Err(e(Errno::Einval)));
    // Wrong POSIX_ACL_XATTR_VERSION → EOPNOTSUPP (posix_acl_fix_xattr_common).
    assert_eq!(set(&i, "system.posix_acl_access", &1u32.to_le_bytes(), 0, &c),
               Err(e(Errno::Eopnotsupp)));
    // Trailing partial entry → EINVAL.
    let mut short = acl_blob(&[(T_USER_OBJ, 6, 0)]);
    short.pop();
    assert_eq!(set(&i, "system.posix_acl_access", &short, 0, &c), Err(e(Errno::Einval)));
    // Out-of-order entries fail posix_acl_valid.
    let bad = acl_blob(&[(T_OTHER, 4, 0), (T_USER_OBJ, 6, 0)]);
    assert_eq!(set(&i, "system.posix_acl_access", &bad, 0, &c), Err(e(Errno::Einval)));
    // A named user with no mask entry is invalid too.
    let nomask = acl_blob(&[(T_USER_OBJ, 6, 0), (T_USER, 4, 1000), (T_GROUP_OBJ, 4, 0), (T_OTHER, 4, 0)]);
    assert_eq!(set(&i, "system.posix_acl_access", &nomask, 0, &c), Err(e(Errno::Einval)));
}

#[test]
fn access_acl_rewrites_the_mode_and_a_mode_equivalent_acl_is_not_stored() {
    let i = inode_of(FileType::Regular, 0o600, 0, true);
    let c = root();
    // A three-entry ACL carries no more than the mode bits → applied, not stored.
    let trivial = acl_blob(&[(T_USER_OBJ, 6, 0), (T_GROUP_OBJ, 4, 0), (T_OTHER, 4, 0)]);
    assert_eq!(set(&i, "system.posix_acl_access", &trivial, 0, &c), Ok(()));
    assert_eq!(i.perm().unwrap(), 0o644);
    assert_eq!(vfs_getxattr(&i, "system.posix_acl_access", &c), Err(e(Errno::Enodata)));
    // A named user makes it non-trivial → stored, and the MASK becomes the group bits.
    let rich = acl_blob(&[(T_USER_OBJ, 7, 0), (T_USER, 4, 1000), (T_GROUP_OBJ, 4, 0),
                          (T_MASK, 5, 0), (T_OTHER, 4, 0)]);
    assert_eq!(set(&i, "system.posix_acl_access", &rich, 0, &c), Ok(()));
    assert_eq!(i.perm().unwrap(), 0o754);
    assert_eq!(vfs_getxattr(&i, "system.posix_acl_access", &c), Ok(rich));
}

#[test]
fn default_acl_is_directory_only_and_ownership_gated() {
    let c = root();
    let trivial = acl_blob(&[(T_USER_OBJ, 6, 0), (T_GROUP_OBJ, 4, 0), (T_OTHER, 4, 0)]);
    // `set_posix_acl`: a default ACL on a non-directory is EACCES...
    let f = file();
    assert_eq!(set(&f, "system.posix_acl_default", &trivial, 0, &c), Err(e(Errno::Eacces)));
    // ... while an EMPTY default ACL on a non-directory is a silent no-op.
    assert_eq!(set(&f, "system.posix_acl_default", &2u32.to_le_bytes(), 0, &c), Ok(()));
    // On a directory it is stored verbatim (no mode rewrite for the default ACL).
    let d = inode_of(FileType::Directory, 0o755, 0, true);
    assert_eq!(set(&d, "system.posix_acl_default", &trivial, 0, &c), Ok(()));
    assert_eq!(vfs_getxattr(&d, "system.posix_acl_default", &c), Ok(trivial.clone()));
    // Only the owner (or CAP_FOWNER) may set an ACL, whatever the mode says.
    let world = inode_of(FileType::Directory, 0o777, 0, true);
    assert_eq!(set(&world, "system.posix_acl_default", &trivial, 0, &cred_of(1000, false, false)),
               Err(e(Errno::Eperm)));
    // Removal drops it and tolerates "already absent".
    assert_eq!(vfs_removexattr(&d, "system.posix_acl_default", &c), Ok(()));
    assert_eq!(vfs_removexattr(&d, "system.posix_acl_default", &c), Ok(()));
    assert!(acl::is_acl_name("system.posix_acl_access"));
}

#[test]
fn xattrs_are_per_inode_and_outlive_the_setting_handle() {
    // The store belongs to the INODE object, not to any open handle: a value
    // set through one reference is visible through every other reference and
    // outlives the handle that set it.
    let i = file();
    let c = root();
    assert_eq!(set(&i, "user.k", b"v", 0, &c), Ok(()));
    let alias = i.clone();
    drop(i);
    assert_eq!(vfs_getxattr(&alias, "user.k", &c), Ok(b"v".to_vec()));
    // A DIFFERENT inode has its own store.
    let other = file();
    assert_eq!(vfs_getxattr(&other, "user.k", &c), Err(e(Errno::Enodata)));
    assert_eq!(vfs_listxattr(&other, &c), Ok(Vec::new()));
}
