//! Unit coverage for `syscalls::path_ops_policy` — the create/remove/readlink
//! decision core the kernel-only slot files delegate to. Each case pins one
//! ORDER or one errno choice that a plausible-looking rewrite would get wrong.

use syscall::errno::Errno;
use syscalls::path_ops_policy::{
    check_create_leaf, check_create_leaf_kind, check_readlink_bufsiz, check_rmdir_leaf_kind,
    check_unlink_leaf_kind, check_unlink_trailing_slash, has_trailing_slash, readlink_copy_len,
    CreateKind, LastKind,
};

fn err<T>(r: Result<T, Errno>) -> Option<Errno> { r.err() }

// ---- leaf kind: the three families disagree, deliberately ------------------

#[test]
fn create_rejects_every_non_ordinary_leaf_as_eexist() {
    assert_eq!(check_create_leaf_kind(LastKind::Norm), Ok(()));
    for k in [LastKind::Dot, LastKind::Dotdot, LastKind::Root] {
        assert_eq!(err(check_create_leaf_kind(k)), Some(Errno::Eexist),
            "{k:?}: the name already denotes something, so creating it is EEXIST");
    }
}

#[test]
fn rmdir_gives_each_non_ordinary_leaf_its_own_errno() {
    assert_eq!(check_rmdir_leaf_kind(LastKind::Norm), Ok(()));
    assert_eq!(err(check_rmdir_leaf_kind(LastKind::Dot)), Some(Errno::Einval));
    assert_eq!(err(check_rmdir_leaf_kind(LastKind::Dotdot)), Some(Errno::Enotempty));
    assert_eq!(err(check_rmdir_leaf_kind(LastKind::Root)), Some(Errno::Ebusy));
}

#[test]
fn unlink_calls_every_non_ordinary_leaf_a_directory() {
    assert_eq!(check_unlink_leaf_kind(LastKind::Norm), Ok(()));
    for k in [LastKind::Dot, LastKind::Dotdot, LastKind::Root] {
        assert_eq!(err(check_unlink_leaf_kind(k)), Some(Errno::Eisdir), "{k:?}");
    }
}

#[test]
fn the_three_families_disagree_on_the_same_leaf() {
    // One shape, three answers — the reason the verdict is per-family and not
    // a single shared table.
    assert_eq!(err(check_create_leaf_kind(LastKind::Dotdot)), Some(Errno::Eexist));
    assert_eq!(err(check_rmdir_leaf_kind(LastKind::Dotdot)),  Some(Errno::Enotempty));
    assert_eq!(err(check_unlink_leaf_kind(LastKind::Dotdot)), Some(Errno::Eisdir));
}

// ---- create: EEXIST beats the trailing-slash ENOENT -----------------------

#[test]
fn occupied_name_is_eexist_whatever_the_slash_says() {
    for kind in [CreateKind::Dir, CreateKind::NonDir] {
        for slash in [false, true] {
            assert_eq!(err(check_create_leaf(true, slash, kind)), Some(Errno::Eexist),
                "{kind:?} slash={slash}: exclusivity survives the create suppression");
        }
    }
}

#[test]
fn trailing_slash_blocks_a_non_directory_create() {
    assert_eq!(check_create_leaf(false, false, CreateKind::NonDir), Ok(()));
    assert_eq!(err(check_create_leaf(false, true, CreateKind::NonDir)), Some(Errno::Enoent),
        "symlink/link/mknod lose LOOKUP_CREATE under a trailing slash, so a free name is ENOENT");
}

#[test]
fn mkdir_is_exempt_from_the_trailing_slash_rule() {
    assert_eq!(check_create_leaf(false, true, CreateKind::Dir), Ok(()),
        "mkdir asks for a directory, so `foo/` agrees with the request");
}

// ---- unlink trailing slash: the victim's type picks the errno -------------

#[test]
fn unlink_trailing_slash_reports_the_victims_type() {
    assert_eq!(check_unlink_trailing_slash(false, false), Ok(()));
    assert_eq!(check_unlink_trailing_slash(false, true), Ok(()),
        "no slash: the EISDIR for a directory victim comes from may_delete, not from here");
    assert_eq!(err(check_unlink_trailing_slash(true, true)), Some(Errno::Eisdir));
    assert_eq!(err(check_unlink_trailing_slash(true, false)), Some(Errno::Enotdir),
        "`file/` asserts a directory that is not there");
}

// ---- has_trailing_slash ---------------------------------------------------

#[test]
fn root_is_not_a_trailing_slash() {
    assert!(!has_trailing_slash("/"), "the root's slash is the path, not a suffix");
    assert!(!has_trailing_slash("a"));
    assert!(has_trailing_slash("a/"));
    assert!(has_trailing_slash("/a/b/"));
}

// ---- readlink -------------------------------------------------------------

#[test]
fn readlink_rejects_zero_and_negative_buffer_sizes() {
    assert_eq!(check_readlink_bufsiz(1), Ok(()));
    assert_eq!(err(check_readlink_bufsiz(0)), Some(Errno::Einval));
    assert_eq!(err(check_readlink_bufsiz(-1)), Some(Errno::Einval),
        "signed bufsiz: -1 must not be reinterpreted as 4 GiB");
    assert_eq!(err(check_readlink_bufsiz(i32::MIN)), Some(Errno::Einval));
}

#[test]
fn readlink_truncates_without_error() {
    assert_eq!(readlink_copy_len(10, 100), 10, "a roomy buffer takes the whole target");
    assert_eq!(readlink_copy_len(10, 10), 10, "an exact fit is not truncation");
    assert_eq!(readlink_copy_len(10, 4), 4, "a short buffer truncates and still succeeds");
    assert_eq!(readlink_copy_len(0, 4), 0);
}
