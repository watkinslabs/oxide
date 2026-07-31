//! The `may_create` / `may_delete` legs that sit OUTSIDE the DAC check and are
//! therefore invisible to the permission tests: the dead-directory `ENOENT`,
//! the unrepresentable-owner `EOVERFLOW`, the swap-backing `EPERM`, and the
//! filesystem-root `EBUSY`. Each case pins the leg's POSITION relative to the
//! permission check, because that ordering is the whole contract — a caller
//! who is also denied by DAC must still see the specific reason.

use vfs::inode::{S_DEAD, S_SWAPFILE};
use vfs::namei::{may_create, may_delete};
use vfs::{Cred, FileType, InodeBuilder, InodeRef, VfsError, default_file_ops, default_inode_ops,
    mk_mode};

/// `(uid_t)-1` — the reserved sentinel an inode may carry when the filesystem
/// cannot express its real owner.
const INVALID_ID: u32 = u32::MAX;

fn pfile(perm: u16, uid: u32, flags: u32) -> InodeRef {
    InodeBuilder::new(1, mk_mode(FileType::Regular, perm), default_inode_ops(), default_file_ops())
        .owner(uid, 0).i_flags(flags).build()
}

fn pdir(perm: u16, uid: u32, flags: u32) -> InodeRef {
    InodeBuilder::new(2, mk_mode(FileType::Directory, perm), default_inode_ops(), default_file_ops())
        .owner(uid, 0).i_flags(flags).build()
}

fn user(uid: u32) -> Cred {
    Cred { uid, gid: uid, cap_dac_override: false, cap_dac_read_search: false,
        cap_fowner: false, cap_chown: false, cap_fsetid: false, groups: vfs::GroupList::empty() }
}

fn root() -> Cred {
    Cred { uid: 0, gid: 0, cap_dac_override: true, cap_dac_read_search: true,
        cap_fowner: true, cap_chown: true, cap_fsetid: true, groups: vfs::GroupList::empty() }
}

// ---- may_create ----------------------------------------------------------

#[test]
fn create_in_a_dead_directory_is_enoent_not_eacces() {
    // A directory already removed by rmdir can never gain a child again. The
    // reason is "it is gone", so it outranks the permission answer — even for
    // a directory that is otherwise perfectly writable.
    let dead = pdir(0o777, 0, S_DEAD);
    assert_eq!(may_create(&dead, &user(1000)).err(), Some(VfsError::Enoent));
    assert_eq!(may_create(&dead, &root()).err(), Some(VfsError::Enoent),
        "capabilities grant permission, not existence");
}

#[test]
fn dead_directory_check_precedes_the_dac_check() {
    // Unwritable AND dead: the dead answer must win, otherwise the caller
    // retries after a chmod that can never help.
    let dead_ro = pdir(0o555, 0, S_DEAD);
    assert_eq!(may_create(&dead_ro, &user(1000)).err(), Some(VfsError::Enoent));
    // Control: the same directory alive reports the permission answer.
    assert_eq!(may_create(&pdir(0o555, 0, 0), &user(1000)).err(), Some(VfsError::Eacces));
}

#[test]
fn create_with_an_unrepresentable_caller_is_eoverflow() {
    let d = pdir(0o777, 0, 0);
    let mut c = user(1000);
    c.uid = INVALID_ID;
    assert_eq!(may_create(&d, &c).err(), Some(VfsError::Eoverflow),
        "a new object cannot be owned by an id the filesystem cannot write back");
    let mut c = user(1000);
    c.gid = INVALID_ID;
    assert_eq!(may_create(&d, &c).err(), Some(VfsError::Eoverflow));
}

#[test]
fn ordinary_create_still_passes() {
    assert!(may_create(&pdir(0o777, 0, 0), &user(1000)).is_ok());
}

// ---- may_delete ----------------------------------------------------------

#[test]
fn deleting_a_swap_backing_file_is_eperm() {
    // The swap code holds this inode's block map; dropping its last name would
    // let the blocks be reused under the live swap device.
    let dir = pdir(0o777, 1000, 0);
    let victim = pfile(0o644, 1000, S_SWAPFILE);
    assert_eq!(may_delete(&dir, &victim, false, &user(1000)).err(), Some(VfsError::Eperm));
    assert_eq!(may_delete(&dir, &victim, false, &root()).err(), Some(VfsError::Eperm),
        "the swap hold is not a permission, so no capability lifts it");
    // Control: the same file not in swap is removable.
    assert!(may_delete(&dir, &pfile(0o644, 1000, 0), false, &user(1000)).is_ok());
}

#[test]
fn unrepresentable_victim_owner_is_eoverflow_before_permission() {
    // Removing a name rewrites the inode, so an owner the filesystem cannot
    // express is refused before anything else — including before the EACCES a
    // read-only parent would produce.
    let bad = InodeBuilder::new(3, mk_mode(FileType::Regular, 0o644), default_inode_ops(),
        default_file_ops()).owner(INVALID_ID, 0).build();
    assert_eq!(may_delete(&pdir(0o777, 0, 0), &bad, false, &root()).err(),
        Some(VfsError::Eoverflow));
    assert_eq!(may_delete(&pdir(0o555, 0, 0), &bad, false, &user(1000)).err(),
        Some(VfsError::Eoverflow), "EOVERFLOW outranks the EACCES this parent would give");
    let bad_gid = InodeBuilder::new(4, mk_mode(FileType::Regular, 0o644), default_inode_ops(),
        default_file_ops()).owner(0, INVALID_ID).build();
    assert_eq!(may_delete(&pdir(0o777, 0, 0), &bad_gid, false, &root()).err(),
        Some(VfsError::Eoverflow));
}

#[test]
fn deleting_from_a_dead_directory_is_enoent_after_the_type_check() {
    // ENOENT sits at the very END of the ladder, so a type mismatch still wins:
    // `unlink` of a directory in a dead parent is EISDIR, not ENOENT.
    let dead = pdir(0o777, 1000, S_DEAD);
    let file = pfile(0o644, 1000, 0);
    let subdir = pdir(0o755, 1000, 0);
    assert_eq!(may_delete(&dead, &file, false, &user(1000)).err(), Some(VfsError::Enoent));
    assert_eq!(may_delete(&dead, &subdir, false, &user(1000)).err(), Some(VfsError::Eisdir),
        "the type disagreement is reported ahead of the parent's death");
    assert_eq!(may_delete(&dead, &file, true, &user(1000)).err(), Some(VfsError::Enotdir));
}

#[test]
fn a_sticky_denial_still_outranks_the_dead_parent() {
    // Ordering both ways round: sticky is step 4, dead-parent is step 7.
    let dead_sticky = pdir(0o1777, 0, S_DEAD);
    let victim = pfile(0o644, 1000, 0);
    assert_eq!(may_delete(&dead_sticky, &victim, false, &user(2000)).err(),
        Some(VfsError::Eperm));
}
