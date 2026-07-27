//! `renameat2` flag validation (`rename_flags_check`) + the `vfs_rename`
//! dual-parent permission gate (`may_rename`) per Linux `fs/namei.c`. Synthetic
//! `Inode` impls carry explicit mode/uid/`i_flags`; both helpers are reached via
//! their fully-qualified `vfs::namei` paths (crate-root re-exports reported, not
//! edited).

use vfs::inode::S_APPEND;
use vfs::namei::{
    may_rename, rename_flags_check, RENAME_EXCHANGE, RENAME_NOREPLACE, RENAME_WHITEOUT,
};
use vfs::{Cred, FileType, InodeBuilder, InodeRef, VfsError, default_file_ops, default_inode_ops, mk_mode};
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_INO: AtomicU64 = AtomicU64::new(10);

fn next_ino() -> u64 { NEXT_INO.fetch_add(1, Ordering::Relaxed) }

/// Regular file with explicit perm/uid + VFS `i_flags`.
fn pfile(perm: u16, uid: u32, flags: u32) -> InodeRef {
    InodeBuilder::new(next_ino(), mk_mode(FileType::Regular, perm), default_inode_ops(), default_file_ops())
        .owner(uid, 0).i_flags(flags).build()
}

/// Directory with explicit perm/uid + VFS `i_flags`.
fn pdir(perm: u16, uid: u32, flags: u32) -> InodeRef {
    InodeBuilder::new(next_ino(), mk_mode(FileType::Directory, perm), default_inode_ops(), default_file_ops())
        .owner(uid, 0).i_flags(flags).build()
}

/// Unprivileged cred (no caps).
fn user(uid: u32) -> Cred {
    Cred {
        uid, gid: uid,
        cap_dac_override: false, cap_dac_read_search: false,
        cap_fowner: false, cap_chown: false, cap_fsetid: false,
        groups: vfs::GroupList::empty(),
    }
}

// ---- rename_flags_check (do_renameat2 EINVAL gate) -----------------------

#[test]
fn flags_zero_ok() {
    assert!(rename_flags_check(0).is_ok());
}

#[test]
fn flags_known_single_bits_ok() {
    assert!(rename_flags_check(RENAME_NOREPLACE).is_ok());
    assert!(rename_flags_check(RENAME_EXCHANGE).is_ok());
    assert!(rename_flags_check(RENAME_WHITEOUT).is_ok());
    // WHITEOUT + NOREPLACE is a legal (non-EXCHANGE) combination.
    assert!(rename_flags_check(RENAME_WHITEOUT | RENAME_NOREPLACE).is_ok());
}

#[test]
fn flags_unknown_bit_einval() {
    assert_eq!(rename_flags_check(1 << 31).err(), Some(VfsError::Einval));
}

#[test]
fn flags_exchange_with_noreplace_einval() {
    assert_eq!(
        rename_flags_check(RENAME_EXCHANGE | RENAME_NOREPLACE).err(),
        Some(VfsError::Einval),
    );
}

#[test]
fn flags_exchange_with_whiteout_einval() {
    assert_eq!(
        rename_flags_check(RENAME_EXCHANGE | RENAME_WHITEOUT).err(),
        Some(VfsError::Einval),
    );
}

// ---- may_rename: NOREPLACE / EXCHANGE existence --------------------------

#[test]
fn noreplace_target_present_eexist() {
    let od = pdir(0o777, 1000, 0);
    let src = pfile(0o644, 1000, 0);
    let nd = pdir(0o777, 1000, 0);
    let tgt = pfile(0o644, 1000, 0);
    assert_eq!(
        may_rename(&od, &src, &nd, Some(&tgt), RENAME_NOREPLACE, true, &user(1000)).err(),
        Some(VfsError::Eexist),
    );
}

#[test]
fn noreplace_target_absent_ok() {
    let od = pdir(0o777, 1000, 0);
    let src = pfile(0o644, 1000, 0);
    let nd = pdir(0o777, 1000, 0);
    assert!(may_rename(&od, &src, &nd, None, RENAME_NOREPLACE, true, &user(1000)).is_ok());
}

#[test]
fn exchange_target_absent_enoent() {
    let od = pdir(0o777, 1000, 0);
    let src = pfile(0o644, 1000, 0);
    let nd = pdir(0o777, 1000, 0);
    assert_eq!(
        may_rename(&od, &src, &nd, None, RENAME_EXCHANGE, true, &user(1000)).err(),
        Some(VfsError::Enoent),
    );
}

#[test]
fn same_inode_target_noop_but_noreplace_still_eexist() {
    let od = pdir(0o777, 1000, 0);
    let src = pfile(0o644, 1000, 0);
    let nd = pdir(0o777, 1000, 0);
    let same = src.clone();
    assert!(may_rename(&od, &src, &nd, Some(&same), 0, true, &user(1000)).is_ok());
    assert!(may_rename(&od, &src, &nd, Some(&same), RENAME_EXCHANGE, true, &user(1000)).is_ok());
    assert_eq!(
        may_rename(&od, &src, &nd, Some(&same), RENAME_NOREPLACE, true, &user(1000)).err(),
        Some(VfsError::Eexist),
    );
}

// ---- may_rename: type agreement (plain rename onto existing) -------------

#[test]
fn dir_onto_file_enotdir() {
    // Source is a directory, occupied target is a file → may_delete(isdir=true)
    // on a file victim → ENOTDIR.
    let od = pdir(0o777, 1000, 0);
    let src = pdir(0o755, 1000, 0);
    let nd = pdir(0o777, 1000, 0);
    let tgt = pfile(0o644, 1000, 0);
    assert_eq!(
        may_rename(&od, &src, &nd, Some(&tgt), 0, true, &user(1000)).err(),
        Some(VfsError::Enotdir),
    );
}

#[test]
fn file_onto_dir_eisdir() {
    // Source is a file, occupied target is a directory → EISDIR.
    let od = pdir(0o777, 1000, 0);
    let src = pfile(0o644, 1000, 0);
    let nd = pdir(0o777, 1000, 0);
    let tgt = pdir(0o755, 1000, 0);
    assert_eq!(
        may_rename(&od, &src, &nd, Some(&tgt), 0, true, &user(1000)).err(),
        Some(VfsError::Eisdir),
    );
}

#[test]
fn exchange_dir_and_file_type_mismatch_ok() {
    // EXCHANGE checks the TARGET's own type, so swapping a dir with a file is
    // permitted (both survive). Permission allows it under 0o777 parents.
    let od = pdir(0o777, 1000, 0);
    let src = pdir(0o755, 1000, 0);
    let nd = pdir(0o777, 1000, 0);
    let tgt = pfile(0o644, 1000, 0);
    assert!(may_rename(&od, &src, &nd, Some(&tgt), RENAME_EXCHANGE, true, &user(1000)).is_ok());
}

// ---- may_rename: dual-parent DAC -----------------------------------------

#[test]
fn unwritable_source_parent_eacces() {
    // Source parent 0o555 (no write) → may_delete(src) EACCES before any
    // destination check.
    let od = pdir(0o555, 0, 0);
    let src = pfile(0o644, 2000, 0);
    let nd = pdir(0o777, 2000, 0);
    assert_eq!(
        may_rename(&od, &src, &nd, None, 0, false, &user(2000)).err(),
        Some(VfsError::Eacces),
    );
}

#[test]
fn unwritable_dest_parent_eacces() {
    // Source parent writable, destination parent 0o555 → may_create EACCES.
    let od = pdir(0o777, 2000, 0);
    let src = pfile(0o644, 2000, 0);
    let nd = pdir(0o555, 0, 0);
    assert_eq!(
        may_rename(&od, &src, &nd, None, 0, false, &user(2000)).err(),
        Some(VfsError::Eacces),
    );
}

#[test]
fn sticky_dest_non_owner_target_eperm() {
    // Destination is a sticky dir; occupied target owned by someone else; the
    // caller owns neither target nor dir → may_delete(target) EPERM.
    let od = pdir(0o777, 2000, 0);
    let src = pfile(0o644, 2000, 0);
    let nd = pdir(0o1777, 0, 0);
    let tgt = pfile(0o644, 1000, 0);
    assert_eq!(
        may_rename(&od, &src, &nd, Some(&tgt), 0, false, &user(2000)).err(),
        Some(VfsError::Eperm),
    );
}

#[test]
fn append_only_source_parent_eperm() {
    let od = pdir(0o777, 1000, S_APPEND);
    let src = pfile(0o644, 1000, 0);
    let nd = pdir(0o777, 1000, 0);
    assert_eq!(
        may_rename(&od, &src, &nd, None, 0, true, &user(1000)).err(),
        Some(VfsError::Eperm),
    );
}

// ---- may_rename: cross-directory `..` write on a moved dir ----------------

#[test]
fn cross_dir_move_dir_needs_write_on_subtree() {
    // Moving a directory to a different parent requires MAY_WRITE on the moved
    // dir itself (for the `..` flip). A 0o555 source dir (no write) → EACCES,
    // even though both parents are writable.
    let od = pdir(0o777, 1000, 0);
    let src = pdir(0o555, 1000, 0); // not writable
    let nd = pdir(0o777, 1000, 0);
    assert_eq!(
        may_rename(&od, &src, &nd, None, 0, false, &user(1000)).err(),
        Some(VfsError::Eacces),
    );
}

#[test]
fn cross_dir_move_writable_dir_ok() {
    let od = pdir(0o777, 1000, 0);
    let src = pdir(0o755, 1000, 0); // writable by owner
    let nd = pdir(0o777, 1000, 0);
    assert!(may_rename(&od, &src, &nd, None, 0, false, &user(1000)).is_ok());
}

#[test]
fn same_dir_move_dir_no_subtree_write_needed() {
    // Within one parent, no `..` flip → an unwritable (0o555) source dir may
    // still be renamed (only parent write/search is required).
    let od = pdir(0o777, 1000, 0);
    let src = pdir(0o555, 1000, 0);
    assert!(may_rename(&od, &src, &od, None, 0, true, &user(1000)).is_ok());
}

#[test]
fn plain_rename_free_dest_ok() {
    let od = pdir(0o777, 1000, 0);
    let src = pfile(0o644, 1000, 0);
    let nd = pdir(0o777, 1000, 0);
    assert!(may_rename(&od, &src, &nd, None, 0, true, &user(1000)).is_ok());
}
