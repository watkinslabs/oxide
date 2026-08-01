//! `fsconfig(2)`'s three `FSCONFIG_CMD_*` commands as a state machine over
//! `fs_context.phase`, plus the privilege rungs each one carries.
//!
//! What these pin (each was absent before, so a caller saw a different errno or
//! no check at all):
//!
//! * CMD_CREATE / CMD_CREATE_EXCL check the PHASE first (EBUSY) and privilege
//!   second (EPERM) — so the errno never leaks whether the caller was
//!   privileged for a context that was not creatable anyway;
//! * privilege is `mount_capable(fc)`, the same predicate `mount(2)` applies,
//!   which is what stops an unprivileged user-namespace holder from realizing a
//!   superblock of a type reserved for the initial user namespace by going
//!   through `fsopen` + `fsconfig` instead;
//! * CMD_RECONFIGURE takes its own privilege answer (`ns_capable(sb->s_user_ns,
//!   CAP_SYS_ADMIN)`) and marks the context FAILED when refused;
//! * a successful create parks the context in AWAITING_MOUNT, and a successful
//!   reconfigure cleans it back to AWAITING_RECONF, which is what makes a second
//!   command on the same context fd report EBUSY rather than repeating the work.
//!
//! The syscall shim is `cfg(oxide-kernel)`; the decision lives in `vfs::fs`, so
//! it is exercised here directly with the capability answer supplied — the shim
//! only samples that bool from scheduler state.

use std::sync::Arc;

mod common;

use vfs::fs::fs_context::FsContext;
use vfs::fs::{
    finish_clean_context, vfs_clean_context, vfs_cmd_create, vfs_cmd_reconfigure, vfs_get_tree,
    FileSystem, FsContextPhase, FsContextPurpose, SB_FLAGS_USER_MASK,
};
use vfs::superblock::{next_anon_dev, FileSystemType, SuperBlock};
use vfs::{
    default_file_ops, default_inode_ops, mk_mode, FileType, InodeBuilder, InodeRef, KResult,
    VfsError,
};

fn tdir() -> InodeRef {
    InodeBuilder::new(1, mk_mode(FileType::Directory, 0), default_inode_ops(), default_file_ops()).build()
}

struct TFs;
impl FileSystem for TFs {
    fn name(&self) -> &str { "cmdfs" }
    fn root(&self) -> Option<InodeRef> { Some(tdir()) }
}

struct Ty;
impl FileSystemType for Ty {
    fn name(&self) -> &str { "cmdfs" }
    fn mount(&self, _src: Option<&str>, _opts: &str) -> KResult<Arc<SuperBlock>> {
        Ok(common::realize_sb(Arc::new(TFs), TFs.root(), next_anon_dev(), "cmdfs".to_string()))
    }
}

fn fresh() -> FsContext { FsContext::for_mount(Arc::new(Ty), 0) }

// ---- CMD_CREATE ---------------------------------------------------------

#[test]
fn a_privileged_create_realizes_the_tree_and_parks_at_awaiting_mount() {
    let mut fc = fresh();
    assert_eq!(fc.phase(), FsContextPhase::CreateParams);
    assert_eq!(vfs_cmd_create(&mut fc, false, true), Ok(()));
    assert_eq!(fc.phase(), FsContextPhase::AwaitingMount);
    assert!(fc.root().is_some(), "a realized context carries the tree root");
}

#[test]
fn an_unprivileged_create_is_eperm_and_realizes_nothing() {
    let mut fc = fresh();
    assert_eq!(vfs_cmd_create(&mut fc, false, false), Err(VfsError::Eperm));
    assert!(fc.root().is_none(), "a refused create must not leave a superblock behind");
    assert!(fc.sb().is_none());
}

// The phase rung outranks the privilege rung: a context that is not in
// CREATE_PARAMS reports EBUSY even for a caller who would also have been
// refused for privilege, so the errno cannot be used to probe privilege.
#[test]
fn the_wrong_phase_is_ebusy_even_for_an_unprivileged_caller() {
    let mut fc = fresh();
    vfs_cmd_create(&mut fc, false, true).expect("first create");
    assert_eq!(fc.phase(), FsContextPhase::AwaitingMount);
    assert_eq!(vfs_cmd_create(&mut fc, false, false), Err(VfsError::Ebusy));
    assert_eq!(vfs_cmd_create(&mut fc, false, true), Err(VfsError::Ebusy),
        "a second create on a realized context is EBUSY regardless of privilege");
}

#[test]
fn create_excl_is_the_same_command_carrying_the_exclusive_bit() {
    let mut fc = fresh();
    assert_eq!(vfs_cmd_create(&mut fc, true, true), Ok(()));
    assert!(fc.create_exclusive(), "CMD_CREATE_EXCL must reach the superblock lookup");
    let mut fc2 = fresh();
    assert_eq!(vfs_cmd_create(&mut fc2, false, true), Ok(()));
    assert!(!fc2.create_exclusive(), "plain CMD_CREATE must not set it");
}

// ---- CMD_RECONFIGURE ----------------------------------------------------

fn live_sb() -> Arc<SuperBlock> {
    let mut fc = fresh();
    vfs_get_tree(&mut fc).unwrap();
    fc.sb().unwrap().clone()
}

fn picked(sb: &Arc<SuperBlock>) -> FsContext {
    let root = sb.s_root().expect("live sb has an s_root");
    FsContext::for_reconfigure(sb.clone(), root, sb.s_flags(), SB_FLAGS_USER_MASK)
}

#[test]
fn an_unprivileged_reconfigure_is_eperm_and_fails_the_context() {
    let sb = live_sb();
    let mut fc = picked(&sb);
    assert_eq!(vfs_cmd_reconfigure(&mut fc, false), Err(VfsError::Eperm));
    assert_eq!(fc.phase(), FsContextPhase::Failed,
        "a refused reconfigure marks the context failed, not retryable in place");
    assert_eq!(vfs_cmd_reconfigure(&mut fc, true), Err(VfsError::Ebusy),
        "and the failed context is EBUSY for any later command");
}

#[test]
fn a_privileged_reconfigure_cleans_the_context_back_to_awaiting_reconf() {
    let sb = live_sb();
    let mut fc = picked(&sb);
    assert_eq!(vfs_cmd_reconfigure(&mut fc, true), Ok(()));
    assert_eq!(fc.phase(), FsContextPhase::AwaitingReconf);
    assert_eq!(fc.purpose(), FsContextPurpose::Reconfigure);
}

// ---- clean / finish_clean ----------------------------------------------

// `vfs_clean_context` discards everything that described HOW to build the tree
// while keeping the realized `(sb, root)`, so the context becomes exactly what
// an `fspick(2)` would have produced.
#[test]
fn clean_context_keeps_the_tree_and_drops_the_recipe() {
    let mut fc = fresh();
    fc.set_source("dev0");
    vfs_cmd_create(&mut fc, true, true).expect("create");
    let root = fc.root().cloned();

    vfs_clean_context(&mut fc);

    assert_eq!(fc.phase(), FsContextPhase::AwaitingReconf);
    assert_eq!(fc.purpose(), FsContextPurpose::Reconfigure);
    assert_eq!(fc.source(), None, "the source string is part of the recipe");
    assert_eq!(fc.sb_flags(), 0);
    assert!(!fc.create_exclusive());
    assert!(fc.params().is_empty());
    assert!(fc.root().is_some(), "the realized tree survives the clean");
    assert!(root.is_some());
}

// A cleaned context is not mountable again: the phase gate is what makes a
// second `fsmount(2)` on one context fd report EBUSY instead of minting a
// second mount object from a single superblock.
#[test]
fn a_cleaned_context_is_no_longer_awaiting_mount() {
    let mut fc = fresh();
    vfs_cmd_create(&mut fc, false, true).expect("create");
    assert_eq!(fc.phase(), FsContextPhase::AwaitingMount);
    vfs_clean_context(&mut fc);
    assert_ne!(fc.phase(), FsContextPhase::AwaitingMount);
}

// `finish_clean_context` re-arms a parked context for parameters and leaves
// every other phase alone — one implementation, so the parameter path and the
// command path cannot disagree about when the promotion happens.
#[test]
fn finish_clean_context_promotes_only_the_parked_phase() {
    let mut fc = fresh();
    vfs_cmd_create(&mut fc, false, true).expect("create");
    vfs_clean_context(&mut fc);
    assert_eq!(finish_clean_context(&mut fc), Ok(()));
    assert_eq!(fc.phase(), FsContextPhase::ReconfParams);
    // idempotent, and a fresh create-phase context is untouched
    assert_eq!(finish_clean_context(&mut fc), Ok(()));
    assert_eq!(fc.phase(), FsContextPhase::ReconfParams);
    let mut f2 = fresh();
    assert_eq!(finish_clean_context(&mut f2), Ok(()));
    assert_eq!(f2.phase(), FsContextPhase::CreateParams);
}
