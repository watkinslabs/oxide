// `umask(2)` storage semantics. Linux keeps the mask in `current->fs->umask`,
// i.e. on the SHARED `fs_struct` owner — not on the task — so every `CLONE_FS`
// sibling (which is every thread of a process) observes one mask, `fork(2)`
// takes a private copy, and `unshare(CLONE_FS)` is what splits it.

use crate::task::{SchedClass, Task, UMASK_MASK};

const PARENT_TID: u32 = 7_951;
const CHILD_TID:  u32 = 7_952;
const TASK_WEIGHT: u32 = 1_024;
const BOOT_UMASK: u32 = 0o022;
const RESTRICTIVE: u32 = 0o077;
const OTHER_MASK: u32 = 0o007;
/// Bits above `S_IRWXUGO` that `umask(2)` must discard.
const STRAY_HIGH_BITS: u32 = 0o7000;

fn task(tid: u32, name: &'static str) -> Task { Task::new(tid, name, SchedClass::Normal { weight: TASK_WEIGHT }) }

#[test]
fn umask_returns_the_previous_mask_and_keeps_only_the_permission_bits() {
    let t = task(PARENT_TID, "umask");
    assert_eq!(t.umask(), BOOT_UMASK, "boot fs_struct starts at the default mask");
    assert_eq!(t.swap_umask(RESTRICTIVE), BOOT_UMASK, "umask(2) returns the PREVIOUS mask");
    assert_eq!(t.umask(), RESTRICTIVE);
    // Linux: `xchg(&current->fs->umask, mask & S_IRWXUGO)`.
    assert_eq!(t.swap_umask(STRAY_HIGH_BITS | OTHER_MASK), RESTRICTIVE);
    assert_eq!(t.umask(), OTHER_MASK, "bits outside S_IRWXUGO must be discarded");
    assert_eq!(UMASK_MASK, 0o777);
}

#[test]
fn clone_fs_siblings_share_one_umask() {
    let parent = task(PARENT_TID, "umask-parent");
    let child  = task(CHILD_TID, "umask-child");
    child.inherit_fs_context_from(&parent, true);

    parent.swap_umask(RESTRICTIVE);
    assert_eq!(child.umask(), RESTRICTIVE, "CLONE_FS siblings observe one fs_struct umask");
    child.swap_umask(OTHER_MASK);
    assert_eq!(parent.umask(), OTHER_MASK, "the sharing is symmetric");
}

#[test]
fn fork_copies_the_umask_and_unshare_splits_it() {
    let parent = task(PARENT_TID, "umask-fork-parent");
    parent.swap_umask(RESTRICTIVE);
    let child = task(CHILD_TID, "umask-fork-child");
    child.inherit_fs_context_from(&parent, false);

    assert_eq!(child.umask(), RESTRICTIVE, "fork(2) inherits the mask value");
    child.swap_umask(OTHER_MASK);
    assert_eq!(parent.umask(), RESTRICTIVE, "fork(2) took a PRIVATE fs_struct copy");

    let sibling = task(CHILD_TID + 1, "umask-unshare");
    sibling.inherit_fs_context_from(&parent, true);
    sibling.unshare_fs_context();
    sibling.swap_umask(OTHER_MASK);
    assert_eq!(parent.umask(), RESTRICTIVE, "unshare(CLONE_FS) detaches the mask");
}
