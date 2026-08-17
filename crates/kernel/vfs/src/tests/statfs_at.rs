// `statfs` in hand of the object the call named.
//
// A filesystem with per-object limits — a project quota, a subvolume, a tree
// quota — must be able to answer for THAT object rather than for the whole
// volume, because reporting the volume's counts to a caller confined to a
// fraction of it says there is room where there is none. Linux passes the
// dentry for exactly this reason.
//
// The contract has two halves and both break silently. A backend that does not
// narrow must keep answering as before, or every filesystem in the tree changes
// behaviour at once; and a backend that DOES narrow must actually be asked,
// or the override sits there looking correct and never runs.

use super::*;

use crate::inode::InodeRef;
use crate::superblock::{SbStatFs, SuperOps};
use crate::types::KResult;

/// Whole-volume counts, the same for every object.
const WHOLE: u64 = 1000;
/// What an object confined to a fraction of the volume is entitled to.
const CONFINED: u64 = 10;

/// A backend with no per-object limits: it never overrides `statfs_at`.
struct Plain;

impl SuperOps for Plain {
    fn statfs(&self) -> KResult<SbStatFs> {
        Ok(SbStatFs { f_blocks: WHOLE, f_bfree: WHOLE, ..Default::default() })
    }
}

/// A backend that narrows to the object's own limits.
struct Narrowing;

impl SuperOps for Narrowing {
    fn statfs(&self) -> KResult<SbStatFs> {
        Ok(SbStatFs { f_blocks: WHOLE, f_bfree: WHOLE, ..Default::default() })
    }
    fn statfs_at(&self, _inode: &InodeRef) -> KResult<SbStatFs> {
        Ok(SbStatFs { f_blocks: CONFINED, f_bfree: CONFINED, ..Default::default() })
    }
}

fn any_inode() -> InodeRef { MemFile::new(1) }

#[test]
fn a_backend_without_per_object_limits_answers_the_same_either_way() {
    // The default forwards, so adding the hook changed nothing for the
    // fourteen filesystems that do not narrow.
    let ops = Plain;
    let whole = ops.statfs().unwrap();
    let at = ops.statfs_at(&any_inode()).unwrap();
    assert_eq!(at.f_blocks, whole.f_blocks);
    assert_eq!(at.f_bfree, whole.f_bfree);
}

#[test]
fn a_backend_with_per_object_limits_is_asked_about_the_object() {
    // The half that made the hook necessary: the narrowed answer must be what
    // comes back, not the volume's.
    let ops = Narrowing;
    let at = ops.statfs_at(&any_inode()).unwrap();
    assert_eq!(at.f_blocks, CONFINED, "the object's limit, not the volume's");
    assert_eq!(at.f_bfree, CONFINED);
    assert_ne!(at.f_blocks, ops.statfs().unwrap().f_blocks);
}

#[test]
fn narrowing_does_not_change_the_volume_wide_answer() {
    // `statfs` and `statfs_at` are different questions. A backend that narrows
    // must still be able to report the volume, which is what `ustat` and the
    // unconfined caller ask for.
    let ops = Narrowing;
    assert_eq!(ops.statfs().unwrap().f_blocks, WHOLE);
}
