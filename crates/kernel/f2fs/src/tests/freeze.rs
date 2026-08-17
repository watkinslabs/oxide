//! What a freeze and a thaw of one volume decide.

use syscall::errno::Errno;

use super::{decide, thaw_issues_discards, Facts, Outcome};

/// A mount that can be frozen: writable, no recorded error, nothing pending.
/// # C: O(1)
fn clean() -> Facts { Facts { readonly: false, cp_error: false, dirty: false } }

#[test]
fn a_clean_writable_mount_raises_the_mark() {
    assert_eq!(decide(clean()), Ok(Outcome::Mark));
}

#[test]
fn a_read_only_mount_is_frozen_by_doing_nothing() {
    // It has no writes to stop and no mark to raise. Refusing would make a
    // snapshot of a read-only mount impossible.
    assert_eq!(decide(Facts { readonly: true, ..clean() }), Ok(Outcome::Nothing));
}

#[test]
fn a_read_only_mount_is_answered_before_either_refusal() {
    // The order is the contract: a read-only mount is not refused for state
    // it cannot have been responsible for and cannot repair.
    for f in [Facts { readonly: true, cp_error: true, dirty: false },
              Facts { readonly: true, cp_error: false, dirty: true },
              Facts { readonly: true, cp_error: true, dirty: true }] {
        assert_eq!(decide(f), Ok(Outcome::Nothing), "{f:?}");
    }
}

#[test]
fn a_volume_whose_checkpoint_records_an_error_cannot_be_sealed() {
    // The snapshot would name a state the medium never held.
    assert_eq!(decide(Facts { cp_error: true, ..clean() }), Err(Errno::Eio));
    // And it is answered ahead of the dirty check: an I/O error is why the
    // volume is dirty, not a separate fact about the caller.
    assert_eq!(decide(Facts { cp_error: true, dirty: true, ..clean() }), Err(Errno::Eio));
}

#[test]
fn a_volume_still_dirty_after_the_sync_is_an_invalid_request() {
    // The freeze already synced, so work left over is the caller's defect
    // rather than the medium's failure — which is why this is not `EIO`.
    assert_eq!(decide(Facts { dirty: true, ..clean() }), Err(Errno::Einval));
}

#[test]
fn a_thaw_issues_the_parked_runs_only_where_the_mount_owns_them() {
    // Where the device does the discarding, parked runs are its business.
    assert!(thaw_issues_discards(true, false));
    assert!(!thaw_issues_discards(true, true));
    assert!(!thaw_issues_discards(false, false));
    assert!(!thaw_issues_discards(false, true));
}

#[test]
fn the_mark_goes_up_and_comes_down() {
    let mut f = crate::sbflags::SbFlags::new();
    assert!(!f.freezing());
    f.set_freezing(true);
    assert!(f.freezing());
    assert_ne!(f.stored() & crate::sbflags::bits::bit(crate::sbflags::bits::IS_FREEZING), 0);
    f.set_freezing(false);
    assert!(!f.freezing());
}
