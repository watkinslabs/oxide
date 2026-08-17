//! Lifting a read-only mount's own read-only for the length of a repair.

use super::{lift_read_only, need_recovery, Facts};

/// A volume with nothing owed: cleanly unmounted, no orphans. # C: O(1)
fn clean() -> Facts {
    Facts { orphans_present: false, replays: true, clean_umount: true }
}

#[test]
fn a_cleanly_unmounted_volume_owes_no_repair() {
    assert!(!need_recovery(clean()));
}

#[test]
fn a_volume_that_was_not_cleanly_unmounted_owes_one() {
    assert!(need_recovery(Facts { clean_umount: false, ..clean() }));
}

#[test]
fn an_orphan_list_is_owed_whatever_the_mount_asked_about_the_chain() {
    // The inodes it names are already unlinked and their blocks already
    // unreachable; declining roll-forward does not decline that.
    for replays in [false, true] {
        for clean_umount in [false, true] {
            let f = Facts { orphans_present: true, replays, clean_umount };
            assert!(need_recovery(f), "{f:?}");
        }
    }
}

#[test]
fn a_mount_that_declined_the_chain_owes_nothing_for_it() {
    assert!(!need_recovery(Facts { replays: false, clean_umount: false, ..clean() }));
}

#[test]
fn only_a_read_only_mount_over_a_writable_medium_lifts_anything() {
    // A medium that refuses writes cannot be repaired at all.
    assert!(!lift_read_only(true, false, false));
    // A mount that may already write has nothing to lift, and raising the
    // mark there would make the close of the window turn it read-only.
    assert!(!lift_read_only(true, true, true));
    // Nothing owed, nothing lifted.
    assert!(!lift_read_only(false, true, false));
    assert!(lift_read_only(true, true, false));
}

#[test]
fn the_mark_goes_up_and_comes_down() {
    let mut f = crate::sbflags::SbFlags::new();
    assert!(!f.transiently_writable());
    f.set_transiently_writable(true);
    assert!(f.transiently_writable());
    assert_ne!(f.stored() & crate::sbflags::bits::bit(crate::sbflags::bits::IS_WRITABLE), 0);
    f.set_transiently_writable(false);
    assert!(!f.transiently_writable());
}
