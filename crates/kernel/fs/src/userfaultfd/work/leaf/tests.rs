// The leaf judgements, driven against the REAL leaf encodings the running
// kernel walks — every entry below is built by the same packer the fault path
// uses, so a change to an encoding that broke one of these judgements would
// break this file too.

use hal::pt_walker::{MigrationEntry, PtWalker, SwapEntry};

use super::*;

/// The walker for the architecture this test build targets. The judgements are
/// generic over it; what is architecture-specific is the ENCODING each entry
/// below is built with, which is the thing worth testing against.
#[cfg(target_arch = "x86_64")]
type W = hal_x86_64::vmm::PtWalkerX86;
#[cfg(target_arch = "aarch64")]
type W = hal_aarch64::vmm::PtWalkerArm;

const PA: u64 = 0x1234_5000;

fn present_rw() -> u64 {
    W::pack_4k_leaf(PA, hal::PageFlags::USER | hal::PageFlags::READ | hal::PageFlags::WRITE)
}
fn swapped() -> u64 { W::pack_swap_entry(SwapEntry::new(1, 0x4242).expect("swap entry")) }
fn migrating() -> u64 { W::pack_migration_entry(MigrationEntry::new(0x99).expect("token")) }
fn poisoned() -> u64 { W::pack_poison_marker() }

// ---- publishing into an occupied address ----------------------------------

/// Every kind of entry blocks a publish, not just a resident page. Overwriting
/// a swap entry leaks its slot; overwriting a migration entry loses the page in
/// transit; overwriting a poison marker turns contents the monitor declared
/// unrecoverable back into ordinary memory.
#[test]
fn a_publish_is_refused_over_every_kind_of_entry() {
    assert_eq!(dst_must_be_empty(None), Ok(()));
    assert_eq!(dst_must_be_empty(Some(0)), Ok(()));
    for raw in [present_rw(), swapped(), migrating(), poisoned()] {
        assert_eq!(dst_must_be_empty(Some(raw)), Err(Errno::Eexist), "{raw:#x}");
    }
}

// ---- classification -------------------------------------------------------

/// Each encoding classifies as itself. A migration entry read as a swap entry
/// would move a slot reference that does not exist; a poison marker read as
/// either would move contents that are gone.
#[test]
fn every_leaf_encoding_classifies_as_what_it_is() {
    assert_eq!(classify::<W>(None), SrcLeaf::Absent);
    assert_eq!(classify::<W>(Some(0)), SrcLeaf::Absent);
    assert_eq!(classify::<W>(Some(present_rw())), SrcLeaf::Present(present_rw()));
    assert_eq!(classify::<W>(Some(swapped())), SrcLeaf::Swapped(swapped()));
    assert_eq!(classify::<W>(Some(migrating())), SrcLeaf::InFlight);
    assert_eq!(classify::<W>(Some(poisoned())), SrcLeaf::Unmovable);
}

/// The three non-present encodings are distinct values AND distinct from an
/// absent leaf. A collision between any two would make the classification above
/// a coin toss.
#[test]
fn the_non_present_encodings_do_not_collide() {
    let all = [swapped(), migrating(), poisoned()];
    for (i, a) in all.iter().enumerate() {
        assert_ne!(*a, 0, "a non-present encoding must not read as absent");
        assert!(!W::is_valid(*a), "a non-present encoding must not read as resident");
        for (j, b) in all.iter().enumerate() { if i != j { assert_ne!(a, b); } }
    }
    assert!(W::is_poison_marker(poisoned()));
    assert!(!W::is_poison_marker(swapped()));
    assert!(!W::is_poison_marker(migrating()));
    assert!(W::unpack_swap_entry(poisoned()).is_none());
    assert!(W::unpack_migration_entry(poisoned()).is_none());
    assert!(W::unpack_swap_entry(migrating()).is_none());
    assert!(W::unpack_migration_entry(swapped()).is_none());
}

// ---- the move ladder ------------------------------------------------------

/// The destination is judged BEFORE the source, so a move onto an occupied
/// address reports EEXIST whatever the source holds — including when the source
/// is a hole the caller asked to skip.
#[test]
fn a_move_judges_the_destination_before_the_source() {
    assert_eq!(move_step::<W>(Some(present_rw()), None, true), MoveStep::Fail(Errno::Eexist));
    assert_eq!(move_step::<W>(Some(present_rw()), Some(poisoned()), false),
               MoveStep::Fail(Errno::Eexist));
}

/// A resident source is marked as needing the exclusive-ownership proof; a
/// swapped one is not. Losing that distinction would either move a shared page
/// out from under the mapping that shares it, or refuse every swapped page for
/// an ownership question that does not apply to a slot reference.
#[test]
fn only_a_resident_source_needs_the_exclusive_ownership_proof() {
    assert_eq!(move_step::<W>(None, Some(present_rw()), false),
               MoveStep::Relocate { raw: present_rw(), resident: true });
    assert_eq!(move_step::<W>(None, Some(swapped()), false),
               MoveStep::Relocate { raw: swapped(), resident: false });
}

/// A hole is progress only when the caller asked for it; a page in transit is
/// retryable; a poison marker is a fault.
#[test]
fn the_unmovable_sources_each_report_their_own_errno() {
    assert_eq!(move_step::<W>(None, None, true), MoveStep::Skip);
    assert_eq!(move_step::<W>(None, Some(0), true), MoveStep::Skip);
    assert_eq!(move_step::<W>(None, None, false), MoveStep::Fail(Errno::Enoent));
    assert_eq!(move_step::<W>(None, Some(migrating()), true), MoveStep::Fail(Errno::Eagain));
    assert_eq!(move_step::<W>(None, Some(poisoned()), true), MoveStep::Fail(Errno::Efault));
}

// ---- the fill source ------------------------------------------------------

/// A continue publishes what the object HAS and nothing else; every other fill
/// refuses an offset the object already holds rather than overwriting contents
/// another mapper may be using.
#[test]
fn a_fill_takes_its_contents_from_the_object_whenever_there_is_one() {
    use FillKind::*;
    assert_eq!(fill_source(Continue, true, true), Ok(FillSource::Existing));
    assert_eq!(fill_source(Continue, true, false), Err(Errno::Efault));
    assert_eq!(fill_source(Continue, false, false), Err(Errno::Efault));
    for k in [Copy, Zeropage, Poison] {
        assert_eq!(fill_source(k, true, false), Ok(FillSource::IntoObject), "{k:?}");
        assert_eq!(fill_source(k, true, true), Err(Errno::Eexist), "{k:?}");
        assert_eq!(fill_source(k, false, false), Ok(FillSource::Fresh), "{k:?}");
    }
}

// ---- the write-protecting fill --------------------------------------------

/// A page installed under a write-protecting fill carries BOTH halves. The
/// marker alone leaves the page writable, so the write the barrier exists to
/// catch never faults; removing write permission alone makes the next write
/// look like an ordinary protection fault, which resolves as a copy instead of
/// being reported.
#[test]
fn a_write_protecting_fill_installs_the_marker_and_removes_write_permission() {
    let plain = present_rw();
    let armed = wp_leaf::<W>(plain);
    assert!(W::leaf_is_uffd_wp(armed), "the marker must be set");
    assert!(!W::leaf_is_uffd_wp(plain), "and must not have been there already");
    assert!(W::is_valid(armed), "the page stays resident and readable");
    assert_eq!(armed & W::PHYS_MASK, plain & W::PHYS_MASK, "the same frame");
    // Write permission is gone: re-applying the wrprotect alone is a no-op on
    // the armed leaf, which it would not be if the leaf were still writable.
    assert_eq!(W::leaf_wrprotect(armed), armed);
    assert_ne!(W::leaf_wrprotect(plain), plain, "the plain leaf WAS writable");
}
