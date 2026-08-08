// Bit-semantics tests for the PtWalkerArm walker: the non-present encodings must stay
// mutually undecodable, and a leaf asked for a monitor's write-protect barrier
// must be built protected rather than protected after the fact.

use super::*;
/// Page-aligned stand-in physical addresses for leaf-packing tests.
const TEST_LEAF_PA: u64 = 0x4000;
const TEST_BLOCK_PA: u64 = 2 << 20;

#[test]
fn map_err_distinct() {
    assert_ne!(MapErr::AllocFailed, MapErr::HitBlockDescriptor);
    assert_ne!(MapErr::HitBlockDescriptor, MapErr::AlreadyMapped);
}

/// A bottom-level child must be spelled as a page, not as a block: the same
/// descriptor bit means "block" above the bottom level and "page" at it, so
/// a verbatim copy produces a descriptor the walker treats as invalid.
#[test]
fn splitting_to_the_bottom_level_respells_the_descriptor_as_a_page() {
    let flags = hal::PageFlags::READ | hal::PageFlags::WRITE;
    let block = PtWalkerArm::pack_block_leaf(2 << 20, flags);
    assert!(PtWalkerArm::is_huge_or_block(block));
    let child = PtWalkerArm::split_child_leaf(block, 0x4000, LEAF_LEVEL_4K);
    assert_eq!(child, PtWalkerArm::pack_4k_leaf(0x4000, flags),
               "a bottom-level child must be identical to a directly packed page leaf");
}

/// An intermediate child stays a block and keeps every attribute.
#[test]
fn splitting_to_an_intermediate_block_keeps_the_block_spelling() {
    let flags = hal::PageFlags::READ | hal::PageFlags::WRITE;
    let block = PtWalkerArm::pack_block_leaf(1 << 30, flags);
    let child = PtWalkerArm::split_child_leaf(block, 1 << 21, 2);
    assert!(PtWalkerArm::is_huge_or_block(child));
    assert_eq!(child, PtWalkerArm::pack_block_leaf(1 << 21, flags));
}

/// The contiguous hint promises a run of adjacent leaves; split children no
/// longer form that run, so carrying it down would let a TLB fold entries
/// that are about to stop agreeing.
#[test]
fn splitting_drops_the_contiguous_hint() {
    let block = PtWalkerArm::pack_block_leaf(1 << 30, hal::PageFlags::READ) | CONT;
    assert_eq!(PtWalkerArm::split_child_leaf(block, 1 << 21, 2) & CONT, 0);
    assert_eq!(PtWalkerArm::split_child_leaf(block, 0x1000, LEAF_LEVEL_4K) & CONT, 0);
}

/// Removing a page from the linear map and restoring it must be exactly
/// reversible, or the restored page differs from the one that was taken.
#[test]
fn clearing_and_restoring_a_leaf_round_trips() {
    let leaf = PtWalkerArm::pack_4k_leaf(0x9000, hal::PageFlags::READ | hal::PageFlags::WRITE);
    let gone = PtWalkerArm::leaf_set_present(leaf, false);
    assert!(!PtWalkerArm::is_valid(gone), "the page must stop translating");
    assert_eq!(gone & PtWalkerArm::PHYS_MASK, 0x9000, "the address must survive so it can be restored");
    assert_eq!(PtWalkerArm::leaf_set_present(gone, true), leaf);
}

#[test]
fn arm_walker_pack_unpack_roundtrip() {
    let pa = 0xdead_b000_u64;
    let leaf = PtWalkerArm::pack_device_leaf(pa);
    assert!(PtWalkerArm::is_valid(leaf));
    // L3 page leaves keep TABLE set; the walker driver only
    // calls is_huge_or_block on intermediate entries.
    assert_eq!(leaf & PtWalkerArm::PHYS_MASK, pa);
    let table = PtWalkerArm::pack_table(pa);
    assert!(PtWalkerArm::is_valid(table));
    assert!(!PtWalkerArm::is_huge_or_block(table));
    assert_eq!(table & PtWalkerArm::PHYS_MASK, pa);
}


/// The marker family must be impossible to read as a swap entry, as a page
/// in transit, or as a hole — and every one of THOSE must be impossible to
/// read as a marker. For every representable value, not for the one sample
/// each happens to use: a collision turns a poisoned page into a swap-slot
/// reference (freeing a slot nothing owns) or a write-protected hole into a
/// page in transit (a fault that waits for a migration that never ends).
#[test]
fn no_marker_leaf_can_be_read_as_a_swap_or_migration_entry() {
    use hal::pt_walker::{MigrationEntry, PteMarker, SwapEntry};
    for bits in 1..=PteMarker::MASK {
        let Some(m) = PteMarker::from_bits(bits) else { continue };
        let raw = PtWalkerArm::pack_pte_marker(m);
        assert_ne!(raw, 0, "a marker must not read as an absent leaf");
        assert!(!PtWalkerArm::is_valid(raw), "a marker must not read as resident");
        assert_eq!(PtWalkerArm::unpack_pte_marker(raw), Some(m));
        assert!(PtWalkerArm::unpack_swap_entry(raw).is_none(), "marker {bits} read as swap");
        assert!(PtWalkerArm::unpack_migration_entry(raw).is_none(), "marker {bits} read as migration");
    }
    for kind in 0..=SwapEntry::MAX_KIND {
        for i in 0..SwapEntry::OFFSET_BITS {
            for off in [0u64, 1u64 << i, SwapEntry::MAX_OFFSET] {
                let e = SwapEntry::new(kind, off).expect("representable swap entry");
                let raw = PtWalkerArm::pack_swap_entry(e);
                assert_eq!(PtWalkerArm::unpack_swap_entry(raw), Some(e));
                assert!(PtWalkerArm::unpack_pte_marker(raw).is_none(),
                        "swap entry kind {kind} offset {off:#x} read as a marker");
            }
        }
    }
    for i in 0..MigrationEntry::TOKEN_BITS {
        for tok in [0u64, 1u64 << i, MigrationEntry::MAX_TOKEN] {
            let e = MigrationEntry::new(tok).expect("representable migration entry");
            let raw = PtWalkerArm::pack_migration_entry(e);
            assert_eq!(PtWalkerArm::unpack_migration_entry(raw), Some(e));
            assert!(PtWalkerArm::unpack_pte_marker(raw).is_none(),
                    "migration token {tok:#x} read as a marker");
        }
    }

    // The write-protect bit a non-present leaf carries must be invisible to
    // all three decoders, in BOTH directions and for every representable
    // value: setting it may not turn one encoding into another, and no
    // encoding's payload may set it by accident. A collision here silently
    // frees a slot nothing owns, waits on a migration that never ends, or
    // arms a barrier on a page no monitor asked about.
    for bits in 1..=PteMarker::MASK {
        let Some(m) = PteMarker::from_bits(bits) else { continue };
        let raw = PtWalkerArm::pack_pte_marker(m);
        assert!(!PtWalkerArm::nonpresent_is_uffd_wp(raw), "marker {bits} carries the bit unasked");
        let armed = PtWalkerArm::nonpresent_set_uffd_wp(raw);
        assert_eq!(PtWalkerArm::unpack_pte_marker(armed), Some(m), "marker {bits} lost its kinds");
        assert!(PtWalkerArm::unpack_swap_entry(armed).is_none());
        assert!(PtWalkerArm::unpack_migration_entry(armed).is_none());
    }
    for kind in 0..=SwapEntry::MAX_KIND {
        for i in 0..SwapEntry::OFFSET_BITS {
            for off in [0u64, 1u64 << i, SwapEntry::MAX_OFFSET] {
                let e = SwapEntry::new(kind, off).expect("representable swap entry");
                let raw = PtWalkerArm::pack_swap_entry(e);
                assert!(!PtWalkerArm::nonpresent_is_uffd_wp(raw), "swap {kind}/{off:#x} carries the bit unasked");
                let armed = PtWalkerArm::nonpresent_set_uffd_wp(raw);
                assert!(PtWalkerArm::nonpresent_is_uffd_wp(armed));
                assert!(!PtWalkerArm::is_valid(armed), "an armed swap entry must not read as resident");
                assert_eq!(PtWalkerArm::unpack_swap_entry(armed), Some(e), "swap {kind}/{off:#x} identity moved");
                assert!(PtWalkerArm::unpack_pte_marker(armed).is_none());
                assert!(PtWalkerArm::unpack_migration_entry(armed).is_none());
                assert_eq!(PtWalkerArm::nonpresent_clear_uffd_wp(armed), raw, "arming must be exactly reversible");
            }
        }
    }
    for i in 0..MigrationEntry::TOKEN_BITS {
        for tok in [0u64, 1u64 << i, MigrationEntry::MAX_TOKEN] {
            let e = MigrationEntry::new(tok).expect("representable migration entry");
            let raw = PtWalkerArm::pack_migration_entry(e);
            assert!(!PtWalkerArm::nonpresent_is_uffd_wp(raw), "migration {tok:#x} carries the bit unasked");
            let armed = PtWalkerArm::nonpresent_set_uffd_wp(raw);
            assert!(PtWalkerArm::nonpresent_is_uffd_wp(armed));
            assert!(!PtWalkerArm::is_valid(armed));
            assert_eq!(PtWalkerArm::unpack_migration_entry(armed), Some(e), "migration {tok:#x} identity moved");
            assert!(PtWalkerArm::unpack_pte_marker(armed).is_none());
            assert!(PtWalkerArm::unpack_swap_entry(armed).is_none());
            assert_eq!(PtWalkerArm::nonpresent_clear_uffd_wp(armed), raw, "arming must be exactly reversible");
        }
    }
    // The two barriers are asked about separately and must never answer for
    // each other: a resident page carries the state in its own permissions,
    // an entry naming a page elsewhere carries it in the entry.
    let page = PtWalkerArm::pack_4k_leaf(0x4000, hal::PageFlags::USER | hal::PageFlags::READ);
    assert!(!PtWalkerArm::nonpresent_is_uffd_wp(PtWalkerArm::leaf_set_uffd_wp(page)),
            "a present leaf must never answer the non-present question");
    let swapped = PtWalkerArm::nonpresent_set_uffd_wp(
        PtWalkerArm::pack_swap_entry(SwapEntry::new(3, 0x1234).expect("swap entry")));
    assert!(!PtWalkerArm::leaf_is_uffd_wp(swapped),
            "a non-present leaf must never answer the present question");
}


/// Asking a leaf for the monitor's barrier must BUILD it protected: the one
/// store that publishes the mapping publishes the barrier with it. An
/// install that granted write permission and re-protected the page
/// afterwards leaves a window in which a peer thread's write escapes the
/// barrier exactly once, with no message to the monitor.
#[test]
fn a_leaf_asked_for_the_barrier_is_never_published_writable() {
    let rwx = hal::PageFlags::READ | hal::PageFlags::WRITE | hal::PageFlags::USER;
    for base in [rwx, rwx | hal::PageFlags::EXEC, rwx.with_pkey(2)] {
        let plain = PtWalkerArm::pack_4k_leaf(TEST_LEAF_PA, base);
        let armed = PtWalkerArm::pack_4k_leaf(TEST_LEAF_PA, base | hal::PageFlags::UFFD_WP);
        assert!(PtWalkerArm::is_valid(armed), "the page is present the moment it is published");
        assert!(PtWalkerArm::leaf_is_uffd_wp(armed), "and already carries the barrier");
        assert!(!PtWalkerArm::leaf_is_uffd_wp(plain), "which an ordinary install must not");
        assert_eq!(PtWalkerArm::leaf_wrprotect(armed), armed, "and is not writable for any window");
        // Same destination as arming an already-published writable leaf,
        // reached without ever publishing the writable one.
        assert_eq!(armed, PtWalkerArm::leaf_set_uffd_wp(PtWalkerArm::leaf_wrprotect(plain)));
        // A block leaf answers identically, so no granularity can publish a
        // writable page over an address a monitor is watching.
        let block = PtWalkerArm::pack_block_leaf(TEST_BLOCK_PA, base | hal::PageFlags::UFFD_WP);
        assert!(PtWalkerArm::leaf_is_uffd_wp(block));
        assert_eq!(PtWalkerArm::leaf_wrprotect(block), block);
    }
}

/// One leaf carries several facts at once, and each is answered
/// independently. Contents that are gone outrank a barrier over writes to
/// them, so a leaf carrying both still reports as poisoned.
#[test]
fn one_marker_leaf_carries_several_facts_at_once() {
    use hal::pt_walker::PteMarker;
    let both = PtWalkerArm::pack_pte_marker(PteMarker::POISON.with(PteMarker::UFFD_WP));
    assert!(PtWalkerArm::is_poison_marker(both));
    assert!(PtWalkerArm::is_uffd_wp_marker(both));
    assert!(PtWalkerArm::is_poison_marker(PtWalkerArm::pack_poison_marker()));
    assert!(!PtWalkerArm::is_uffd_wp_marker(PtWalkerArm::pack_poison_marker()));
    assert!(PtWalkerArm::is_uffd_wp_marker(PtWalkerArm::pack_uffd_wp_marker()));
    assert!(!PtWalkerArm::is_poison_marker(PtWalkerArm::pack_uffd_wp_marker()));
    assert!(!PtWalkerArm::is_poison_marker(0), "an absent leaf carries nothing");
    assert!(!PtWalkerArm::is_uffd_wp_marker(0), "an absent leaf carries nothing");
}

/// The transition every page of a write-protect range takes. Absent leaves
/// only acquire a marker when the mapping carries the protection over
/// addresses with no page; a poisoned leaf is untouched in both directions,
/// because resolving a barrier must not turn a permanent memory error back
/// into a page of fresh zeroes.
#[test]
fn the_write_protect_step_covers_every_leaf_encoding() {
    use hal::pt_walker::{uffd_wp_step, MigrationEntry, PteMarker, SwapEntry};
    type W = PtWalkerArm;
    let wp_marker = W::pack_uffd_wp_marker();
    // An address with no page: a marker only when markers are in use.
    assert_eq!(uffd_wp_step::<W>(None, true, true), Some(wp_marker));
    assert_eq!(uffd_wp_step::<W>(Some(0), true, true), Some(wp_marker));
    assert_eq!(uffd_wp_step::<W>(None, true, false), None);
    assert_eq!(uffd_wp_step::<W>(None, false, true), None);
    // A present page carries the state in its own permissions.
    let page = W::pack_4k_leaf(0x4000, hal::PageFlags::USER | hal::PageFlags::READ | hal::PageFlags::WRITE);
    let armed = uffd_wp_step::<W>(Some(page), true, true).expect("a writable page is armed");
    assert!(W::leaf_is_uffd_wp(armed) && W::is_valid(armed));
    assert_eq!(W::leaf_wrprotect(armed), armed, "write permission is gone");
    assert_eq!(uffd_wp_step::<W>(Some(armed), true, true), None, "already armed");
    let freed = uffd_wp_step::<W>(Some(armed), false, true).expect("an armed page resolves");
    assert!(!W::leaf_is_uffd_wp(freed) && W::is_valid(freed));
    // The marker itself: resolving removes it, arming leaves it.
    assert_eq!(uffd_wp_step::<W>(Some(wp_marker), false, true), Some(0));
    assert_eq!(uffd_wp_step::<W>(Some(wp_marker), true, true), None);
    // Both facts on one leaf: resolving the barrier leaves the poison.
    let both = W::pack_pte_marker(PteMarker::POISON.with(PteMarker::UFFD_WP));
    assert_eq!(uffd_wp_step::<W>(Some(both), false, true), Some(W::pack_poison_marker()));
    // Contents that are gone are untouched in both directions.
    let poison = W::pack_poison_marker();
    assert_eq!(uffd_wp_step::<W>(Some(poison), true, true), None);
    assert_eq!(uffd_wp_step::<W>(Some(poison), false, true), None);
    // A page that is ELSEWHERE takes the barrier into the entry naming it.
    // Leaving those alone looks harmless — neither carries write permission
    // right now — but the fault that brings the page back builds a fresh
    // leaf from the mapping's permissions, which is writable. An eviction
    // would then silently disarm the barrier.
    for away in [W::pack_swap_entry(SwapEntry::new(1, 0x4242).expect("swap entry")),
                 W::pack_migration_entry(MigrationEntry::new(0x99).expect("migration entry"))] {
        let armed = uffd_wp_step::<W>(Some(away), true, true).expect("an absent page is armed");
        assert!(W::nonpresent_is_uffd_wp(armed), "{away:#x} lost the barrier on eviction");
        assert!(!W::is_valid(armed));
        assert_eq!(uffd_wp_step::<W>(Some(armed), true, true), None, "already armed");
        assert_eq!(uffd_wp_step::<W>(Some(armed), false, true), Some(away),
                   "resolving must restore the exact entry");
        assert_eq!(uffd_wp_step::<W>(Some(away), false, true), None, "nothing to resolve");
    }
}

