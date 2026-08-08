// Bit-semantics tests for the PtWalkerX86 walker: the non-present encodings must stay
// mutually undecodable, and a leaf asked for a monitor's write-protect barrier
// must be built protected rather than protected after the fact.

use super::*;
/// Page-aligned stand-in physical addresses for leaf-packing tests.
const TEST_LEAF_PA: u64 = 0x4000;
const TEST_BLOCK_PA: u64 = 2 << 20;

#[test]
fn map_err_distinct() {
    assert_ne!(MapErr::AllocFailed, MapErr::HitHugePage);
    assert_ne!(MapErr::HitHugePage, MapErr::AlreadyMapped);
}

#[test]
fn host_walker_pack_unpack_roundtrip() {
    let pa = 0xdead_b000_u64;
    let leaf = PtWalkerX86::pack_device_leaf(pa);
    assert!(PtWalkerX86::is_valid(leaf));
    assert!(!PtWalkerX86::is_huge_or_block(leaf));
    assert_eq!(leaf & PtWalkerX86::PHYS_MASK, pa);
    let table = PtWalkerX86::pack_table(pa);
    assert!(PtWalkerX86::is_valid(table));
    assert!(!PtWalkerX86::is_huge_or_block(table));
    assert_eq!(table & PtWalkerX86::PHYS_MASK, pa);
}

#[test]
fn interior_table_entries_grant_user() {
    // Intel SDM §4.6: every interior entry on a CPL=3 walk must
    // have U/S=1 or the access faults. The leaf's U bit alone
    // gates user access; interior U=1 is unconditional.
    let table = PtWalkerX86::pack_table(0x10_0000);
    assert!(table & (1 << 2) != 0, "U/S bit must be set on interior entries");
    assert!(table & RW_BIT != 0, "RW bit must be set on interior entries");
}

#[test]
fn user_leaf_packs_user_bit_and_clears_nx() {
    let pa = 0x4000_u64;
    let leaf = PtWalkerX86::pack_4k_leaf(pa, hal::PageFlags::READ | hal::PageFlags::EXEC | hal::PageFlags::USER);
    assert!(leaf & (1 << 2) != 0, "leaf U/S bit set");
    assert_eq!(leaf & NX_BIT, 0, "EXEC ⇒ NX clear");
    assert_eq!(leaf & PtWalkerX86::PHYS_MASK, pa);
}

/// The memory-type selector's high bit sits at a DIFFERENT descriptor
/// position in a bottom-level leaf than in a block leaf, because the block
/// leaf spends that position on the size selector. A split that copies the
/// descriptor verbatim therefore changes the child's memory type — silently
/// making a write-through page uncached, or worse.
#[test]
fn splitting_to_the_bottom_level_moves_the_memory_type_selector() {
    let block = PtWalkerX86::pack_block_leaf(2 << 20, hal::PageFlags::READ | hal::PageFlags::WRITE)
        | (1 << BLOCK_TYPE_HI_SHIFT);
    let child = PtWalkerX86::split_child_leaf(block, 0x4000, LEAF_LEVEL_4K);
    assert_eq!(child & PS_BIT, 1 << LEAF_TYPE_HI_SHIFT,
               "the selector must land on the bottom-level position, which is where the size selector was");
    assert_eq!(child & PtWalkerX86::PHYS_MASK, 0x4000, "the child must translate its own address");
    assert!(PtWalkerX86::is_valid(child));
    // The size selector is only asked about above the bottom level, which
    // is exactly why the position is free to carry the memory type there.
    let plain = PtWalkerX86::split_child_leaf(
        PtWalkerX86::pack_block_leaf(2 << 20, hal::PageFlags::READ | hal::PageFlags::WRITE),
        0x4000, LEAF_LEVEL_4K);
    assert_eq!(plain & PS_BIT, 0, "a split of a default-memory-type block leaves the position clear");
}

/// Splitting a block into smaller BLOCKS leaves the selector where it was.
#[test]
fn splitting_to_an_intermediate_block_keeps_the_selector_in_place() {
    let block = PtWalkerX86::pack_block_leaf(1 << 30, hal::PageFlags::READ | hal::PageFlags::WRITE)
        | (1 << BLOCK_TYPE_HI_SHIFT);
    let child = PtWalkerX86::split_child_leaf(block, 1 << 21, 2);
    assert_ne!(child & (1 << BLOCK_TYPE_HI_SHIFT), 0);
    assert!(PtWalkerX86::is_huge_or_block(child), "an intermediate child is still a block");
    assert_eq!(child & !PtWalkerX86::PHYS_MASK, block & !PtWalkerX86::PHYS_MASK,
               "every other attribute carries over unchanged");
}

/// Removing a page from the linear map and restoring it must be exactly
/// reversible, or the restored page differs from the one that was taken.
#[test]
fn clearing_and_restoring_a_leaf_round_trips() {
    let leaf = PtWalkerX86::pack_4k_leaf(0x9000, hal::PageFlags::READ | hal::PageFlags::WRITE);
    let gone = PtWalkerX86::leaf_set_present(leaf, false);
    assert!(!PtWalkerX86::is_valid(gone), "the page must stop translating");
    assert_eq!(gone & PtWalkerX86::PHYS_MASK, 0x9000, "the address must survive so it can be restored");
    assert_eq!(PtWalkerX86::leaf_set_present(gone, true), leaf);
}

#[test]
fn kernel_only_leaf_clears_user_bit() {
    let pa = 0x5000_u64;
    let leaf = PtWalkerX86::pack_4k_leaf(pa, hal::PageFlags::READ | hal::PageFlags::WRITE);
    assert_eq!(leaf & (1 << 2), 0, "kernel-only leaf must have U/S=0");
    assert!(leaf & NX_BIT != 0, "no EXEC ⇒ NX set");
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
        let raw = PtWalkerX86::pack_pte_marker(m);
        assert_ne!(raw, 0, "a marker must not read as an absent leaf");
        assert!(!PtWalkerX86::is_valid(raw), "a marker must not read as resident");
        assert_eq!(PtWalkerX86::unpack_pte_marker(raw), Some(m));
        assert!(PtWalkerX86::unpack_swap_entry(raw).is_none(), "marker {bits} read as swap");
        assert!(PtWalkerX86::unpack_migration_entry(raw).is_none(), "marker {bits} read as migration");
    }
    for kind in 0..=SwapEntry::MAX_KIND {
        for i in 0..SwapEntry::OFFSET_BITS {
            for off in [0u64, 1u64 << i, SwapEntry::MAX_OFFSET] {
                let e = SwapEntry::new(kind, off).expect("representable swap entry");
                let raw = PtWalkerX86::pack_swap_entry(e);
                assert_eq!(PtWalkerX86::unpack_swap_entry(raw), Some(e));
                assert!(PtWalkerX86::unpack_pte_marker(raw).is_none(),
                        "swap entry kind {kind} offset {off:#x} read as a marker");
            }
        }
    }
    for i in 0..MigrationEntry::TOKEN_BITS {
        for tok in [0u64, 1u64 << i, MigrationEntry::MAX_TOKEN] {
            let e = MigrationEntry::new(tok).expect("representable migration entry");
            let raw = PtWalkerX86::pack_migration_entry(e);
            assert_eq!(PtWalkerX86::unpack_migration_entry(raw), Some(e));
            assert!(PtWalkerX86::unpack_pte_marker(raw).is_none(),
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
        let raw = PtWalkerX86::pack_pte_marker(m);
        assert!(!PtWalkerX86::nonpresent_is_uffd_wp(raw), "marker {bits} carries the bit unasked");
        let armed = PtWalkerX86::nonpresent_set_uffd_wp(raw);
        assert_eq!(PtWalkerX86::unpack_pte_marker(armed), Some(m), "marker {bits} lost its kinds");
        assert!(PtWalkerX86::unpack_swap_entry(armed).is_none());
        assert!(PtWalkerX86::unpack_migration_entry(armed).is_none());
    }
    for kind in 0..=SwapEntry::MAX_KIND {
        for i in 0..SwapEntry::OFFSET_BITS {
            for off in [0u64, 1u64 << i, SwapEntry::MAX_OFFSET] {
                let e = SwapEntry::new(kind, off).expect("representable swap entry");
                let raw = PtWalkerX86::pack_swap_entry(e);
                assert!(!PtWalkerX86::nonpresent_is_uffd_wp(raw), "swap {kind}/{off:#x} carries the bit unasked");
                let armed = PtWalkerX86::nonpresent_set_uffd_wp(raw);
                assert!(PtWalkerX86::nonpresent_is_uffd_wp(armed));
                assert!(!PtWalkerX86::is_valid(armed), "an armed swap entry must not read as resident");
                assert_eq!(PtWalkerX86::unpack_swap_entry(armed), Some(e), "swap {kind}/{off:#x} identity moved");
                assert!(PtWalkerX86::unpack_pte_marker(armed).is_none());
                assert!(PtWalkerX86::unpack_migration_entry(armed).is_none());
                assert_eq!(PtWalkerX86::nonpresent_clear_uffd_wp(armed), raw, "arming must be exactly reversible");
            }
        }
    }
    for i in 0..MigrationEntry::TOKEN_BITS {
        for tok in [0u64, 1u64 << i, MigrationEntry::MAX_TOKEN] {
            let e = MigrationEntry::new(tok).expect("representable migration entry");
            let raw = PtWalkerX86::pack_migration_entry(e);
            assert!(!PtWalkerX86::nonpresent_is_uffd_wp(raw), "migration {tok:#x} carries the bit unasked");
            let armed = PtWalkerX86::nonpresent_set_uffd_wp(raw);
            assert!(PtWalkerX86::nonpresent_is_uffd_wp(armed));
            assert!(!PtWalkerX86::is_valid(armed));
            assert_eq!(PtWalkerX86::unpack_migration_entry(armed), Some(e), "migration {tok:#x} identity moved");
            assert!(PtWalkerX86::unpack_pte_marker(armed).is_none());
            assert!(PtWalkerX86::unpack_swap_entry(armed).is_none());
            assert_eq!(PtWalkerX86::nonpresent_clear_uffd_wp(armed), raw, "arming must be exactly reversible");
        }
    }
    // The two barriers are asked about separately and must never answer for
    // each other: a resident page carries the state in its own permissions,
    // an entry naming a page elsewhere carries it in the entry.
    let page = PtWalkerX86::pack_4k_leaf(0x4000, hal::PageFlags::USER | hal::PageFlags::READ);
    assert!(!PtWalkerX86::nonpresent_is_uffd_wp(PtWalkerX86::leaf_set_uffd_wp(page)),
            "a present leaf must never answer the non-present question");
    let swapped = PtWalkerX86::nonpresent_set_uffd_wp(
        PtWalkerX86::pack_swap_entry(SwapEntry::new(3, 0x1234).expect("swap entry")));
    assert!(!PtWalkerX86::leaf_is_uffd_wp(swapped),
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
        let plain = PtWalkerX86::pack_4k_leaf(TEST_LEAF_PA, base);
        let armed = PtWalkerX86::pack_4k_leaf(TEST_LEAF_PA, base | hal::PageFlags::UFFD_WP);
        assert!(PtWalkerX86::is_valid(armed), "the page is present the moment it is published");
        assert!(PtWalkerX86::leaf_is_uffd_wp(armed), "and already carries the barrier");
        assert!(!PtWalkerX86::leaf_is_uffd_wp(plain), "which an ordinary install must not");
        assert_eq!(PtWalkerX86::leaf_wrprotect(armed), armed, "and is not writable for any window");
        // Same destination as arming an already-published writable leaf,
        // reached without ever publishing the writable one.
        assert_eq!(armed, PtWalkerX86::leaf_set_uffd_wp(PtWalkerX86::leaf_wrprotect(plain)));
        // A block leaf answers identically, so no granularity can publish a
        // writable page over an address a monitor is watching.
        let block = PtWalkerX86::pack_block_leaf(TEST_BLOCK_PA, base | hal::PageFlags::UFFD_WP);
        assert!(PtWalkerX86::leaf_is_uffd_wp(block));
        assert_eq!(PtWalkerX86::leaf_wrprotect(block), block);
    }
}

/// One leaf carries several facts at once, and each is answered
/// independently. Contents that are gone outrank a barrier over writes to
/// them, so a leaf carrying both still reports as poisoned.
#[test]
fn one_marker_leaf_carries_several_facts_at_once() {
    use hal::pt_walker::PteMarker;
    let both = PtWalkerX86::pack_pte_marker(PteMarker::POISON.with(PteMarker::UFFD_WP));
    assert!(PtWalkerX86::is_poison_marker(both));
    assert!(PtWalkerX86::is_uffd_wp_marker(both));
    assert!(PtWalkerX86::is_poison_marker(PtWalkerX86::pack_poison_marker()));
    assert!(!PtWalkerX86::is_uffd_wp_marker(PtWalkerX86::pack_poison_marker()));
    assert!(PtWalkerX86::is_uffd_wp_marker(PtWalkerX86::pack_uffd_wp_marker()));
    assert!(!PtWalkerX86::is_poison_marker(PtWalkerX86::pack_uffd_wp_marker()));
    assert!(!PtWalkerX86::is_poison_marker(0), "an absent leaf carries nothing");
    assert!(!PtWalkerX86::is_uffd_wp_marker(0), "an absent leaf carries nothing");
}

/// The transition every page of a write-protect range takes. Absent leaves
/// only acquire a marker when the mapping carries the protection over
/// addresses with no page; a poisoned leaf is untouched in both directions,
/// because resolving a barrier must not turn a permanent memory error back
/// into a page of fresh zeroes.
#[test]
fn the_write_protect_step_covers_every_leaf_encoding() {
    use hal::pt_walker::{uffd_wp_step, MigrationEntry, PteMarker, SwapEntry};
    type W = PtWalkerX86;
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

