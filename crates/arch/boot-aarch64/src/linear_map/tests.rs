use super::*;

/// The contract that makes a page removable from the kernel's view of RAM
/// without touching the granularity of a live mapping: every byte of RAM the
/// linear map covers is reached through a BOTTOM-LEVEL leaf. If any RAM slot
/// keeps its 1 GiB block, a page inside that GiB can only be hidden by
/// re-granularising while the map is live, which this architecture refuses to
/// guarantee abort-free on the CPU models we run.
#[test]
fn every_ram_slot_is_reached_through_bottom_level_leaves() {
    for slot in RAM_FIRST_L1_SLOT..RAM_FIRST_L1_SLOT + RAM_L1_SLOTS {
        assert_eq!(l1_slot_kind(slot), L1Slot::PageTable, "RAM slot {slot} kept a block");
    }
    assert!(linear_map_is_page_granular());
}

/// Device space is deliberately left in blocks. Nothing is ever removed from
/// it, and paging all of it would cost two orders of magnitude more static
/// memory than paging the RAM does.
#[test]
fn device_space_keeps_its_blocks() {
    assert_eq!(l1_slot_kind(0), L1Slot::DeviceBlock);
    for slot in RAM_FIRST_L1_SLOT + RAM_L1_SLOTS..L1_ENTRIES {
        assert_eq!(l1_slot_kind(slot), L1Slot::DeviceBlock);
    }
    let device_slots = L1_ENTRIES - RAM_L1_SLOTS;
    let paged_device_cost = device_slots * ENTRIES_PER_TABLE * (PAGE_BYTES as usize);
    assert!(paged_device_cost > 100 * L3_BYTES);
}

/// A device block's output address is its own slot, so the map still reaches
/// the interrupt controller and the UART at their physical addresses.
#[test]
fn device_block_outputs_its_own_slot() {
    for slot in [0usize, 4, 255, 511] {
        assert_eq!(device_block(slot) & !0xfff, (slot as u64) * L1_SPAN_BYTES);
        assert_eq!(device_block(slot) & 0xfff, DEVICE_BLOCK_BITS);
    }
}

/// Re-granularising must not change what the map MEANS. A bottom-level leaf
/// carries the same memory attributes as the block it replaces and differs
/// only in descriptor kind — the bit that reads as "block" above the bottom
/// level and must be set on a bottom-level page.
#[test]
fn page_leaves_carry_the_replaced_blocks_attributes() {
    const KIND_BIT: u64 = 1 << 1;
    assert_eq!(NORMAL_BLOCK_BITS & KIND_BIT, 0);
    assert_eq!(NORMAL_PAGE_BITS, NORMAL_BLOCK_BITS | KIND_BIT);
    assert_eq!(NORMAL_PAGE_BITS & !KIND_BIT, NORMAL_BLOCK_BITS);
}

/// The leaves tile the covered RAM exactly: page `i` outputs the `i`-th page
/// from the RAM base, the first leaf is the RAM base itself, and the last leaf
/// ends precisely where device space begins. An off-by-one here maps RAM at
/// the wrong physical address, which is not a fault — it is silent corruption.
#[test]
fn bottom_level_leaves_tile_the_covered_ram_exactly() {
    assert_eq!(l3_leaf(0) & !0xfff, RAM_BASE_PA);
    for i in [0usize, 1, 511, 512, L3_ENTRIES / 2, L3_ENTRIES - 1] {
        assert_eq!(l3_leaf(i) & !0xfff, RAM_BASE_PA + (i as u64) * PAGE_BYTES);
        assert_eq!(l3_leaf(i) & 0xfff, NORMAL_PAGE_BITS);
    }
    let last_end = (l3_leaf(L3_ENTRIES - 1) & !0xfff) + PAGE_BYTES;
    assert_eq!(last_end, RAM_BASE_PA + (RAM_L1_SLOTS as u64) * L1_SPAN_BYTES);
}

/// Table counts follow from the span arithmetic, not from a hand-written
/// number: one bottom-level table per L2 entry, one L2 table per RAM slot.
#[test]
fn table_counts_follow_from_the_span_arithmetic() {
    assert_eq!(L1_SPAN_BYTES / L2_SPAN_BYTES, ENTRIES_PER_TABLE as u64);
    assert_eq!(L2_SPAN_BYTES / PAGE_BYTES, ENTRIES_PER_TABLE as u64);
    assert_eq!(L2_TABLES, RAM_L1_SLOTS);
    assert_eq!(L3_TABLES, RAM_L1_SLOTS * ENTRIES_PER_TABLE);
    assert_eq!(L3_ENTRIES as u64 * PAGE_BYTES, RAM_L1_SLOTS as u64 * L1_SPAN_BYTES);
    assert_eq!(L2_BYTES + L3_BYTES, (L2_TABLES + L3_TABLES) * PAGE_BYTES as usize);
}

/// The static cost of the policy, stated so a change to the covered span
/// cannot quietly move it: one bottom-level table per 2 MiB of covered RAM.
#[test]
fn static_page_table_cost_is_one_table_per_two_megabytes_of_ram() {
    let covered = RAM_L1_SLOTS as u64 * L1_SPAN_BYTES;
    assert_eq!(L3_BYTES as u64, covered / L2_SPAN_BYTES * PAGE_BYTES);
    assert_eq!(L3_BYTES as u64 * 512, covered);
    assert_eq!(L2_BYTES + L3_BYTES, 6 * 1024 * 1024 + 3 * 4096);
}

/// A table descriptor names its table and nothing else — the low bits are the
/// descriptor kind, so a table that is not page-aligned would corrupt them.
#[test]
fn table_descriptor_names_an_aligned_table() {
    let pa = 0x4123_4000u64;
    assert_eq!(table_desc(pa) & !0xfff, pa);
    assert_eq!(table_desc(pa) & 0xfff, TABLE_BITS);
}
