// Granularity policy for the kernel linear map (HHDM) this platform's boot
// trampoline installs, and the descriptor arithmetic the trampoline uses to
// build it.
//
// The linear map reaches all of RAM through the high half. Built the cheap way
// it is a handful of 1 GiB block leaves, and a single page can then only be
// taken out of the kernel's view of RAM by re-granularising a live mapping —
// which this architecture only permits without a translation-conflict abort
// when the implementation advertises that it does. QEMU's CPU models do not,
// so a map built from blocks makes every "hide this page from the kernel"
// contract permanently unavailable on the machines we boot.
//
// The reference resolves this the other way round, and by default: the RAM
// covered by the linear map is MAPPED at page granularity in the first place,
// while device space keeps its blocks. Nothing is ever removed from device
// space, and page tables for hundreds of GiB of it would cost more memory than
// the machine has. That is the policy here.
//
// Everything in this file is plain arithmetic on purpose: the trampoline is
// assembly that runs with the MMU off, so the numbers it is built from — how
// many tables, which L1 slots become tables, what a leaf descriptor looks like
// — have to be checkable without a machine. They are the same constants the
// assembly is assembled with, not a copy of them.

/// Descriptor kinds an L1 slot of the shared identity/HHDM table can hold.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum L1Slot {
    /// 1 GiB Device-nGnRE block: MMIO, never removed from the map.
    DeviceBlock,
    /// Table descriptor leading to 4 KiB leaves: the RAM the linear map covers.
    PageTable,
}

/// Bytes spanned by one L1 entry with the 4 KiB granule and a 48-bit VA.
pub const L1_SPAN_BYTES: u64 = 1 << 30;
/// Bytes spanned by one L2 entry.
pub const L2_SPAN_BYTES: u64 = 1 << 21;
/// Bytes spanned by one bottom-level entry.
pub const PAGE_BYTES: u64 = 1 << 12;
/// Entries in one 4 KiB table at every level.
pub const ENTRIES_PER_TABLE: usize = 512;
/// L1 entries in the identity/HHDM table (the whole 512 GiB it can describe).
pub const L1_ENTRIES: usize = 512;

/// First L1 slot the platform's RAM starts in. Below it is the MMIO aperture
/// holding the interrupt controller and the UART.
pub const RAM_FIRST_L1_SLOT: usize = 1;
/// L1 slots RAM can occupy. The map describes RAM up to the point where the
/// platform's high MMIO windows begin, and every slot above is device space.
pub const RAM_L1_SLOTS: usize = 3;

/// First L1 slot above RAM. Every slot from here up is device space.
pub const DEVICE_FIRST_L1_SLOT: usize = RAM_FIRST_L1_SLOT + RAM_L1_SLOTS;

/// Physical base of the RAM the linear map covers.
pub const RAM_BASE_PA: u64 = (RAM_FIRST_L1_SLOT as u64) * L1_SPAN_BYTES;

/// L2 tables the page-granular RAM half needs: one per L1 slot it replaces.
pub const L2_TABLES: usize = RAM_L1_SLOTS;
/// Bottom-level tables: one per L2 entry across every RAM slot.
pub const L3_TABLES: usize = RAM_L1_SLOTS * ENTRIES_PER_TABLE;
/// Bottom-level leaves the trampoline writes — one per page of covered RAM.
pub const L3_ENTRIES: usize = L3_TABLES * ENTRIES_PER_TABLE;

/// Static bytes the L2 level costs.
pub const L2_BYTES: usize = L2_TABLES * (PAGE_BYTES as usize);
/// Static bytes the bottom level costs.
pub const L3_BYTES: usize = L3_TABLES * (PAGE_BYTES as usize);

/// Attribute bits of a Normal write-back, inner-shareable, accessed leaf at the
/// bottom level: descriptor kind `page`, memory-attribute index 1, shareability
/// inner, access flag set.
pub const NORMAL_PAGE_BITS: u64 = 0x707;
/// Same memory attributes as `NORMAL_PAGE_BITS` in a block descriptor, which is
/// what the RAM slots held before this policy.
pub const NORMAL_BLOCK_BITS: u64 = 0x705;
/// Device-nGnRE 1 GiB block: attribute index 0, shareability outer, access flag
/// set.
pub const DEVICE_BLOCK_BITS: u64 = 0x401;
/// Table descriptor bits — valid, and not a block.
pub const TABLE_BITS: u64 = 0x3;

/// What the trampoline puts in L1 slot `slot` of the identity/HHDM table.
/// # C: O(1)
pub const fn l1_slot_kind(slot: usize) -> L1Slot {
    if slot >= RAM_FIRST_L1_SLOT && slot < RAM_FIRST_L1_SLOT + RAM_L1_SLOTS { L1Slot::PageTable }
    else { L1Slot::DeviceBlock }
}

/// Bottom-level leaf for the `index`-th page of covered RAM.
/// # C: O(1)
pub const fn l3_leaf(index: usize) -> u64 {
    (RAM_BASE_PA + (index as u64) * PAGE_BYTES) | NORMAL_PAGE_BITS
}

/// Table descriptor naming the table at `pa`.
/// # C: O(1)
pub const fn table_desc(pa: u64) -> u64 { pa | TABLE_BITS }

/// Device block leaf for L1 slot `slot`.
/// # C: O(1)
pub const fn device_block(slot: usize) -> u64 {
    ((slot as u64) * L1_SPAN_BYTES) | DEVICE_BLOCK_BITS
}

/// Whether the linear map this trampoline builds lets a single page be removed
/// from it without changing the granularity of a live mapping. True exactly
/// when every byte of RAM the map covers is reached through a bottom-level
/// leaf.
/// # C: O(L1 entries)
pub const fn linear_map_is_page_granular() -> bool {
    let mut slot = RAM_FIRST_L1_SLOT;
    while slot < RAM_FIRST_L1_SLOT + RAM_L1_SLOTS {
        match l1_slot_kind(slot) { L1Slot::PageTable => {} L1Slot::DeviceBlock => return false }
        slot += 1;
    }
    true
}

// The architecture layer answers "can a page be removed from the kernel linear
// map" from a declared policy, and this is the code that has to honour it.
// Keeping the declaration there and the check here means a change to what the
// trampoline builds without a matching change to what the capability claims
// does not compile, rather than silently making the claim false.
const _: () = assert!(
    linear_map_is_page_granular() == hal_aarch64::vmm::linear::LINEAR_MAP_RAM_PAGE_GRANULAR);

#[cfg(test)]
mod tests;
