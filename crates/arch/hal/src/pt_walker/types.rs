// Arch-generic 4-level 4 KiB page-table walker per `20§5` / `21§5`.
//
// Both x86_64 (PML4→PDPT→PD→PT) and aarch64 EL1 with 4 KiB granule
// (L0→L1→L2→L3) use a 4-level table tree with 512 entries per
// table and the same VA-bit shifts (39/30/21/12). Only the entry
// bit semantics + privileged register access differ. The walk
// driver here owns the loop and HHDM-based table access; the
// per-arch `PtWalker` impl supplies the bit semantics.
//
// Used so far for splicing Device-attr MMIO leaves into the live
// tables; future callers (real `MmuOps::map`, page-fault handler
// installs) ride the same driver.

/// Entries per 4 KiB page table — fixed for both arches.
pub const ENTRIES_PER_TABLE: usize = 512;

/// VA-bit shift for the L0/PML4 index (4-level walk).
pub const L0_SHIFT: u32 = 39;
/// VA-bit shift for the L1/PDPT index.
pub const L1_SHIFT: u32 = 30;
/// VA-bit shift for the L2/PD index.
pub const L2_SHIFT: u32 = 21;
/// VA-bit shift for the L3/PT index (leaf).
pub const L3_SHIFT: u32 = 12;
/// Mask of one table-index field (9 bits = 512 entries).
pub const TABLE_IDX_MASK: u64 = 0x1ff;

/// Errors `map_device_4k` can return.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum WalkErr {
    /// Frame allocator returned `None` mid-walk.
    AllocFailed,
    /// An intermediate entry is a huge page / block descriptor and
    /// would need to be split. Caller policy decides if that's an
    /// error or a "split first then retry"; this driver doesn't.
    HitHugeOrBlock,
    /// Leaf already present at `va` and points elsewhere.
    AlreadyMapped,
}

/// Architecture-neutral identity of a swapped-out anonymous page.
///
/// The architecture owns its non-present PTE encoding; this value is the
/// VM-visible `(swap type, page offset)` pair and never contains a physical
/// address. Both supported architectures preserve five type bits and forty
/// offset bits in a non-present L3 entry.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SwapEntry {
    kind: u8,
    offset: u64,
}

/// Transient non-present PTE owned by in-flight migration. Unlike a swap
/// entry it names no backing slot and carries no reference or memcg charge.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct MigrationEntry { token: u64 }

impl MigrationEntry {
    pub const TOKEN_BITS: u8 = 40;
    pub const MAX_TOKEN: u64 = (1u64 << Self::TOKEN_BITS) - 1;
    /// # C: O(1)
    pub const fn new(token: u64) -> Option<Self> {
        if token > Self::MAX_TOKEN { None } else { Some(Self { token }) }
    }
    /// # C: O(1)
    pub const fn token(self) -> u64 { self.token }
}

impl SwapEntry {
    pub const TYPE_BITS: u8 = 5;
    pub const OFFSET_BITS: u8 = 40;
    pub const MAX_KIND: u8 = (1 << Self::TYPE_BITS) - 1;
    pub const MAX_OFFSET: u64 = (1u64 << Self::OFFSET_BITS) - 1;

    /// Construct a representable swap entry.
    /// # C: O(1)
    pub const fn new(kind: u8, offset: u64) -> Option<Self> {
        if kind > Self::MAX_KIND || offset > Self::MAX_OFFSET { return None; }
        Some(Self { kind, offset })
    }

    /// Swap-area type index.
    /// # C: O(1)
    pub const fn kind(self) -> u8 { self.kind }

    /// Page offset within that swap area.
    /// # C: O(1)
    pub const fn offset(self) -> u64 { self.offset }
}

/// Per-arch bit semantics for the 4-level walker. Static methods
/// only; impls are zero-sized markers.
///
/// Generic at the call site (per `07§5` no-`dyn` rule): the walker
/// monomorphizes per impl.
///
/// # C: each method is O(1).
pub trait PtWalker {
    /// Mask of the physical-address field in a PTE (12-bit aligned;
    /// excludes flag bits). `0x000f_ffff_ffff_f000` on x86_64,
    /// `0x0000_ffff_ffff_f000` on aarch64.
    const PHYS_MASK: u64;

    /// Read the active page-table base PA for the walk targeting
    /// `va`. On x86_64 there's a single CR3 so `va` is ignored. On
    /// aarch64 the TTBR0_EL1 / TTBR1_EL1 split is keyed off bit 55
    /// of the VA (per ARM ARM D5.2.4): high-half VAs (kernel) use
    /// TTBR1, low-half (user) use TTBR0. Letting the walker pick
    /// per-call lets `MmuOps::map(USER_VA, ...)` plumb into the
    /// user tree without a separate impl.
    /// # SAFETY: privileged read; legal at CPL=0 / EL1.
    unsafe fn read_pt_base(va: u64) -> u64;

    /// Local-CPU TLB invalidate of a single 4 KiB page at `va`.
    /// # SAFETY: privileged.
    unsafe fn flush_va(va: u64);

    /// True when `entry`'s "present/valid" bit is set.
    fn is_valid(entry: u64) -> bool;

    /// True when a present `entry` describes a leaf at a
    /// non-bottom level (huge page on x86; block descriptor on
    /// arm). At L3 this is always false because L3 entries are
    /// always page leaves.
    fn is_huge_or_block(entry: u64) -> bool;

    /// Pack a fresh intermediate (table) entry pointing to
    /// `child_pa`. Sets only the table-descriptor bits — child
    /// permissions ride through as the leaf is installed.
    fn pack_table(child_pa: u64) -> u64;

    /// Pack a 4 KiB Device-attr leaf at `pa` (PCD|PWT|NX on x86;
    /// AttrIdx=Device|Inner-Shareable|AF|PXN|UXN on arm).
    fn pack_device_leaf(pa: u64) -> u64;

    /// Pack a 4 KiB leaf from arch-neutral `PageFlags`. Used by
    /// `MmuOps::map` per `20§5`/`21§5`. Each impl translates:
    /// WRITE → writable; EXEC clear → set NX (x86) / UXN+PXN
    /// according to USER (arm); USER → user-accessible; NO_CACHE +
    /// WRITE_THROUGH → device/non-cacheable bits.
    fn pack_4k_leaf(pa: u64, flags: crate::PageFlags) -> u64;

    /// Pack a huge/block leaf at `pa` (2 MiB or 1 GiB; same bit
    /// pattern at either level for both arches — x86 sets PS=1
    /// at PD/PDPT, arm clears the TABLE bit at L1/L2). Native
    /// flags translate identically to `pack_4k_leaf`.
    fn pack_block_leaf(pa: u64, flags: crate::PageFlags) -> u64;

    /// Pack a non-present L3 swap entry. It must always fault in hardware and
    /// be distinguishable from an all-zero unmapped leaf.
    fn pack_swap_entry(entry: SwapEntry) -> u64;

    /// Decode one of this architecture's non-present L3 swap entries.
    /// Returns `None` for an ordinary unmapped or another non-present state.
    fn unpack_swap_entry(raw: u64) -> Option<SwapEntry>;
    fn pack_migration_entry(entry: MigrationEntry) -> u64 { let _ = entry; 0 }
    fn unpack_migration_entry(raw: u64) -> Option<MigrationEntry> { let _ = raw; None }

    /// Make a present leaf reject writes while keeping it readable and
    /// resident. There is deliberately no inverse: a leaf regains write
    /// permission only by being re-packed from its VMA protection, so no
    /// caller can invent write access out of a raw entry.
    /// # C: O(1)
    fn leaf_wrprotect(raw: u64) -> u64;

    /// Set the software "write-protected on behalf of a userfaultfd" marker on
    /// a present leaf. The marker is per-PAGE state living in the leaf itself,
    /// which is what makes the page table the single owner of "this page is
    /// uffd write-protected" — no side table can disagree with what the CPU
    /// walks.
    /// # C: O(1)
    fn leaf_set_uffd_wp(raw: u64) -> u64;

    /// Clear the software userfaultfd write-protect marker. Write permission
    /// is deliberately NOT restored here: the next write takes an ordinary
    /// protection fault, which is where write access is decided.
    /// # C: O(1)
    fn leaf_clear_uffd_wp(raw: u64) -> u64;

    /// Whether a present leaf carries the userfaultfd write-protect marker.
    /// # C: O(1)
    fn leaf_is_uffd_wp(raw: u64) -> bool;

    /// Whether this architecture may replace a live kernel-linear-map block
    /// leaf with a table of smaller leaves while other CPUs run. One
    /// architecture reaches the new granularity through an intermediate state
    /// the hardware tolerates; the other only guarantees no translation-conflict
    /// abort when the implementation advertises the relaxed break-before-make
    /// behaviour, so it answers from the CPU's own feature identification.
    /// # C: O(1)
    fn can_split_kernel_leaf() -> bool;

    /// Derive one child of a split block leaf. `child_level` is `2` for a
    /// 2 MiB child and `3` for a 4 KiB child; `child_pa` is that child's output
    /// address, aligned to the child's span. Every attribute of `block` carries
    /// over unchanged — a split changes granularity, never permissions or
    /// memory type — including any attribute field whose descriptor position
    /// differs between a block leaf and a bottom-level page leaf.
    /// # C: O(1)
    fn split_child_leaf(block: u64, child_pa: u64, child_level: u8) -> u64;

    /// Order the stores that filled a freshly built table ahead of the store
    /// publishing the table entry that points at it, as observed by every CPU's
    /// hardware table walker. Plain release ordering is not enough on an
    /// architecture whose walkers are not coherent with the store buffer.
    /// # SAFETY: none — barrier only.
    /// # C: O(1)
    fn publish_table_barrier();

    /// Set or clear a leaf's translation-valid state, preserving its output
    /// address and every attribute so the inverse call restores the original
    /// translation exactly.
    /// # C: O(1)
    fn leaf_set_present(raw: u64, present: bool) -> u64;

    /// A non-present leaf marking the page as poisoned: an access to it raises
    /// a memory-error fault instead of allocating a page. Distinct from the
    /// swap and migration encodings and from the all-zero absent leaf.
    /// # C: O(1)
    fn pack_poison_marker() -> u64;

    /// Whether `raw` is the marker written by [`Self::pack_poison_marker`].
    /// # C: O(1)
    fn is_poison_marker(raw: u64) -> bool;
}
