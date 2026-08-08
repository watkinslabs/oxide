// Supported huge-page granules and the flag-word size encoding.
//
// Several syscalls carry the requested huge-page size as log2 of the byte
// size in a 6-bit field of a flag word (`mmap`'s `MAP_HUGE_*`, `memfd_create`'s
// `MFD_HUGE_*`, `shmget`'s `SHM_HUGE_*`). All three use the same shift and
// mask, so the encoding lives once, here, and each syscall names it.

use hal::PageSize;

/// Bit position of the size-log field in a flag word.
pub const HUGE_FLAG_ENCODE_SHIFT: u32 = 26;
/// Width mask of the size-log field, before shifting.
pub const HUGE_FLAG_ENCODE_MASK: u32 = 0x3f;

/// log2 of the default huge-page size on both supported arches (2 MiB).
pub const DEFAULT_HUGE_SHIFT: u32 = 21;
/// log2 of the gigantic huge-page size on both supported arches (1 GiB).
pub const GIGANTIC_HUGE_SHIFT: u32 = 30;

/// A huge-page granule the pool can serve.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum HugePageSize {
    /// 2 MiB — the default hstate.
    Huge2M,
    /// 1 GiB — the gigantic hstate.
    Huge1G,
}

impl HugePageSize {
    /// Bytes this granule covers.
    /// # C: O(1)
    pub const fn bytes(self) -> u64 {
        match self {
            HugePageSize::Huge2M => 1u64 << DEFAULT_HUGE_SHIFT,
            HugePageSize::Huge1G => 1u64 << GIGANTIC_HUGE_SHIFT,
        }
    }

    /// log2 of [`HugePageSize::bytes`] — the value a flag word encodes.
    /// # C: O(1)
    pub const fn shift(self) -> u32 {
        match self {
            HugePageSize::Huge2M => DEFAULT_HUGE_SHIFT,
            HugePageSize::Huge1G => GIGANTIC_HUGE_SHIFT,
        }
    }

    /// Buddy order of one page of this granule.
    /// # C: O(1)
    pub const fn order(self) -> crate::Order {
        crate::Order((self.shift() - hal::PAGE_SHIFT) as u8)
    }

    /// Base pages one page of this granule covers.
    /// # C: O(1)
    pub const fn nr_base_pages(self) -> u64 {
        1u64 << (self.shift() - hal::PAGE_SHIFT)
    }

    /// Page-table granule that installs one page of this size as a single leaf.
    /// # C: O(1)
    pub const fn leaf(self) -> PageSize {
        match self {
            HugePageSize::Huge2M => PageSize::P2M,
            HugePageSize::Huge1G => PageSize::P1G,
        }
    }

    /// Mask that clears the in-page offset.
    /// # C: O(1)
    pub const fn mask(self) -> u64 { !(self.bytes() - 1) }

    /// The default granule, used whenever a caller asks for "a huge page"
    /// without naming a size — a zero size-log field.
    /// # C: O(1)
    pub const fn default_size() -> HugePageSize { HugePageSize::Huge2M }
}

/// Resolve a size-log field to a granule. A zero log selects the default
/// granule; any other value must name a supported size exactly, and an
/// unsupported one resolves to `None` so the caller can refuse rather than
/// silently round to a size the program did not ask for.
/// # C: O(1)
pub const fn size_from_log(page_size_log: u32) -> Option<HugePageSize> {
    match page_size_log {
        0                     => Some(HugePageSize::default_size()),
        DEFAULT_HUGE_SHIFT    => Some(HugePageSize::Huge2M),
        GIGANTIC_HUGE_SHIFT   => Some(HugePageSize::Huge1G),
        _                     => None,
    }
}

/// Extract the size-log field a flag word carries.
/// # C: O(1)
pub const fn size_log_from_flags(flags: u64) -> u32 {
    ((flags >> HUGE_FLAG_ENCODE_SHIFT) as u32) & HUGE_FLAG_ENCODE_MASK
}

/// Resolve a granule directly from a flag word carrying the size-log field.
/// # C: O(1)
pub const fn size_from_flags(flags: u64) -> Option<HugePageSize> {
    size_from_log(size_log_from_flags(flags))
}
