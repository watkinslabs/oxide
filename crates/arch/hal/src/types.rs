use core::time::Duration;

// ---------------------------------------------------------------------------
// Common types
// ---------------------------------------------------------------------------

/// Physical address (per 01§1).
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Pa(pub u64);

/// Virtual address (per 01§1).
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Va(pub u64);

/// 47-bit user virtual address upper bound per `01§1`. Anything `≥`
/// this is non-canonical user space.
pub const USER_VA_END: u64 = 0x0000_8000_0000_0000;

/// Alternate signal stack (`sigaltstack(2)`) state crossing the HAL
/// boundary into `build_signal_frame` / out of `restore_signal_frame`.
/// `sp`/`size`/`flags` mirror `stack_t` and are what the frame's
/// `uc_stack` records; `use_alt` is the already-decided Linux `sigsp()`
/// verdict (SA_ONSTACK set AND `sas_ss_flags(sp) == 0`), so the arch
/// builder only places the frame and never re-derives policy.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct AltStack {
    pub sp:      u64,
    pub size:    u64,
    pub flags:   i32,
    pub use_alt: bool,
}

/// User virtual address per `01§1`. Newtype with a private constructor
/// so the only way to obtain one is `UserVirtAddr::new`, which rejects
/// `≥ USER_VA_END` and any non-canonical bit pattern. No `+usize` impl
/// — pointer arithmetic goes through `checked_add`.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct UserVirtAddr(u64);

impl UserVirtAddr {
    /// Construct from a raw u64. `None` if `≥ USER_VA_END`.
    /// # C: O(1)
    pub const fn new(raw: u64) -> Option<Self> {
        if raw < USER_VA_END { Some(Self(raw)) } else { None }
    }
    /// # C: O(1)
    pub const fn as_u64(self) -> u64 { self.0 }
    /// Saturating-fail add: returns `None` if the result lands `≥ USER_VA_END`
    /// or overflows `u64`. Per `01§1` "no `+usize` op on VA types".
    /// # C: O(1)
    pub const fn checked_add(self, off: usize) -> Option<Self> {
        match self.0.checked_add(off as u64) {
            Some(v) if v < USER_VA_END => Some(Self(v)),
            _ => None,
        }
    }
}

/// Page Frame Number (per 01§1).
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Pfn(pub u64);

/// Cycle / TSC count (host-monotonic).
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Cycles(pub u64);

/// Nanoseconds (per 01§5).
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Nanos(pub u64);

/// Page size selector for [`MmuOps::map`] (per 20§5).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PageSize {
    P4K,
    P2M,
    P1G,
}

/// Four-level walk depth shared by both arches: L0 root … L3 page leaf.
const WALK_LEVEL_1G: u8 = 1;
const WALK_LEVEL_2M: u8 = 2;
const WALK_LEVEL_4K: u8 = 3;

impl PageSize {
    /// Granule a leaf found at walk `level` covers. `None` for a level that
    /// carries no legal leaf on either arch (the L0 root), so a caller can
    /// never turn an unrecognised depth into a plausible-looking 4 KiB answer.
    /// # C: O(1)
    pub const fn from_walk_level(level: u8) -> Option<PageSize> {
        match level {
            WALK_LEVEL_4K => Some(PageSize::P4K),
            WALK_LEVEL_2M => Some(PageSize::P2M),
            WALK_LEVEL_1G => Some(PageSize::P1G),
            _             => None,
        }
    }

    /// Granule covering exactly `bytes`, or `None` when no leaf does.
    /// # C: O(1)
    pub const fn from_bytes(bytes: u64) -> Option<PageSize> {
        match bytes {
            b if b == PageSize::P4K.bytes() => Some(PageSize::P4K),
            b if b == PageSize::P2M.bytes() => Some(PageSize::P2M),
            b if b == PageSize::P1G.bytes() => Some(PageSize::P1G),
            _                               => None,
        }
    }

    /// Bytes this granule covers.
    /// # C: O(1)
    pub const fn bytes(self) -> u64 {
        match self {
            PageSize::P4K => 4 * 1024,
            PageSize::P2M => 2 * 1024 * 1024,
            PageSize::P1G => 1024 * 1024 * 1024,
        }
    }
}

/// Base page size in bytes per `01§1`. Both arches use 4 KiB at order 0.
pub const PAGE_SIZE_BYTES: u64 = 4096;
/// log2(`PAGE_SIZE_BYTES`); use for `Pfn ↔ PhysAddr` conversion.
pub const PAGE_SHIFT: u32 = 12;
/// Usable bytes in every task and per-CPU hardirq stack.
///
/// This is Linux `THREAD_SIZE` for the supported x86_64 and aarch64 kernels.
/// Architecture entry assembly consumes the same value as a const operand, so
/// stack-window guards cannot drift from the scheduler's allocator.
pub const KERNEL_STACK_BYTES: usize = 16 * 1024;


// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

impl Pfn {
    /// Build PFN from `Pa` (truncates the offset bits).
    /// # C: O(1)
    pub const fn from_pa(pa: Pa) -> Self { Pfn(pa.0 >> 12) }

    /// PA of this PFN's base (aligned to 4 KiB).
    /// # C: O(1)
    pub const fn to_pa(self) -> Pa { Pa(self.0 << 12) }
}

impl Nanos {
    /// Convert a `Duration` to nanoseconds (saturating).
    /// # C: O(1)
    pub fn from_duration(d: Duration) -> Self {
        let n = d.as_nanos();
        Nanos(if n > u64::MAX as u128 { u64::MAX } else { n as u64 })
    }
}


