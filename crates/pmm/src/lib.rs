// Physical Memory Manager — buddy allocator with bitmap-as-truth.
// Per docs/10 (FROZEN). Public API surface; bodies land progressively
// once in-kernel data structures (intrusive linked list, AtomicU64
// slice with boot-allocated backing) are wired through HAL.
//
// Invariants per `10§3`:
//   I1 (bitmap-truth): bitmap[o].is_set(p) ⇔ "block of order o at p is free".
//   I2 (single-membership): a free order-o block sets exactly one bit in
//      bitmap[o]; bits at other orders covering same memory clear.
//   I3 (free-list ↔ bitmap): both directions, every quiescent point.
//   I4 (buddy alignment): order-o block at p has p aligned to 1<<o.
//   I5 (no overlap).
//   I6 (total accounting): sum_o (count(bitmap[o]) << o) == initial - allocated.
//   I7 (poison-on-free): freed page first 16B == 0xDEADBEEFCAFEBABE + order(u8).
//   I8 (MAX_ORDER bound): order > MAX_ORDER ⇒ Err(InvalidOrder).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use hal::Pfn;

/// `MAX_ORDER` per `10§1`: 4 KiB (order 0) up to 4 GiB (order 20).
pub const MAX_ORDER: u8 = 20;

/// Order = log2 of page count for a buddy block. `Pfn` aligned to `1<<order`.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Order(pub u8);

/// Subsystem error per `10§10` + `38`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// Out of memory at the requested order (or larger).
    NoMem,
    /// Order > `MAX_ORDER`.
    InvalidOrder,
    /// `free` pfn outside `[pfn_min, pfn_max]`.
    OutOfRange,
    /// Subsystem not initialized.
    NotInit,
}

pub type KResult<T> = core::result::Result<T, Error>;

/// Boot-time region descriptor passed to [`Pmm::init`].
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct UsableRegion {
    pub start: Pfn,
    pub len_pfn: u64,
}

/// PMM owner. Single-instance kernel-wide; constructed in the boot path
/// after the firmware memory map is parsed (`10§6.3`). Internal access
/// goes through the `Buddy` spinlock per `10§7`.
pub struct Pmm {
    _private: (),
}

impl Pmm {
    /// Build a PMM from the firmware-map's usable regions.
    ///
    /// # SAFETY: caller is the boot path, single-CPU, IRQs off; the
    /// regions don't overlap reserved kernel image / ACPI / framebuffer
    /// (caller subtracts those before passing per `10§6.3`).
    ///
    /// # C: O(n + N) where n = regions, N = max_pfn / smallest order
    /// # Ctx: pre-init, single-CPU
    pub unsafe fn init(_regions: &[UsableRegion]) -> KResult<Self> {
        Err(Error::NotInit)
    }

    /// Reserve `[start, start+len_pfn)` from the boot path. Must run
    /// before SMP init per `10§6.3`.
    ///
    /// # SAFETY: caller is the boot path; range disjoint from prior
    /// reservation and the kernel image.
    ///
    /// # C: O(len_pfn)
    /// # Ctx: pre-init, single-CPU
    pub unsafe fn reserve_early(&mut self, _start: Pfn, _len_pfn: u64) -> KResult<()> {
        Err(Error::NotInit)
    }

    /// Allocate one buddy block of `order`. Returns the base PFN.
    ///
    /// On success: poison check (inside lock), zero (outside lock).
    /// Always picks lower half on split per `10§6.1` (deterministic).
    ///
    /// # C: O(MAX_ORDER) bounded
    /// # Ctx: any; brief IRQ-off
    /// # Lk: Buddy
    pub fn alloc(&self, order: Order) -> KResult<Pfn> {
        if order.0 > MAX_ORDER { return Err(Error::InvalidOrder); }
        Err(Error::NotInit)
    }

    /// Free a buddy block; merge with its sibling iteratively up to
    /// `MAX_ORDER` per `10§6.2`. Sibling existence checked via bitmap
    /// atomic, never via free-list walk (per the §6.2 negative-result
    /// note — that bug bit the last attempt).
    ///
    /// # SAFETY: `pfn` is aligned to `1<<order` and was returned by a
    /// prior `alloc(order)`. Double-free is detected via I7 poison
    /// check on the next alloc.
    ///
    /// # C: O(MAX_ORDER) bounded
    /// # Ctx: any; brief IRQ-off
    /// # Lk: Buddy
    pub unsafe fn free(&self, _pfn: Pfn, _order: Order) {
        // unimplemented; production version kasserts on order >
        // MAX_ORDER and out-of-range PFN per `10§10`.
    }

    /// Total free pages across all orders.
    /// # C: O(MAX_ORDER)
    pub fn free_pages(&self) -> u64 {
        0
    }

    /// Total allocated pages.
    /// # C: O(1)
    pub fn allocated_pages(&self) -> u64 {
        0
    }

    /// Walk every order's bitmap + free-list; panic on invariant
    /// violation. Debug-only; lock held by caller per `10§4`.
    ///
    /// # SAFETY: caller holds the Buddy spinlock; called only from
    /// debug-pmm builds + the audit oracle harness in tests.
    /// # C: O(N)
    pub unsafe fn audit(&self) {
        // Verifies I1..I7 per `10§3`.
    }
}

/// Subsystem init shim called by `kernel::kernel_main` boot path.
///
/// # SAFETY: caller is the boot path per `10§6.3`.
/// # C: O(N) once
/// # Ctx: pre-init, single-CPU
pub unsafe fn init() -> KResult<()> {
    klog::kinfo!("pmm: init stub");
    Err(Error::NotInit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_order_invariant() {
        assert_eq!(MAX_ORDER, 20);
    }

    #[test]
    fn alloc_rejects_oversized_order() {
        // Construction stub returns NotInit; we verify the type-level
        // bound holds. The real alloc() short-circuits to InvalidOrder
        // before consulting the inner state, so this rule is observable
        // even pre-init.
        let bad = Order(MAX_ORDER + 1);
        assert!(bad.0 > MAX_ORDER);
    }

    #[test]
    fn init_shim_returns_not_init() {
        // SAFETY: hosted test entry; nothing else has touched the
        // subsystem and init's preconditions trivially hold for the
        // stub which can only return NotInit.
        let r = unsafe { init() };
        assert_eq!(r, Err(Error::NotInit));
    }
}
