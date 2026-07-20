// HAL trait definitions per docs/20 (x86_64) + docs/21 (aarch64) + docs/14
// (Context). All five trait names listed in 07§5: MmuOps, CpuOps, Context,
// IrqOps, TimerOps. Per 07§5 these are NEVER `dyn`; arch-specific impls live
// in `hal-x86_64` and `hal-aarch64`, monomorphized at compile time.
//
// Method bodies live in arch crates; this crate is trait-only.

#![no_std]

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

/// Extra siginfo_t payload an SA_SIGINFO handler reads, passed
/// arch-neutrally from the signal-delivery path into the per-arch
/// `build_signal_frame` so it can populate the `_sifields` union
/// (`27§5`, siginfo(7)). Currently the SIGCHLD `_sigchld` shape:
/// `code`→si_code (CLD_*), `pid`→si_pid (child VPID), `uid`→si_uid,
/// `status`→si_status. POD so it crosses the HAL boundary without a
/// crate cycle (sched/fs/hal all share this one type).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct SigChld {
    pub code:   i32,
    pub pid:    i32,
    pub uid:    u32,
    pub status: i32,
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

/// Base page size in bytes per `01§1`. Both arches use 4 KiB at order 0.
pub const PAGE_SIZE_BYTES: u64 = 4096;
/// log2(`PAGE_SIZE_BYTES`); use for `Pfn ↔ PhysAddr` conversion.
pub const PAGE_SHIFT: u32 = 12;

bitflags::bitflags! {
    /// PTE protection bits (per 20§5 / 21§5).
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub struct PageFlags: u64 {
        const READ      = 1 << 0;
        const WRITE     = 1 << 1;
        const EXEC      = 1 << 2;
        const USER      = 1 << 3;
        const GLOBAL    = 1 << 4;
        const NO_CACHE  = 1 << 5;
        const WRITE_THROUGH = 1 << 6;
    }
}

// ---------------------------------------------------------------------------
// Context (14§4)
// ---------------------------------------------------------------------------

/// Per-task saved register set; the unit `switch` operates on.
///
/// # C: O(1)
/// # Ctx: kernel internal
///
/// All trait methods are unsafe-by-construction (raw pointers, asm). See
/// `14§4` for the SAFETY contract.
pub trait Context: Sized {
    /// # C: O(1)
    fn new_kernel(stack_top: *mut u8, entry: extern "C" fn(usize) -> !, arg: usize) -> Self;

    /// Build a kernel-thread context whose saved stack carries a synthetic
    /// IRQ frame (saved scratch GPs + vec/err pad + iretq/eret frame), with
    /// `Context.{rsp,sp}` pointing at a saved RIP/LR equal to the per-arch
    /// `oxide_irq_resume_user` resume label. Lets the IRQ epilogue of one
    /// task `Context::switch` directly into a fresh task and `iretq`/`eret`
    /// from there. Frame layout pinned in `14§R07`.
    /// # C: O(1)
    fn new_kernel_with_irq_frame(stack_top: *mut u8, entry: extern "C" fn(usize) -> !, arg: usize) -> Self;

    /// # C: O(1)
    fn new_user(stack_top: *mut u8, user_ip: u64, user_sp: u64) -> Self;

    /// # SAFETY: `prev` and `next` reference valid `Context` records, `next`'s
    /// saved stack is a valid kernel stack with valid return frame, preempt
    /// disabled, runqueue lock held by caller (released by next thread
    /// post-switch). See 14§4.
    /// # C: O(1)
    /// # Ctx: process|irq-return path; preempt-off
    unsafe fn switch(prev: *mut Self, next: *const Self);
}

// ---------------------------------------------------------------------------
// MmuOps (20§5 / 21§5)
// ---------------------------------------------------------------------------

pub mod pt_walker;
pub mod time;
pub mod zerotrap;

pub mod tlb;

/// Local `kassert!` per `07§5` — bridges to `crates/err`'s real
/// implementation once that crate ships per `38`. Form: `kassert!(cond,
/// "literal")` only; no `panic!(fmt)` per CLAUDE.md hard rules.
/// Re-exported `#[macro_export]` so per-arch HAL crates can use it.
#[macro_export]
macro_rules! kassert {
    ($cond:expr, $msg:literal) => {{
        if !($cond) { panic!($msg); }
    }};
}


/// Page-table operations. Owns the active address space.
///
/// # C: see method-level annotations
pub trait MmuOps {
    /// Map `va -> pa` with `flags` at `size`. Returns `Some(old_pa)` iff a
    /// *different* present frame was torn down to make room (the displaced
    /// leaf the caller must `dec_ref`/`put_page` per `11§8`); `None` when the
    /// slot was empty or already mapped the SAME `pa` (a pure permission
    /// rewrite, e.g. fork's W-strip or a shmem RO→RW upgrade — no PTE-count
    /// change). F157-A1: replaces the old silent-replace that leaked the
    /// displaced frame's refcount.
    /// # SAFETY: `va` and `pa` aligned to `size`; the mapping does not alias
    /// existing kernel mappings; caller holds the relevant PT lock per 06.
    /// Displaced-frame accounting is the mm layer's responsibility
    /// (`vmm::AddressSpace` install sites); device/identity/SMP maps that
    /// never run over a PMM-tracked user frame may ignore the result.
    /// # C: O(1) for 4 KiB; O(1) for 2 MiB / 1 GiB
    unsafe fn map(va: Va, pa: Pa, flags: PageFlags, size: PageSize) -> Option<Pa>;

    /// Tear down the mapping at `va` of `size`.
    /// # SAFETY: caller holds the relevant PT lock; `va` aligned to `size`.
    /// # C: O(1)
    unsafe fn unmap(va: Va, size: PageSize);

    /// Translate `va` to (`pa`, flags) if mapped.
    /// # C: O(1)
    fn translate(va: Va) -> Option<(Pa, PageFlags)>;

    /// Issue a TLB shootdown for `va` (size = single page).
    /// # SAFETY: caller ensures cross-CPU IPI delivery as needed per 22.
    /// # C: O(1) local; O(N_cpus) cross-CPU
    unsafe fn flush_va(va: Va);

    /// Flush the entire TLB on this CPU.
    /// # C: O(1) local
    fn flush_all_local();

    /// Like `map` but installs into the page-table tree rooted at
    /// `root_pa` instead of the active CR3 / TTBR0. Used by
    /// `AddressSpace::fork` per docs/11§7 to populate child page
    /// tables without temporarily activating them.
    /// Returns the displaced frame like [`MmuOps::map`] (`Some(old_pa)` iff a
    /// different present leaf was torn down). Fork populates a FRESH child
    /// root, so in practice this is always `None`; the return keeps the two
    /// installers symmetric for callers that account displaced frames.
    /// # SAFETY: caller asserts `root_pa` is a valid kernel-owned
    /// PT root frame; `va` and `pa` aligned per `size`; per-AS PT
    /// lock held.
    /// # C: O(1)
    /// # Ctx: under PT lock per `06§3.6`
    unsafe fn map_at(root_pa: u64, va: Va, pa: Pa, flags: PageFlags, size: PageSize) -> Option<Pa>;

    /// Read the architecture-encoded non-present swap leaf at `va` in an
    /// explicit user root.  Default is appropriate only for hosted MMU mocks
    /// that do not model swap leaves.
    /// # C: O(walk depth)
    fn swap_entry_at(_root_pa: u64, _va: Va) -> Option<pt_walker::SwapEntry> { None }

    /// Read a non-present migration marker from an explicit root.  It is
    /// deliberately distinct from [`Self::swap_entry_at`]: callers must wait
    /// and restart rather than retain/free a swap slot.
    /// # C: O(walk depth)
    fn migration_entry_at(_root_pa: u64, _va: Va) -> Option<pt_walker::MigrationEntry> { None }

    /// Install a non-present swap leaf in a fresh child root.  The operation
    /// never overwrites a present or another non-present leaf, so the caller
    /// can roll back the slot reference on any error.
    /// # SAFETY: caller owns `root_pa` and holds its page-table lock.
    /// # C: O(walk depth)
    unsafe fn map_swap_at(
        _root_pa: u64, _va: Va, _entry: pt_walker::SwapEntry,
    ) -> Result<(), pt_walker::WalkErr> { Err(pt_walker::WalkErr::AllocFailed) }

    /// Remove this exact non-present swap leaf from an unpublished child root.
    /// Used only by fork rollback after its corresponding slot reference was
    /// released.
    /// # SAFETY: caller owns `root_pa` and holds its page-table lock.
    /// # C: O(walk depth)
    unsafe fn clear_swap_at(
        _root_pa: u64, _va: Va, _entry: pt_walker::SwapEntry,
    ) -> bool { false }

    /// Install `root_pa` as this CPU's active user-half page-table root.
    ///
    /// On x86_64 writes `CR3` (single tree covering both halves; the
    /// caller is expected to have populated kernel-half entries from
    /// the kernel master PML4 before calling). On aarch64 writes
    /// `TTBR0_EL1` and invalidates EL1 TLB; `TTBR1_EL1` (kernel half)
    /// is untouched. Per `13§8` (`schedule()` AS-swap).
    ///
    /// # SAFETY: caller is the kernel scheduler or boot path; `root_pa`
    /// references a valid 4 KiB-aligned root frame whose kernel-half
    /// mappings are coherent with the active kernel PT (else the very
    /// next instruction may fault). Single-CPU pre-SMP; preempt-off.
    /// # C: O(1)
    /// # Ctx: schedule path; preempt-off
    unsafe fn activate(root_pa: u64);
}

// ---------------------------------------------------------------------------
// CpuOps (20§* / 21§*)
// ---------------------------------------------------------------------------

/// Per-CPU primitives.
pub trait CpuOps {
    /// Index of the current CPU.
    /// # C: O(1)
    fn current_cpu() -> u32;

    /// Number of online CPUs.
    /// # C: O(1)
    fn cpu_count() -> u32;

    /// Halt this CPU until the next interrupt.
    /// # C: O(1)
    /// # Ctx: idle path
    fn halt();

    /// Memory barrier sufficient to order MMIO writes per 06.
    /// # C: O(1)
    fn mmio_barrier();

    /// Set per-CPU base register (`GS_BASE` on x86, `TPIDR_EL1` on arm).
    /// # SAFETY: `base` points to a valid per-CPU area for this CPU.
    /// # C: O(1)
    unsafe fn set_percpu_base(base: *mut u8);

    /// ELF `AT_HWCAP` advertised to userspace in the initial auxv (Linux
    /// `ELF_HWCAP`). Userspace (musl, OpenSSL) selects SIMD/crypto code
    /// paths from it. Only bits for features the CPU is GUARANTEED to have
    /// are set, so a program can never pick an instruction the hardware
    /// lacks (→ SIGILL). # C: O(1)
    fn cpu_hwcap() -> u64;
}

// ---------------------------------------------------------------------------
// IrqOps (20§11 / 21§11)
// ---------------------------------------------------------------------------

/// Interrupt controller (APIC on x86_64; GICv3 on aarch64 per 21).
pub trait IrqOps {
    /// # C: O(1)
    fn enable_line(line: u32);

    /// # C: O(1)
    fn disable_line(line: u32);

    /// End-of-interrupt acknowledge.
    /// # C: O(1)
    fn eoi(line: u32);

    /// Set CPU affinity for `line`.
    /// # SAFETY: `mask` references valid CPU set; controller-specific routing
    /// table reprogrammed atomically per 22.
    /// # C: O(1)
    unsafe fn set_affinity(line: u32, mask: u64);

    /// Allocate an MSI/MSI-X vector + program address/data per 20§11.
    /// Returns `(addr, data)` to write into the device's MSI table.
    /// # C: O(1) amortized; allocates vector range via 22 vector allocator
    fn alloc_msi() -> (u64, u32);

    /// Send IPI to `target_cpu` with `vector`.
    /// # SAFETY: `vector` is a valid IPI vector per 22 vector map.
    /// # C: O(1)
    unsafe fn send_ipi(target_cpu: u32, vector: u8);

    /// Acknowledge a spurious IRQ; returns `Some(vec)` if a real one is
    /// pending in service register.
    /// # C: O(1)
    fn ack() -> Option<u8>;
}

// ---------------------------------------------------------------------------
// TimerOps (20§12 / 21§12)
// ---------------------------------------------------------------------------

/// Per-CPU monotonic timer (TSC-deadline on x86_64; CNTV on aarch64).
pub trait TimerOps {
    /// Monotonic timestamp from boot.
    /// # C: O(1) (single TSC/CNTV read)
    fn monotonic_ns() -> Nanos;

    /// Arm a one-shot timer to fire at `deadline_ns`.
    /// # SAFETY: caller manages the LVT/CNTV registers per 23.
    /// # C: O(1)
    unsafe fn set_oneshot(deadline_ns: Nanos);

    /// Counter frequency in kHz (cached at boot).
    /// # C: O(1)
    fn freq_khz() -> u32;
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pfn_pa_roundtrip() {
        let pa = Pa(0x1234_5000);
        assert_eq!(Pfn::from_pa(pa).to_pa(), pa);
    }

    #[test]
    fn nanos_from_duration_saturates() {
        let n = Nanos::from_duration(Duration::from_secs(u64::MAX));
        assert_eq!(n, Nanos(u64::MAX));
    }
}
